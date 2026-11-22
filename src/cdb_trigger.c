/* Event Triggers, Trigger Safety & Scheduled Maintenance Coordination (Spec 11.6, 11.9, 11.12).
 *
 * Implements post-commit event triggers with hard recursion depth limits (default 8),
 * cascade mutation warnings, and background scheduled maintenance execution via cdb_worker.
 */
#include "cdb_trigger.h"
#include "cdb_db.h"
#include "cdb_eval.h"
#include "cdb_proc.h"
#include <string.h>

/* Instruction budget for a trigger procedure (spec 11.2 sandbox limits). */
#define CDB_TRIGGER_PROC_BUDGET 100000u

void cdb_trigger_registry_init(cdb_trigger_registry *reg, cdb_worker_pool *pool,
                               uint64_t cascade_threshold)
{
    if (reg == NULL)
        return;
    memset(reg, 0, sizeof(*reg));
    reg->pool = pool;
    reg->cascade_threshold = cascade_threshold ? cascade_threshold : 100u;
    reg->cascade_warning_issued = 0;
}

cdb_status cdb_trigger_register(cdb_trigger_registry *reg, const char *name, size_t name_len,
                                uint64_t store_id, uint8_t events, const char *proc_name,
                                size_t proc_len, uint8_t max_depth)
{
    if (reg == NULL || name == NULL || name_len == 0 || proc_name == NULL || proc_len == 0)
        return CDB_E_INVALID_ARG;
    if (name_len >= CDB_TRIGGER_MAX_NAME || proc_len >= CDB_TRIGGER_MAX_NAME)
        return CDB_E_INVALID_ARG;
    if (reg->n_triggers >= CDB_MAX_TRIGGERS)
        return CDB_E_BUFFER_TOO_SMALL;

    /* Check for duplicate name */
    for (size_t i = 0; i < reg->n_triggers; i++) {
        if (reg->triggers[i].name_len == name_len
            && memcmp(reg->triggers[i].name, name, name_len) == 0) {
            return CDB_E_EXISTS;
        }
    }

    cdb_trigger_def *t = &reg->triggers[reg->n_triggers++];
    memcpy(t->name, name, name_len);
    t->name[name_len] = '\0';
    t->name_len = name_len;
    t->store_id = store_id;
    t->events = events;
    memcpy(t->proc_name, proc_name, proc_len);
    t->proc_name[proc_len] = '\0';
    t->proc_len = proc_len;
    t->max_depth = max_depth ? max_depth : CDB_TRIGGER_DEFAULT_MAX_DEPTH;

    return CDB_OK;
}

cdb_status cdb_trigger_unregister(cdb_trigger_registry *reg, const char *name, size_t name_len)
{
    if (reg == NULL || name == NULL || name_len == 0)
        return CDB_E_INVALID_ARG;

    for (size_t i = 0; i < reg->n_triggers; i++) {
        if (reg->triggers[i].name_len == name_len
            && memcmp(reg->triggers[i].name, name, name_len) == 0) {
            /* Shift down remaining entries */
            for (size_t j = i + 1; j < reg->n_triggers; j++) {
                reg->triggers[j - 1] = reg->triggers[j];
            }
            reg->n_triggers--;
            return CDB_OK;
        }
    }

    return CDB_E_NOT_FOUND;
}

cdb_status cdb_trigger_register_proc(cdb_trigger_registry *reg, const char *name, size_t name_len,
                                     const uint8_t *bytecode, size_t bytecode_len)
{
    if (reg == NULL || name == NULL || name_len == 0 || bytecode == NULL || bytecode_len == 0)
        return CDB_E_INVALID_ARG;
    if (name_len >= CDB_TRIGGER_MAX_NAME || bytecode_len > CDB_TRIGGER_PROC_BYTECODE_CAP)
        return CDB_E_BUFFER_TOO_SMALL;

    /* Replace an existing proc with the same name in place. */
    for (size_t i = 0; i < reg->n_procs; i++) {
        if (reg->procs[i].name_len == name_len
            && memcmp(reg->procs[i].name, name, name_len) == 0) {
            memcpy(reg->procs[i].bytecode, bytecode, bytecode_len);
            reg->procs[i].bytecode_len = bytecode_len;
            return CDB_OK;
        }
    }
    if (reg->n_procs >= CDB_TRIGGER_MAX_PROCS)
        return CDB_E_BUFFER_TOO_SMALL;

    cdb_trigger_proc *p = &reg->procs[reg->n_procs++];
    memcpy(p->name, name, name_len);
    p->name[name_len] = '\0';
    p->name_len = name_len;
    memcpy(p->bytecode, bytecode, bytecode_len);
    p->bytecode_len = bytecode_len;
    return CDB_OK;
}

/* Resolves a registered trigger procedure by name, or NULL if absent. */
static const cdb_trigger_proc *find_proc(const cdb_trigger_registry *reg, const char *name,
                                         size_t name_len)
{
    for (size_t i = 0; i < reg->n_procs; i++) {
        if (reg->procs[i].name_len == name_len
            && memcmp(reg->procs[i].name, name, name_len) == 0) {
            return &reg->procs[i];
        }
    }
    return NULL;
}

cdb_status cdb_trigger_dispatch(cdb_trigger_registry *reg, cdb_db *db, uint64_t store_id,
                                uint8_t event, const cdb_value *old_val, const cdb_value *new_val,
                                unsigned current_depth)
{
    if (reg == NULL)
        return CDB_E_INVALID_ARG;

    /* Marshal the mutated row's old/new values into the procedure's parameter
     * view (spec 11.6). A missing side is passed as NULL so the procedure can
     * distinguish insert (old NULL) from delete (new NULL). These are the only
     * places old/new are exposed; they are never logged or returned (master
     * §5). */
    cdb_value params[2];
    cdb_value null_val;
    cdb_eval_make_null(&null_val);
    params[0] = old_val ? *old_val : null_val;
    params[1] = new_val ? *new_val : null_val;

    for (size_t i = 0; i < reg->n_triggers; i++) {
        cdb_trigger_def *t = &reg->triggers[i];
        if (t->store_id == store_id && (t->events & event) != 0) {
            /* Recursion/cascade depth limit (spec 11.9, 11.12.4): fail closed. */
            if (current_depth >= (unsigned)t->max_depth) {
                return CDB_E_OUT_OF_BUDGET;
            }

            /* Resolve the registered procedure's bytecode and actually run it
             * (spec 11.6). A trigger naming an unregistered procedure is a
             * misconfiguration: fail closed rather than silently skipping. */
            const cdb_trigger_proc *p = find_proc(reg, t->proc_name, t->proc_len);
            if (p == NULL)
                return CDB_E_NOT_FOUND;

            cdb_proc_vm vm;
            cdb_value ret;
            cdb_eval_make_null(&ret);
            cdb_proc_vm_init(&vm, db, CDB_ORDER_LITTLE, params, 2u, CDB_TRIGGER_PROC_BUDGET);
            cdb_status s = cdb_proc_exec(&vm, p->bytecode, p->bytecode_len, &ret);
            if (s != CDB_OK) {
                /* A trigger procedure error must not be swallowed: surface it to
                 * the caller (ADR-4 fail-closed; the base mutation is already
                 * durable, so the error propagates but does not corrupt it). */
                return s;
            }
            reg->last_proc_ran = 1;
            reg->last_proc_ret = ret;

            reg->total_dispatched++;
            if (reg->total_dispatched >= reg->cascade_threshold) {
                reg->cascade_warning_issued = 1;
            }
        }
    }

    return CDB_OK;
}

cdb_status cdb_schedule_register(cdb_trigger_registry *reg, const char *name, size_t name_len,
                                 uint64_t interval_ns, void (*task_fn)(cdb_db *db, void *arg),
                                 void *arg)
{
    if (reg == NULL || name == NULL || name_len == 0 || task_fn == NULL)
        return CDB_E_INVALID_ARG;
    if (name_len >= CDB_TRIGGER_MAX_NAME)
        return CDB_E_INVALID_ARG;
    if (reg->n_schedules >= CDB_MAX_SCHEDULED_TASKS)
        return CDB_E_BUFFER_TOO_SMALL;

    cdb_schedule_def *s = &reg->schedules[reg->n_schedules++];
    memcpy(s->name, name, name_len);
    s->name[name_len] = '\0';
    s->name_len = name_len;
    s->interval_ns = interval_ns;
    s->last_run_ns = 0;
    s->task_fn = task_fn;
    s->arg = arg;

    return CDB_OK;
}

cdb_status cdb_schedule_tick(cdb_trigger_registry *reg, cdb_db *db, int64_t now_ns)
{
    if (reg == NULL)
        return CDB_E_INVALID_ARG;

    for (size_t i = 0; i < reg->n_schedules; i++) {
        cdb_schedule_def *s = &reg->schedules[i];
        if (now_ns - s->last_run_ns >= (int64_t)s->interval_ns) {
            s->last_run_ns = now_ns;
            s->task_fn(db, s->arg);
        }
    }

    return CDB_OK;
}
