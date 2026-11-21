/* On-demand REAL multi-process stress harness for combolite coordinator /
 * multi-writer work (issue #46). It is the re-runnable validation harness for
 * the #33 class of defect: "parallel writers leave a sound archive that won't
 * open (CDB_E_CORRUPT)".
 *
 * Build: it is OFF by default and never part of ctest (it forks processes,
 * sends SIGKILL, and runs for a time budget). Enable with
 *   cmake --preset core-cpu-debug -DCDB_BUILD_STRESS=ON
 * then build the `stress_multiwriter_recovery` target. See tests/stress/README.md for
 * the smoke command and the full campaign.
 *
 * CLI: stress_multiwriter_recovery <self-abs-path> <scratchdir> <rounds> <N> <budget-sec>
 *   self-abs-path  absolute path to this binary (it re-exec's itself as a child)
 *   scratchdir     caller-supplied, expendable scratch directory (recreated)
 *   rounds         number of kill rounds to run
 *   N              number of concurrent writer processes (clamped to 1..7)
 *   budget-sec     wall-clock budget; the campaign stops when it is reached
 * A short bounded smoke run is just small rounds / budget-sec, e.g. 3 2 10.
 *
 * Two roles in one binary:
 *   child      : opens the SAME archive read-write (no ACCEPT_LOSS), joins as a
 *                coordinator, and loops begin->put->commit forever with keys in
 *                its own entry band; after each acked commit it appends
 *                (wid,entry,counter) to its own ground-truth log, fsync'd, so the
 *                controller knows what was DURABLY committed before a kill.
 *   controller : spawns N real child processes (fork+exec), lets them run and
 *                commit, SIGKILLs them at varied/random moments (kill-all, or
 *                stagger: kill a subset, let survivors take over the dead slot,
 *                then kill survivors), and after each round reopens the archive
 *                WITHOUT ACCEPT_LOSS in a loop. The #33 symptom is:
 *                   open(no ACCEPT_LOSS) == CDB_E_CORRUPT
 *                   AND open(ACCEPT_LOSS) == CDB_OK with the acked data intact
 *                i.e. a sound archive rejected. On any CDB_E_CORRUPT the full
 *                forensic state (dir listing, slot-file hexdumps, both open
 *                results, ACCEPT_LOSS data vs acked logs) is captured.
 *
 * Process-kill hygiene: the controller kills ONLY the explicit child PIDs it
 * forked (tracked in an array), with kill(pid,SIGKILL). It never pattern-kills
 * and never signals itself or ancestors. All children are reaped; the scratch
 * archive is recreated fresh each round.
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "combolite/cdb_env.h"
#include "cdb_db.h"
#include "cdb_pager.h"
#include "cdb_page.h"

#define PAGE_LOG2 9u
#define PAGE (1u << PAGE_LOG2)
#define NODES 16u
#define BAND 8u /* entries per writer: entry = wid*BAND + k, must stay < 64 */

static const uint8_t db_id[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

/* ---- one process's database buffers (same shape as the in-repo test) ---- */
struct proc {
    uint8_t arena[NODES * 2u * PAGE + 2u * PAGE];
    cdb_pager_node nodes[NODES];
    cdb_free_extent free_list[1024];
    uint8_t record_buf[1024];
    uint8_t cat_work[24u * 1024u];
    cdb_index_entry cat_entries[512];
    uint8_t cat_page[PAGE];
    cdb_db_config cfg;
    cdb_db db;
};

/* Entry N is logical page N; REPLACE sets, DELETE frees. (verbatim from test) */
static cdb_status kv_apply(void *ctx, cdb_pager *p, const cdb_delta *d)
{
    uint8_t val[PAGE];
    cdb_page_header t;
    uint64_t lid;
    cdb_status s;
    (void)ctx;
    if (d->entry_id >= 64)
        return CDB_E_INVALID_ARG;
    while (p->next_lid < 64)
        if ((s = cdb_pager_alloc(p, &lid)) != CDB_OK)
            return s;
    if (d->op == CDB_OP_DELETE)
        return cdb_pager_free(p, d->entry_id);
    if (d->len >= 64)
        return CDB_E_INVALID_ARG;
    memcpy(val, d->data, d->len);
    memset(&t, 0, sizeof t);
    t.type = CDB_PAGE_TYPE_DATA_TEST;
    t.store_id = d->store_id;
    return cdb_pager_write(p, d->entry_id, &t, val, d->len);
}

static void fill_header(cdb_header *h)
{
    memset(h, 0, sizeof *h);
    h->order = CDB_ORDER_LITTLE;
    h->layout_flags = CDB_LAYOUT_ADDR64;
    h->default_page_log2 = (uint8_t)PAGE_LOG2;
    memcpy(h->db_id, db_id, 16);
}

static void cfg_init(struct proc *p, unsigned flags)
{
    memset(&p->cfg, 0, sizeof p->cfg);
    p->cfg.pager.arena = p->arena;
    p->cfg.pager.arena_size = sizeof p->arena;
    p->cfg.pager.nodes = p->nodes;
    p->cfg.pager.node_cap = NODES;
    p->cfg.pager.free_list = p->free_list;
    p->cfg.pager.free_cap = sizeof p->free_list / sizeof p->free_list[0];
    p->cfg.record_buf = p->record_buf;
    p->cfg.record_buf_size = sizeof p->record_buf;
    p->cfg.apply = kv_apply;
    p->cfg.catalog_work.bytes = p->cat_work;
    p->cfg.catalog_work.bytes_size = sizeof p->cat_work;
    p->cfg.catalog_work.entries = p->cat_entries;
    p->cfg.catalog_work.entries_cap = 512;
    p->cfg.catalog_page = p->cat_page;
    p->cfg.durability = CDB_DURABILITY_FULL; /* every acked commit is durable */
    p->cfg.flags = flags;
    /* fast coordination so takeover/baton churn happens within the time budget */
    p->cfg.coord.beat_ns = 50 * 1000 * 1000; /* 50 ms heartbeat */
    p->cfg.coord.dead_after = 3;             /* ~150 ms fallback dead timeout */
}

static const char *value_of(struct proc *p, uint64_t e, char *out, size_t outsz)
{
    uint8_t buf[PAGE];
    cdb_page_header h;
    cdb_status s = cdb_pager_read(&p->db.pager, e, buf, &h);
    out[0] = '\0';
    if (s != CDB_OK)
        return out;
    size_t n = h.payload_len;
    if (n >= outsz)
        n = outsz - 1;
    memcpy(out, buf + cdb_page_payload_offset(p->db.pager.fmt), n);
    out[n] = '\0';
    return out;
}

/* ============================ CHILD ROLE ============================ */
static volatile sig_atomic_t stop_flag = 0;
static void on_term(int s)
{
    (void)s;
    stop_flag = 1;
}

static int run_child(const char *base, unsigned wid, unsigned seed, long max_commits)
{
    static struct proc pr; /* static: large */
    cdb_env env;
    cdb_hostenv he;
    cdb_header h;
    cdb_status s;
    char ackpath[512];
    int ackfd;
    unsigned long counter = (unsigned long)seed << 20; /* distinct ranges */
    long commits = 0;

    signal(SIGTERM, on_term);
    cdb_hostenv_init(&he, &env);
    cfg_init(&pr, 0u);
    fill_header(&h);

    /* Retry open: peers may be mid-join/mid-takeover. BUSY/NOT_FOUND are
     * transient races; CDB_E_CORRUPT is the #33 condition (a joiner adopting a
     * dead peer's slot while the cluster is live - the cdb_db.c:1762-1766 site).
     * A CORRUPT that resolves on retry is a near-miss (logged); one that
     * persists is a reproduction: write a marker and exit 42. */
    {
        int corrupt_seen = 0;
        for (int attempt = 0; attempt < 4000; attempt++) {
            memset(&pr.db, 0, sizeof pr.db);
            s = cdb_db_open(&pr.db, &env, base, &pr.cfg, &h);
            if (s == CDB_OK)
                break;
            if (s == CDB_E_CORRUPT) {
                corrupt_seen++;
                if (corrupt_seen > 40) {
                    char mk[560];
                    snprintf(mk, sizeof mk, "%s.CORRUPT.%u", base, wid);
                    int mf = open(mk, O_WRONLY | O_CREAT | O_APPEND, 0600);
                    if (mf >= 0) {
                        char l[64];
                        int n = snprintf(l, sizeof l, "live-join CORRUPT wid=%u\n", wid);
                        (void)write(mf, l, (size_t)n);
                        close(mf);
                    }
                    fprintf(stderr, "CHILD wid=%u got persistent CDB_E_CORRUPT on live join\n",
                            wid);
                    return 42;
                }
            }
            struct timespec ts = {0, 2 * 1000 * 1000};
            nanosleep(&ts, NULL); /* 2 ms */
        }
        if (s != CDB_OK) {
            fprintf(stderr, "CHILD wid=%u open failed status=%d\n", wid, s);
            return 43;
        }
        if (corrupt_seen > 0) {
            char nm[560];
            snprintf(nm, sizeof nm, "%s.nearmiss", base);
            int nf = open(nm, O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (nf >= 0) {
                char l[96];
                int n = snprintf(l, sizeof l, "wid=%u recovered after %d CORRUPT retries\n", wid,
                                 corrupt_seen);
                (void)write(nf, l, (size_t)n);
                close(nf);
            }
        }
    }

    snprintf(ackpath, sizeof ackpath, "%s.acked.%u", base, wid);
    ackfd = open(ackpath, O_WRONLY | O_CREAT | O_APPEND, 0600);

    while (!stop_flag) {
        /* entry 0 is the reserved catalog/anchor page; writers start at 1 and
         * stay in disjoint bands below 64 (the apply hook's page limit). */
        uint64_t e = 1u + (uint64_t)wid * BAND + (counter % BAND);
        char val[32];
        int vn = snprintf(val, sizeof val, "%lu", counter);
        s = cdb_tx_begin(&pr.db, CDB_DURABILITY_FULL);
        if (s != CDB_OK) {
            (void)cdb_db_tick(&pr.db);
            continue;
        }
        s = cdb_tx_put(&pr.db, 1, e, CDB_OP_REPLACE, val, (size_t)vn);
        if (s != CDB_OK) {
            continue;
        }
        s = cdb_tx_commit(&pr.db);
        if (s == CDB_OK) {
            if (ackfd >= 0) {
                char line[64];
                int ln = snprintf(line, sizeof line, "%llu %lu\n", (unsigned long long)e, counter);
                (void)write(ackfd, line, (size_t)ln);
                fsync(ackfd);
            }
            counter++;
            commits++;
            if (max_commits > 0 && commits >= max_commits)
                break;
        } else {
            (void)cdb_db_tick(&pr.db);
        }
        /* periodic tick so takeover/reconcile of dead peers progresses */
        if ((commits & 0x3F) == 0)
            (void)cdb_db_tick(&pr.db);
    }
    (void)cdb_db_close(&pr.db);
    if (ackfd >= 0)
        close(ackfd);
    return 0;
}

/* ============================ CONTROLLER ROLE ============================ */
static char g_self[1024];
static char g_base[768];
static char g_work[800]; /* base + ".cdbwork" */
static char g_arch[800]; /* base + ".cdbarch" */
static FILE *g_log;

static void logln(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
    if (g_log) {
        va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fputc('\n', g_log);
        fflush(g_log);
    }
}

static void rm_tree(const char *path); /* fwd */

static void rm_entry(const char *full)
{
    struct stat st;
    if (lstat(full, &st) != 0)
        return;
    if (S_ISDIR(st.st_mode))
        rm_tree(full);
    else
        unlink(full);
}

static void rm_tree(const char *path)
{
    DIR *d = opendir(path);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                continue;
            char full[1200];
            snprintf(full, sizeof full, "%s/%s", path, de->d_name);
            rm_entry(full);
        }
        closedir(d);
        rmdir(path);
    } else {
        unlink(path);
    }
}

static void wipe_archive(void)
{
    rm_tree(g_work);
    unlink(g_arch);
    /* acked logs */
    DIR *d = opendir(".");
    /* base lives in cwd subdir "arena/"; remove acked logs there */
    (void)d;
    if (d)
        closedir(d);
    for (unsigned w = 0; w < 16; w++) {
        char p[900];
        snprintf(p, sizeof p, "%s.acked.%u", g_base, w);
        unlink(p);
        snprintf(p, sizeof p, "%s.CORRUPT.%u", g_base, w);
        unlink(p);
    }
    {
        char p[900];
        snprintf(p, sizeof p, "%s.nearmiss", g_base);
        unlink(p);
    }
}

/* count lines in a text file (0 if absent) */
static long count_lines(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    long n = 0;
    int c, prev = '\n';
    while ((c = fgetc(f)) != EOF) {
        if (c == '\n')
            n++;
        prev = c;
    }
    if (prev != '\n')
        n++;
    fclose(f);
    return n;
}

/* total acked commits across all children this round */
static long total_acked(void)
{
    long t = 0;
    for (unsigned w = 0; w < 16; w++) {
        char p[900];
        snprintf(p, sizeof p, "%s.acked.%u", g_base, w);
        t += count_lines(p);
    }
    return t;
}
/* 1 if any child left a live-join CORRUPT marker */
static int any_corrupt_marker(void)
{
    for (unsigned w = 0; w < 16; w++) {
        char p[900];
        snprintf(p, sizeof p, "%s.CORRUPT.%u", g_base, w);
        FILE *f = fopen(p, "r");
        if (f) {
            fclose(f);
            return 1;
        }
    }
    return 0;
}
static long nearmiss_count(void)
{
    char p[900];
    snprintf(p, sizeof p, "%s.nearmiss", g_base);
    return count_lines(p);
}

/* hex/ascii dump of a small file */
static void dump_file(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        logln("    <absent> %s", path);
        return;
    }
    unsigned char buf[512];
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    logln("    FILE %s (%zd bytes shown):", path, n < 0 ? (ssize_t)0 : n);
    for (ssize_t i = 0; i < n; i += 16) {
        char line[200];
        size_t o = 0;
        o += (size_t)snprintf(line + o, sizeof line - o, "      %04zx  ", i);
        for (ssize_t j = i; j < i + 16 && j < n; j++)
            o += (size_t)snprintf(line + o, sizeof line - o, "%02x ", buf[j]);
        for (ssize_t j = (n < i + 16 ? n : i + 16); j < i + 16; j++)
            o += (size_t)snprintf(line + o, sizeof line - o, "   ");
        o += (size_t)snprintf(line + o, sizeof line - o, " |");
        for (ssize_t j = i; j < i + 16 && j < n; j++) {
            unsigned char c = buf[j];
            o += (size_t)snprintf(line + o, sizeof line - o, "%c", (c >= 32 && c < 127) ? c : '.');
        }
        logln("%s|", line);
    }
}

static void list_workdir(void)
{
    logln("  workdir listing (%s):", g_work);
    DIR *d = opendir(g_work);
    if (!d) {
        logln("    <no workdir>");
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        char full[1200];
        snprintf(full, sizeof full, "%s/%s", g_work, de->d_name);
        struct stat st;
        stat(full, &st);
        logln("    %-24s %lld bytes", de->d_name, (long long)st.st_size);
    }
    closedir(d);
}

/* Read the max acked counter per entry from all children's acked logs. */
#define MAXE 128
static void read_acked(unsigned long *best /*[MAXE]*/, int *have /*[MAXE]*/)
{
    for (int i = 0; i < MAXE; i++) {
        best[i] = 0;
        have[i] = 0;
    }
    for (unsigned w = 0; w < 16; w++) {
        char p[900];
        snprintf(p, sizeof p, "%s.acked.%u", g_base, w);
        FILE *f = fopen(p, "r");
        if (!f)
            continue;
        unsigned long long e;
        unsigned long c;
        while (fscanf(f, "%llu %lu", &e, &c) == 2) {
            if (e < MAXE) {
                have[(int)e] = 1;
                if (c > best[(int)e])
                    best[(int)e] = c;
            }
        }
        fclose(f);
    }
}

/* Try to open the archive; return status. If ok, optionally read values. */
static cdb_status try_open(unsigned flags, struct proc *pr, int read_vals, char vals[MAXE][32])
{
    cdb_env env;
    cdb_hostenv he;
    cdb_header h;
    cdb_status s;
    cdb_hostenv_init(&he, &env);
    cfg_init(pr, flags);
    fill_header(&h);
    memset(&pr->db, 0, sizeof pr->db);
    s = cdb_db_open(&pr->db, &env, g_base, &pr->cfg, &h);
    if (s == CDB_OK && read_vals) {
        for (int e = 0; e < MAXE; e++)
            value_of(pr, (uint64_t)e, vals[e], 32);
    }
    if (s == CDB_OK)
        (void)cdb_db_close(&pr->db);
    return s;
}

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* Spawn one child; returns pid or -1. */
static pid_t spawn_child(unsigned wid, unsigned seed)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        char swid[16], sseed[16];
        snprintf(swid, sizeof swid, "%u", wid);
        snprintf(sseed, sizeof sseed, "%u", seed);
        execl(g_self, g_self, "child", g_base, swid, sseed, (char *)NULL);
        _exit(127);
    }
    return pid;
}

/* wait one pid; return 1 if it exited with code 42 (live-join CDB_E_CORRUPT) */
static int wait_pid42(pid_t pid)
{
    int st;
    if (pid <= 0)
        return 0;
    if (waitpid(pid, &st, 0) < 0)
        return 0;
    return WIFEXITED(st) && WEXITSTATUS(st) == 42;
}

static int reap_all(pid_t *pids, int n)
{
    int c42 = 0;
    for (int i = 0; i < n; i++)
        if (pids[i] > 0) {
            c42 += wait_pid42(pids[i]);
            pids[i] = -1;
        }
    return c42;
}

/* After a kill round, probe reopen. Returns 1 if the #33 symptom fired. */
static int probe_reopen(int round, const char *kind)
{
    static struct proc pr;
    cdb_status s_noloss, s_loss;
    char vals[MAXE][32];
    /* a few retries without loss: transient BUSY/locks from just-dead peers */
    for (int attempt = 0; attempt < 50; attempt++) {
        s_noloss = try_open(0u, &pr, 0, NULL);
        if (s_noloss != CDB_E_BUSY)
            break;
        struct timespec ts = {0, 5 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    if (s_noloss == CDB_OK)
        return 0; /* opened fine, no symptom */

    /* did not open without loss -> investigate */
    s_loss = try_open(CDB_DB_ACCEPT_LOSS, &pr, 1, vals);

    if (s_noloss == CDB_E_CORRUPT) {
        logln("");
        logln("==================== CDB_E_CORRUPT at round %d (%s) ====================", round,
              kind);
        logln("  open(no ACCEPT_LOSS) = CDB_E_CORRUPT(%d); open(ACCEPT_LOSS) = %d", s_noloss,
              s_loss);
        list_workdir();
        /* dump coordinator slot files + journals + archive header area */
        DIR *d = opendir(g_work);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d))) {
                if (de->d_name[0] == '.')
                    continue;
                char full[1200];
                snprintf(full, sizeof full, "%s/%s", g_work, de->d_name);
                dump_file(full);
            }
            closedir(d);
        }
        /* soundness check: compare ACCEPT_LOSS data to acked ground truth */
        if (s_loss == CDB_OK) {
            unsigned long best[MAXE];
            int have[MAXE];
            read_acked(best, have);
            int lost = 0, checked = 0;
            for (int e = 0; e < MAXE; e++) {
                if (!have[e])
                    continue;
                checked++;
                unsigned long got = vals[e][0] ? strtoul(vals[e], NULL, 10) : 0;
                if (!vals[e][0] || got < best[e]) {
                    lost++;
                    logln("    LOSS entry %d: acked>=%lu but archive has '%s'", e, best[e],
                          vals[e]);
                }
            }
            logln("  soundness: %d acked entries checked, %d show loss under ACCEPT_LOSS", checked,
                  lost);
            if (lost == 0 && checked > 0) {
                logln("  *** REPRODUCED #33: SOUND archive (all acked data intact under "
                      "ACCEPT_LOSS) was REJECTED with CDB_E_CORRUPT without it. ***");
                return 2; /* reproduced-sound */
            } else {
                logln("  classification: GENUINE LOSS -> CDB_E_CORRUPT refusal is CORRECT "
                      "(fail-closed working).");
                return 1; /* corrupt but genuine loss */
            }
        } else {
            logln("  ACCEPT_LOSS also did not open (status %d); archive unreadable either way.",
                  s_loss);
            return 1;
        }
    }
    /* some other non-OK status without loss */
    logln("round %d (%s): open(no loss) status=%d (not OK, not CORRUPT); open(loss)=%d", round,
          kind, s_noloss, s_loss);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "child")) {
        /* child base wid seed */
        return run_child(argv[2], (unsigned)atoi(argv[3]), (unsigned)atoi(argv[4]), 0);
    }

    /* controller: mw <self-path> <scratchdir> <rounds> <N> <seconds-budget> */
    if (argc < 6) {
        fprintf(stderr, "usage: %s <self-abs-path> <scratchdir> <rounds> <N> <budget-sec>\n",
                argv[0]);
        return 2;
    }
    snprintf(g_self, sizeof g_self, "%s", argv[1]);
    const char *scratch = argv[2];
    long rounds = atol(argv[3]);
    int N = atoi(argv[4]);
    double budget = atof(argv[5]);
    if (N < 1)
        N = 1;
    if (N > 7)
        N = 7; /* 1 + (N-1)*BAND + (BAND-1) must stay < 64 */

    mkdir(scratch, 0700);
    /* keep the archive inside an "arena" subdir of scratch */
    char arena[700];
    snprintf(arena, sizeof arena, "%s/arena", scratch);
    mkdir(arena, 0700);
    snprintf(g_base, sizeof g_base, "%s/db", arena);
    snprintf(g_work, sizeof g_work, "%s.cdbwork", g_base);
    snprintf(g_arch, sizeof g_arch, "%s.cdbarch", g_base);
    char logpath[800];
    snprintf(logpath, sizeof logpath, "%s/run.log", scratch);
    g_log = fopen(logpath, "a");

    srand((unsigned)getpid() ^ (unsigned)time(NULL));

    logln("# controller start: N=%d rounds=%ld budget=%.0fs self=%s", N, rounds, budget, g_self);
    double t0 = now_s();
    long round = 0;
    long corrupt_events = 0, reproduced = 0, genuine_loss = 0;
    long kills = 0, commits_seen = 0, live_join_corrupt = 0, near_misses = 0, takeover_rounds = 0;

    for (round = 0; round < rounds; round++) {
        if (now_s() - t0 > budget) {
            logln("# budget reached at round %ld", round);
            break;
        }
        wipe_archive();

        pid_t pids[12];
        for (int i = 0; i < 12; i++)
            pids[i] = -1;
        int c42 = 0;
        unsigned nseed = (unsigned)rand();
        for (int i = 0; i < N; i++)
            pids[i] = spawn_child((unsigned)i, nseed + (unsigned)i * 7919u);

        /* let them get going and commit a bunch */
        int startup_ms = 60 + rand() % 240; /* 60..300 ms */
        struct timespec ts = {startup_ms / 1000, (startup_ms % 1000) * 1000000L};
        nanosleep(&ts, NULL);

        int kind_stagger = (round & 1);
        const char *kind = kind_stagger ? "stagger-takeover" : "kill-all";

        if (kind_stagger && N >= 2) {
            /* Kill a subset, then spawn fresh JOINERS that reuse the dead wids'
             * bands. The joiners open while the survivors are still live and
             * must adopt the dead peers' slots - the non-alone open path and the
             * exact cdb_db.c:1762-1766 fail-closed site. Then survivors run on,
             * then everyone is killed. */
            int nkill = 1 + rand() % (N - 1);
            for (int i = 0; i < nkill; i++)
                if (pids[i] > 0) {
                    kill(pids[i], SIGKILL);
                    kills++;
                }
            for (int i = 0; i < nkill; i++)
                if (pids[i] > 0) {
                    c42 += wait_pid42(pids[i]);
                    pids[i] = -1;
                }
            /* brief gap so the dead slots are visible (flock released at once) */
            {
                struct timespec tg = {0, (5 + rand() % 40) * 1000000L};
                nanosleep(&tg, NULL);
            }
            /* fresh joiners take over the just-vacated wids while peers live */
            for (int i = 0; i < nkill; i++)
                pids[i] = spawn_child((unsigned)i, nseed + 104729u + (unsigned)i * 7919u);
            takeover_rounds++;
            int surv_ms = 150 + rand() % 700; /* 0.15..0.85 s of mixed live/takeover */
            struct timespec t2 = {surv_ms / 1000, (surv_ms % 1000) * 1000000L};
            nanosleep(&t2, NULL);
            for (int i = 0; i < N; i++)
                if (pids[i] > 0) {
                    kill(pids[i], SIGKILL);
                    kills++;
                    if (rand() % 2) {
                        struct timespec t3 = {0, (rand() % 3000) * 1000L};
                        nanosleep(&t3, NULL);
                    }
                }
        } else {
            /* kill-all near-simultaneously, with tiny jitter to catch mid-commit/mid-handoff */
            for (int i = 0; i < N; i++)
                if (pids[i] > 0) {
                    if (rand() % 3 == 0) {
                        struct timespec t3 = {0, (rand() % 2000) * 1000L};
                        nanosleep(&t3, NULL);
                    } /* 0..2ms jitter */
                    kill(pids[i], SIGKILL);
                    kills++;
                }
        }
        c42 += reap_all(pids, N);

        commits_seen += total_acked();
        near_misses += nearmiss_count();
        if (c42 > 0 || any_corrupt_marker()) {
            live_join_corrupt += (c42 > 0 ? c42 : 1);
            logln("");
            logln("#### LIVE-JOIN CDB_E_CORRUPT at round %ld (%s): %d joiner(s) refused while "
                  "cluster live",
                  round, kind, c42);
            /* run the controller's soundness probe on the current (post-kill) archive */
        }

        int r = probe_reopen((int)round, kind);
        if (r >= 1)
            corrupt_events++;
        if (r == 2)
            reproduced++;
        if (r == 1)
            genuine_loss++;

        if ((reproduced > 0 && reproduced <= 3)
            || (live_join_corrupt > 0 && live_join_corrupt <= 3
                && (c42 > 0 || any_corrupt_marker()))) {
            logln("# snapshotting archive of round %ld aside for inspection", round);
            /* Move the whole arena (archive + workdir) aside into a per-round
             * snapshot directory for later inspection, then recreate it fresh. */
            char dst[900];
            snprintf(dst, sizeof dst, "%s/repro-round-%ld", scratch, round);
            mkdir(dst, 0700);
            char newarena[1024];
            snprintf(newarena, sizeof newarena, "%s/arena", dst);
            if (rename(arena, newarena) == 0)
                mkdir(arena, 0700);
        }

        if ((round % 200) == 0 && round > 0)
            logln("# progress: round=%ld elapsed=%.0fs kills=%ld commits=%ld takeover_rnds=%ld "
                  "reopen_corrupt=%ld live_join_corrupt=%ld nearmiss=%ld reproduced=%ld",
                  round, now_s() - t0, kills, commits_seen, takeover_rounds, corrupt_events,
                  live_join_corrupt, near_misses, reproduced);
    }

    logln("");
    logln("# ============ SUMMARY ============");
    logln("# rounds_run=%ld  N=%d  elapsed=%.1fs", round, N, now_s() - t0);
    logln("# total_kills=%ld  total_commits_acked=%ld  takeover_rounds=%ld", kills, commits_seen,
          takeover_rounds);
    logln("# reopen CDB_E_CORRUPT events=%ld  (REPRODUCED-sound-rejected=%ld  "
          "genuine-loss-correct=%ld)",
          corrupt_events, reproduced, genuine_loss);
    logln("# live-join CDB_E_CORRUPT events=%ld   transient-CORRUPT near-misses(recovered on "
          "retry)=%ld",
          live_join_corrupt, near_misses);
    if (reproduced > 0)
        logln("# VERDICT: REPRODUCED the #33 symptom under real multi-process concurrency.");
    else if (corrupt_events > 0)
        logln("# VERDICT: CDB_E_CORRUPT occurred but ALL were genuine loss (fail-closed correct); "
              "#33 false-reject NOT reproduced.");
    else
        logln("# VERDICT: NO CDB_E_CORRUPT at all; archive always reopened without ACCEPT_LOSS. "
              "#33 NOT reproduced.");
    if (g_log)
        fclose(g_log);
    return 0;
}
