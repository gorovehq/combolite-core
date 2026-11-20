/* Private journal seams exposed for white-box regression tests only.
 *
 * #23/F6 (CWE-190): the journal's on-disk record size is header + payload +
 * trailer. On a 32-bit build size_t is 32 bits, so a crafted payload_len near
 * UINT32_MAX wraps size_t when the fixed overhead is added, which could let a
 * bound check (size > buf_size) pass on a wrapped-small value. These checked
 * helpers reject the overflow deterministically, before any bound/CRC check.
 *
 * They are declared here (not in the public cdb_journal.h surface) so the F6
 * regression test can drive the overflow edge in a host-independent way
 * (keyed on SIZE_MAX, not a fixed width); production code reaches the same
 * logic through cdb_journal_record_size. Not part of the stable API. */
#ifndef CDB_JOURNAL_INTERNAL_H
#define CDB_JOURNAL_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "combolite/cdb_common.h"

/* Checked size_t addition: *out = a + b, or CDB_E_OVERFLOW if the sum would
 * wrap size_t. *out is left unchanged on overflow. CDB_E_INVALID_ARG if out
 * is NULL. Host-independent: the overflow point is SIZE_MAX, whatever the
 * platform's size_t width. */
cdb_status cdb_journal_size_add(size_t a, size_t b, size_t *out_sum);

/* Total on-disk bytes of a record (header + payload + trailer), rejecting a
 * payload_len whose size arithmetic would overflow size_t (CWE-190) with
 * CDB_E_OVERFLOW, before any bound or CRC check runs. On a 64-bit size_t this
 * cannot overflow for a uint32 payload_len; the guard hardens 32-bit builds
 * and is behaviour-preserving for every value that does not overflow. */
cdb_status cdb_journal_record_size(uint32_t payload_len, size_t *out_size);

#endif /* CDB_JOURNAL_INTERNAL_H */
