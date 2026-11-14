# Testing & Coverage

How the combolite-core test suite is built, run, and measured, the coverage goals it
works toward, and the known gap and the plan to close it.

## Running the suite

Tests use the [Unity](https://github.com/ThrowTheSwitch/Unity) framework and are driven by
CTest. A debug build with tests:

```sh
cmake --preset core-cpu-debug
cmake --build --preset core-cpu-debug -j
ctest --preset core-cpu-debug --output-on-failure
```

Each test is registered through `cdb_add_test(<name>)` in `tests/CMakeLists.txt` and is a
standalone `tests/<name>.c` executable. Test binaries are built with the project's strict
warning set, so a test that does not compile cleanly fails the build.

Several suites re-run with environment toggles for extra scenarios:

- `CDB_TEST_MAX_OPEN=1` — the model suites again with a single open store of each model, so a
  store closed while still in use is exercised.
- `CDB_TEST_ACCEL=1` — the vector/graph suites again with the fake accelerator installed; they
  must produce identical results.

Note: `test_coord` performs multi-process, lock-timing-sensitive sweeps and can be flaky under
high `ctest -jN` parallelism on some hosts; run it serially if it reports a spurious failure.

## Coverage build

Line and branch coverage are measured with Clang source-based coverage. Enable the
instrumentation with the `CDB_COVERAGE` option (off by default; it adds
`-fprofile-instr-generate -fcoverage-mapping` to the library and its test binaries):

```sh
CC=clang cmake -S . -B build-cov -DCDB_BUILD_TESTS=ON -DCDB_COVERAGE=ON
cmake --build build-cov -j

cd build-cov
rm -rf prof && mkdir prof
LLVM_PROFILE_FILE="prof/%m-%p.profraw" ctest
llvm-profdata merge -sparse prof/*.profraw -o cov.profdata

# one test binary is positional; the rest are passed with -object
mapfile -t EXES < <(find tests -maxdepth 1 -type f -executable -name 'test_*')
OBJ=(); for e in "${EXES[@]:1}"; do OBJ+=(-object "$e"); done
llvm-cov report "${EXES[0]}" "${OBJ[@]}" -instr-profile=cov.profdata \
  -ignore-filename-regex='(tests/|third-party/)'
```

(`gcovr`/`lcov` work too if you build with GCC `--coverage`; the above is the first-party path.)

## Coverage goals

The suite works toward high **line** and **branch** coverage of first-party code
(`src/**`, excluding `third-party/` and the test code itself), with the **critical paths** —
cryptography (`cdb_crypto.c`), and the durability/catalog read-write path — held to the
highest bar.

The public-API surface is exercised end to end by `test_e2e_lifecycle` (open an encrypted
database, drive the document model through CMBQL, prove durability across close/reopen and
master-key rotation) alongside the per-module unit suites. Negative and abuse paths —
invalid arguments, tampered ciphertext, wrong keys, buffer-too-small encoders, malformed
input — are covered by the dedicated edge suites (`test_crypto_edge`, `test_math_edge`,
`test_eval_edge`, `test_wire_writer_edge`).

## Known gap: defensive error branches

The largest remaining coverage gap is **defensive error branches** — the status checks guarding
every allocation, I/O operation, and downstream call (for example `if (mbedtls_...(...) != 0)
return CDB_E_CRYPTO;`, or an `CDB_E_IO` return when a write fails mid-operation). These branches
are, by design, not reachable with ordinary inputs; triggering them requires injecting the
underlying failure.

combolite already ships a fault-injection harness for exactly this:

- `cdb_faultdev` — a storage device that can be *armed* to fail or crash at the Nth I/O
  operation (`cdb_faultdev_arm(dev, op, mode, ...)`, with crash modes `TORN`, `REORDER`,
  `KEEP_PREFIX`, `DROP_UNSYNCED`) and to flip bits on disk (`cdb_faultdev_flip_bit`).
- `cdb_faultenv` — a host environment with the same arming (`cdb_faultenv_arm`), plus an
  allocation switch (`cdb_faultenv_set_alloc`) and a controllable clock.

The crash-recovery suites use this to validate durability. Closing the error-branch gap is a
matter of **extending these sweeps across the full operation surface**: for each first-party
module, drive a representative workload while sweeping the injected-failure point across its
I/O operations (and, where applicable, toggling allocation), asserting each error path returns
its typed status and leaves state consistent (fail-closed, no partial writes). Crypto-internal
error returns additionally need the crypto primitives routed through a fault hook, since the
vendored library's calls are not currently injectable.

This is tracked as ongoing work; contributions that extend a module's fault sweep (and turn any
finding into a committed regression test) are welcome.
