# Unity is third-party code: built without the project's strict warnings.
if(NOT TARGET unity)
  if(EXISTS ${PROJECT_SOURCE_DIR}/third-party/unity/src/unity.c)
    add_library(unity STATIC ${PROJECT_SOURCE_DIR}/third-party/unity/src/unity.c)
    target_include_directories(unity PUBLIC ${PROJECT_SOURCE_DIR}/third-party/unity/src)
    target_compile_definitions(unity PUBLIC UNITY_INCLUDE_DOUBLE UNITY_SUPPORT_64)
    if(CDB_SANITIZE)
      target_compile_options(unity PRIVATE ${CDB_SANITIZER_FLAGS})
    endif()
  endif()
endif()

# Test-only support code: kept out of the production library.
add_library(combolite_testing STATIC
  ${PROJECT_SOURCE_DIR}/src/cdb_faultdev.c
  ${PROJECT_SOURCE_DIR}/src/cdb_faultenv.c
  ${PROJECT_SOURCE_DIR}/src/cdb_fakeaccel.c)
target_include_directories(combolite_testing PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(combolite_testing PUBLIC combolite)
target_compile_options(combolite_testing PRIVATE ${CDB_WARNINGS})

# Unified test framework integration (combolite-tests)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../../combolite-tests/cmake/ComboliteTesting.cmake)
  list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../combolite-tests/cmake)
  include(ComboliteTesting)
endif()

# Core test registration function: prefixes test names with submodule name and sets labels
function(cdb_add_test name)
  cmake_parse_arguments(PARSE_ARGV 1 ARG "" "SUBMODULE;LABEL" "LIBS;PROPERTIES;ENVIRONMENT")
  if(NOT ARG_SUBMODULE)
    set(ARG_SUBMODULE "combolite-core")
  endif()
  if(NOT TARGET ${name})
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE combolite combolite_testing unity ${ARG_LIBS})
    target_compile_definitions(${name} PRIVATE CDB_TEST_TMPDIR="${CMAKE_CURRENT_BINARY_DIR}")
    target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/src)
    target_compile_options(${name} PRIVATE ${CDB_WARNINGS})
  endif()
  set(full_name "${ARG_SUBMODULE}:${name}")
  add_test(NAME "${full_name}" COMMAND ${name})
  set_tests_properties("${full_name}" PROPERTIES LABELS "${ARG_SUBMODULE}")
  if(ARG_PROPERTIES)
    set_tests_properties("${full_name}" PROPERTIES ${ARG_PROPERTIES})
  endif()
  if(ARG_ENVIRONMENT)
    set_property(TEST "${full_name}" PROPERTY ENVIRONMENT ${ARG_ENVIRONMENT})
  endif()
endfunction()

cdb_add_test(test_crc32c)
cdb_add_test(test_varint)
cdb_add_test(test_endian)
cdb_add_test(test_value)
cdb_add_test(test_hostfile)
cdb_add_test(test_faultdev)
cdb_add_test(test_header)
cdb_add_test(test_page)
cdb_add_test(test_pager)
cdb_add_test(test_faultenv)
cdb_add_test(test_journal)
cdb_add_test(test_coord)
cdb_add_test(test_db)
cdb_add_test(test_key)
cdb_add_test(test_index)
cdb_add_test(test_catalog)
cdb_add_test(test_doc)
cdb_add_test(test_bigdoc)
cdb_add_test(test_link)
cdb_add_test(test_schema)
cdb_add_test(test_fts)
cdb_add_test(test_vec)
cdb_add_test(test_accel)
cdb_add_test(test_graph)
cdb_add_test(test_tsbits)
cdb_add_test(test_tsblock)

# Benchmarks: built with the tests, run by hand (not part of ctest).
function(cdb_add_bench name)
  add_executable(${name} ${name}.c)
  target_link_libraries(${name} PRIVATE combolite)
  target_include_directories(${name} PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_compile_options(${name} PRIVATE ${CDB_WARNINGS})
endfunction()

cdb_add_bench(bench_graph)
cdb_add_test(test_ts)
cdb_add_test(test_nib)
cdb_add_test(test_table)
cdb_add_test(test_codec)
cdb_add_test(test_colenc)
cdb_add_test(test_rowgroup)
cdb_add_test(test_coltable)
cdb_add_test(test_threads)
cdb_add_test(test_query)
cdb_add_test(test_eval)
cdb_add_test(test_math)
cdb_add_test(test_exec)
cdb_add_test(test_exec_live)
cdb_add_test(test_proc)
cdb_add_test(test_savepoint)
cdb_add_test(test_enclave_tx)
cdb_add_test(test_lexer)
cdb_add_test(test_compiler)
cdb_add_test(test_trigger)
cdb_add_test(test_tx_cross_store)
cdb_add_test(test_crypto)
cdb_add_test(test_security)
cdb_add_test(test_blob)
cdb_add_test(test_reclaim)
cdb_add_test(test_overflow_nib)
cdb_add_test(test_audit)
cdb_add_test(test_crdt)
cdb_add_test(test_cmbql_crud)
cdb_add_test(test_e2e_lifecycle)
cdb_add_test(test_idblocks)

# The suites that use several stores again, with one open store of each
# model at a time, so a store closed while still in use shows up here.
foreach(name test_link test_fts test_vec test_ts test_table test_rowgroup)
  set(full_name "combolite-core:${name}_cap1")
  add_test(NAME "${full_name}" COMMAND ${name})
  set_tests_properties("${full_name}" PROPERTIES
    LABELS "combolite-core"
    ENVIRONMENT CDB_TEST_MAX_OPEN=1)
endforeach()

# The vector suites again with the fake accelerator installed (spec 18.11):
# they must give exactly the same results; the graph suite's crash sweep
# runs with it too.
foreach(name test_vec test_graph)
  set(full_name "combolite-core:${name}_accel")
  add_test(NAME "${full_name}" COMMAND ${name})
  set_tests_properties("${full_name}" PROPERTIES
    LABELS "combolite-core"
    ENVIRONMENT CDB_TEST_ACCEL=1)
endforeach()

# The real devices (spec 18.11), when their backend is built. Without a
# usable device the test exits 77: skipped, not passed. AddressSanitizer
# must leave the shadow gap unprotected for the CUDA driver to map memory.
if(CDB_ACCEL_CUDA)
  cdb_add_test(test_accel_cuda
    SUBMODULE "combolite-accelerator"
    LIBS combolite_accel
    PROPERTIES SKIP_RETURN_CODE 77
    ENVIRONMENT "ASAN_OPTIONS=protect_shadow_gap=0")
endif()
if(CDB_ACCEL_CUDA OR CDB_ACCEL_VULKAN)
  cdb_add_bench(bench_accel)
  target_link_libraries(bench_accel PRIVATE combolite_accel)
endif()
if(CDB_ACCEL_CUDA OR CDB_ACCEL_VULKAN)
  cdb_add_test(test_accel_open
    SUBMODULE "combolite-accelerator"
    LIBS combolite_accel
    PROPERTIES SKIP_RETURN_CODE 77
    ENVIRONMENT "ASAN_OPTIONS=protect_shadow_gap=0;LSAN_OPTIONS=suppressions=${CMAKE_CURRENT_SOURCE_DIR}/lsan_drivers.supp")
endif()
if(CDB_ACCEL_VULKAN)
  cdb_add_test(test_accel_vulkan
    SUBMODULE "combolite-accelerator"
    LIBS combolite_accel
    PROPERTIES SKIP_RETURN_CODE 77
    ENVIRONMENT "LSAN_OPTIONS=suppressions=${CMAKE_CURRENT_SOURCE_DIR}/lsan_drivers.supp")
  # The checked-in SPIR-V must come from the shader sources (spec 18.5).
  find_package(Python3 COMPONENTS Interpreter)
  if(Python3_FOUND)
    set(spirv_test "combolite-accelerator:check_spirv")
    add_test(NAME "${spirv_test}" COMMAND Python3::Interpreter ${PROJECT_SOURCE_DIR}/tools/gen_spirv.py --check)
    set_tests_properties("${spirv_test}" PROPERTIES LABELS "combolite-accelerator")
  endif()
endif()
