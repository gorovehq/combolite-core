# On-demand multi-process stress harness for coordinator / multi-writer work
# (issue #46; origin of the #33 "sound archive rejected with CDB_E_CORRUPT"
# investigation). Built only when CDB_BUILD_STRESS=ON (set at the repo root).
#
# Deliberately NOT registered with add_test(): it forks N child processes,
# sends SIGKILL at varied moments, and runs for a time budget measured in
# seconds-to-minutes, so it is non-deterministic and must never be part of the
# default ctest run. Invoke it by hand (see README.md).
add_executable(stress_multiwriter_recovery stress_multiwriter_recovery.c)

# Links the real POSIX host env and the core library (cdb_hostenv lives in the
# combolite target). The core library's include dir is PUBLIC; the harness also
# needs the private src headers it was adapted against (cdb_db.h / cdb_pager.h /
# cdb_page.h), exactly as the in-tree tests do.
target_link_libraries(stress_multiwriter_recovery PRIVATE combolite Threads::Threads)
target_include_directories(stress_multiwriter_recovery PRIVATE ${PROJECT_SOURCE_DIR}/src)

# Same strict warning set (and -Werror unless CDB_WERROR=OFF) as the rest of the
# tree: the harness must compile clean with no -Werror regression.
target_compile_options(stress_multiwriter_recovery PRIVATE ${CDB_WARNINGS})
