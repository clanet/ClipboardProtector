# ClipboardProtector integration

`src/detours.cpp` has a conditional local change enabled with
`CLIP_DETOURS_STATIC_NODES` in the Hook DLL and the heap-owner regression test.
Transaction thread and operation nodes use fixed storage for 4096 threads and
256 operations instead of the host CRT heap. Storage is reset only after the
transaction ownership check succeeds. Exhaustion follows Detours' existing
allocation-failure/abort path; individual node deletion does not free memory.

This removes `new`/`delete` heap-lock dependencies while arbitrary host threads
are suspended. The host-side freeze limit must stay within the thread capacity.
Default upstream behavior is unchanged when this definition is absent. Review
this integration and run `detour_heap_smoke`, `hook_abort_smoke`, and
`hook_smoke` on both x86 and x64 when updating Detours.
