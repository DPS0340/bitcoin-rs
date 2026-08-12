# Cross-platform shutdown uses `ctrlc`

The node needs the same graceful-shutdown notification on Unix and Windows.
`signal-hook::iterator` is unavailable on Windows, while directly calling
`SetConsoleCtrlHandler` duplicates platform handling and requires an unsafe FFI
callback in node code.

Use `ctrlc` with its `termination` feature as the process-level adapter. The
registered callback performs only a non-blocking send into the existing bounded
shutdown channel. The event loop, subsystem draining, and clean checkpoint stay
outside the callback and remain platform-independent.
