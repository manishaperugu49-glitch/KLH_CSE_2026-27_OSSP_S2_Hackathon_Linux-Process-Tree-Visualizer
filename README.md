# Linux Process Tree Visualizer

## Build and run (Ubuntu/WSL)
From this directory:
```bash
make clean
make
./process_tree
```
Or use `make run`.

## Features
- Live process tree, process search and details from Linux `/proc`
- Child process lifecycle with `fork()` and `waitpid()`
- IPC demonstrations: anonymous pipe, named FIFO and signal
- Process group/session information
- System and process memory information
- File record creation, viewing and metadata
- POSIX threads protected by a mutex
- Scheduling policy and process-state counts
- Educational safe-state example
- Snapshot and monitoring logs
- System-call and Linux `/proc` service view

The process monitor reads system information. The lifecycle/IPC demonstrations create only their own child processes. Records and snapshots are written under `logs/`.
