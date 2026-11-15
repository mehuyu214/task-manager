# task-manager bridge

Local bridge for the task manager Space (タスクマネージャー), which shows
what is running on this VM and lets KK kill processes from his phone.

- `tkbridge.py` — stdlib-only HTTP bridge on 127.0.0.1:8792.
  - `GET /ping`, `GET /procs` (load averages, uptime, per-process
    pid/ppid/cpu/mem/etime/command, killable flag with a protection reason)
  - `POST /kill` {pid, sig, tree} — terminate a process (optionally its
    whole tree).
  - Protection: pid 1, the bridge itself, /opt/hatch and systemd
    processes, and other users' processes are marked unkillable with a
    Japanese reason shown in the UI.
