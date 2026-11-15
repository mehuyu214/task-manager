#!/usr/bin/env python3
"""Task-manager bridge: list processes and kill them on KK's request.

Localhost only (127.0.0.1:8792). Stdlib only.
Endpoints:
  GET  /procs            -> {ok, load:[l1,l5,l15], uptime_sec, procs:[{pid,ppid,cpu,mem,etime,cmd,killable,protect_reason}]}
  POST /kill {pid, sig: "TERM"|"KILL", tree: bool} -> {ok, killed:[pid,...]} or {ok:false, error}
Safety: only processes owned by this uid can be killed; pid 1, this bridge,
systemd and /opt/hatch runtime processes are protected and reported as such.
"""
import json
import os
import signal
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8792
MY_UID = os.getuid()
MY_PID = os.getpid()

PROTECT_PREFIXES = ("/opt/hatch", "/usr/lib/systemd", "/opt/hatch-image")


def proc_uid(pid):
    try:
        with open(f"/proc/{pid}/status", "rb") as f:
            for raw in f:
                line = raw.decode("utf-8", "replace")
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except Exception:
        return None
    return None


def protect_reason(pid, cmd):
    if pid == 1:
        return "init"
    if pid == MY_PID:
        return "このブリッジ自身"
    if cmd.startswith(PROTECT_PREFIXES):
        return "Muse ランタイム"
    if "hatch daemon" in cmd or "hatch-execd" in cmd:
        return "Muse ランタイム"
    return None


def list_procs():
    out = subprocess.run(
        ["ps", "-eo", "pid,ppid,pcpu,pmem,etime,args", "--no-headers"],
        capture_output=True, text=True, timeout=10,
    ).stdout
    procs = []
    for line in out.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
            cpu, mem = float(parts[2]), float(parts[3])
        except ValueError:
            continue
        etime, cmd = parts[4], parts[5]
        if cmd.startswith("[") and cmd.endswith("] <defunct>"):
            killable, reason = False, "ゾンビ（終了済み）"
        else:
            reason = protect_reason(pid, cmd)
            if reason:
                killable = False
            elif proc_uid(pid) != MY_UID:
                killable, reason = False, "他ユーザーのプロセス"
            else:
                killable = True
        procs.append({
            "pid": pid, "ppid": ppid, "cpu": cpu, "mem": mem,
            "etime": etime, "cmd": cmd[:500],
            "killable": killable, "protect_reason": reason,
        })
    procs.sort(key=lambda p: (-p["cpu"], p["pid"]))
    with open("/proc/loadavg") as f:
        load = [float(x) for x in f.read().split()[:3]]
    with open("/proc/uptime") as f:
        uptime_sec = float(f.read().split()[0])
    return {"ok": True, "load": load, "uptime_sec": uptime_sec, "procs": procs}


def descendants(pid):
    children = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", "rb") as f:
                data = f.read()
            rparen = data.rfind(b")")
            ppid = int(data[rparen + 2:].split()[1])
            children.setdefault(ppid, []).append(int(name))
        except Exception:
            continue
    result, stack = [], [pid]
    while stack:
        cur = stack.pop()
        for ch in children.get(cur, []):
            result.append(ch)
            stack.append(ch)
    return result  # order: shallow->deep; caller reverses for kill order


def do_kill(body):
    try:
        pid = int(body.get("pid"))
    except Exception:
        return {"ok": False, "error": "pid が不正です"}
    sig_name = body.get("sig", "TERM")
    if sig_name not in ("TERM", "KILL"):
        return {"ok": False, "error": "sig は TERM か KILL のみ"}
    tree = bool(body.get("tree", False))
    if not os.path.exists(f"/proc/{pid}"):
        return {"ok": False, "error": f"PID {pid} は既に存在しません"}
    if proc_uid(pid) != MY_UID:
        return {"ok": False, "error": "他ユーザーのプロセスは終了できません"}
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except Exception:
        cmd = ""
    reason = protect_reason(pid, cmd)
    if reason:
        return {"ok": False, "error": f"保護対象です（{reason}）"}
    targets = [pid]
    if tree:
        targets = list(reversed(descendants(pid))) + [pid]
    sig = signal.SIGTERM if sig_name == "TERM" else signal.SIGKILL
    killed, errors = [], []
    for t in targets:
        r = protect_reason(t, "")
        if t != pid and r:
            continue
        try:
            os.kill(t, sig)
            killed.append(t)
        except ProcessLookupError:
            pass
        except PermissionError:
            errors.append(t)
    return {"ok": True, "killed": killed, "errors": errors, "sig": sig_name}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/procs"):
            try:
                self._json(200, list_procs())
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
        elif self.path.startswith("/ping"):
            self._json(200, {"ok": True, "pid": MY_PID})
        else:
            self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path.startswith("/kill"):
            try:
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n) or b"{}")
                self._json(200, do_kill(body))
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
        else:
            self._json(404, {"ok": False, "error": "not found"})


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
