#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tkinter debug console for the usbnet web service (Roman firmware).

A one-window GUI for poking at a running Pico over its USB network interface.
It is built around the POST /debug endpoint and also drives the three storage
endpoints, so a single tool covers "what state is the board in?" and "make it
do something".

Endpoints used (see README.md / web_server.h):

    POST /debug                          diagnostics snapshot
    POST /debug  {"action":"clear"}      erase the stored keys (recovery path)
    POST /debug  {"action":"reset"}      reboot the board (~100 ms later)
    GET  /info                           device id + provisioning state
    POST /write  {"pk":...,"sk":...,"device_id":...}   one shot provisioning
    POST /clear  {"ed25519_sk":...}  erase, proving the provisioning secret
    POST /sign   {"challenge":...,"context":...,"timestamp":...}   test signing

Nothing runs on the network in the Tk thread: every request is executed by a
single worker thread and its result is handed back through a queue, so the UI
stays responsive and requests can never overlap (which matters when a clear
and a print are queued back to back).

The window text is Chinese; the code and comments stay English to match the
rest of the repository.

Standard library only: tkinter + urllib. Tested with Python 3.8+ / Tk 8.6.

Usage:
    python debug_tool.py
    python debug_tool.py --host 192.168.7.1 --port 80 --interval 2
"""

import argparse
import json
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk
from urllib import error as uerr
from urllib import request as ureq

# ---------------------------------------------------------------------------
# response model
# ---------------------------------------------------------------------------


class Result:
    """Outcome of one HTTP request.

    status  HTTP status code, or None when the request never got an answer
            (connection refused, timeout, ...).
    body    response body as bytes (b"" when unknown).
    ms      wall-clock duration in milliseconds.
    error   human readable transport error, or None.
    """

    __slots__ = ("status", "body", "ms", "error")

    def __init__(self, status, body, ms, error=None):
        self.status = status
        self.body = body
        self.ms = ms
        self.error = error

    @property
    def ok(self):
        return self.status is not None and 200 <= self.status < 300

    def text(self):
        return self.body.decode("utf-8", "replace")

    def json(self):
        """Parsed body, or None when it is not JSON."""
        try:
            return json.loads(self.text())
        except ValueError:
            return None


class UsbNetClient:
    """Blocking HTTP client for the firmware's web service.

    Every method returns a Result instead of raising, so the GUI can display
    failures. Safe to call from any thread.
    """

    def __init__(self, host="192.168.7.1", port=80, timeout=5.0):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)

    @property
    def base(self):
        return "http://%s:%d" % (self.host, self.port)

    def request(self, method, path, payload=None):
        url = self.base + path
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = payload.encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = ureq.Request(url, data=data, method=method, headers=headers)
        t0 = time.perf_counter()
        try:
            with ureq.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                status = resp.status
        except uerr.HTTPError as e:          # 4xx / 5xx still carry a body
            body = e.read()
            status = e.code
        except Exception as e:               # URLError, timeout, ...
            return Result(None, b"", (time.perf_counter() - t0) * 1000.0, str(e))
        return Result(status, body, (time.perf_counter() - t0) * 1000.0)

    # -- individual endpoints ------------------------------------------------

    def snapshot(self):
        return self.request("POST", "/debug")

    def debug_action(self, action):
        return self.request("POST", "/debug", json.dumps({"action": action}))

    def info(self):
        return self.request("GET", "/info")

    def provision(self, pk_b64, sk_b64, device_id):
        return self.request("POST", "/write",
                            json.dumps({"pk": pk_b64, "sk": sk_b64,
                                        "device_id": device_id}))

    def clear_with_key(self, ed25519_sk_b64):
        # POST /clear wants the Ed25519 secret key that was provisioned, not the
        # X25519 one (the board never hands that out).
        return self.request("POST", "/clear",
                           json.dumps({"ed25519_sk": ed25519_sk_b64}))

    def sign(self, challenge, context, timestamp):
        return self.request("POST", "/sign",
                            json.dumps({"challenge": challenge, "context": context,
                                        "timestamp": timestamp}))


# ---------------------------------------------------------------------------
# snapshot presentation
# ---------------------------------------------------------------------------


def format_uptime(ms):
    """123456 ms -> '2m 03.456s (123456 ms)'."""
    if not isinstance(ms, (int, float)):
        return str(ms)
    secs, rem = divmod(int(ms), 1000)
    mins, secs = divmod(secs, 60)
    hours, mins = divmod(mins, 60)
    if hours:
        human = "%d时 %02d分 %02d秒" % (hours, mins, secs)
    elif mins:
        human = "%d分 %02d秒" % (mins, secs)
    else:
        human = "%d.%03d秒" % (secs, rem)
    return "%s (%d ms)" % (human, int(ms))


def format_bytes(n):
    if not isinstance(n, (int, float)):
        return str(n)
    return "%d 字节" % n


def format_bool(v):
    if v is True:
        return "是"
    if v is False:
        return "否"
    return str(v)


def format_offset(n):
    if isinstance(n, int):
        return "%d (0x%X)" % (n, n)
    return str(n)


def _get(d, *keys, **kw):
    """Nested dict lookup that tolerates missing/!dict levels."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return kw.get("default")
        cur = cur[k]
    return cur


# storage self-test results come off the wire as ok/empty/corrupt
SELFTEST_ZH = {"ok": "正常", "empty": "空", "corrupt": "损坏"}

# (group, key, value formatter, source path inside the snapshot)
SNAPSHOT_LAYOUT = (
    ("系统", "uptime_ms", format_uptime, ("uptime_ms",)),
    ("系统", "sdk", str, ("sdk",)),
    ("系统", "cpu_mhz", lambda v: "%s MHz" % v if v is not None else "-", ("cpu_mhz",)),
    ("系统", "unique_id", str, ("unique_id",)),
    ("系统", "reset_by_watchdog", format_bool, ("reset_by_watchdog",)),
    ("系统", "stack.used_now", format_bytes, ("stack", "used_now")),
    ("系统", "stack.used_max", format_bytes, ("stack", "used_max")),
    # 最小剩余栈空间：新增深层调用后必须看这一项（见 README 的 Stack budget）
    ("系统", "stack.free_min", format_bytes, ("stack", "free_min")),
    ("系统", "stack.total", format_bytes, ("stack", "total")),
    ("网络", "net.ip", str, ("net", "ip")),
    ("网络", "net.mac", str, ("net", "mac")),
    ("网络", "net.link_up", format_bool, ("net", "link_up")),
    ("请求", "web.conns", str, ("web", "conns")),
    ("请求", "web.conns_max", str, ("web", "conns_max")),
    ("请求", "web.requests", str, ("web", "requests")),
    ("请求", "web.sign_ok", str, ("web", "sign_ok")),
    ("请求", "web.sign_bad", str, ("web", "sign_bad")),
    ("请求", "web.write_ok", str, ("web", "write_ok")),
    ("请求", "web.write_bad", str, ("web", "write_bad")),
    ("请求", "web.clear_ok", str, ("web", "clear_ok")),
    ("请求", "web.clear_bad", str, ("web", "clear_bad")),
    ("请求", "web.not_found", str, ("web", "not_found")),
    ("请求", "web.too_large", str, ("web", "too_large")),
    ("请求", "web.errors", str, ("web", "errors")),
    ("存储", "storage.writen", format_bool, ("storage", "writen")),
    ("存储", "storage.available", format_bool, ("storage", "available")),
    ("存储", "storage.selftest", lambda v: SELFTEST_ZH.get(v, str(v)), ("storage", "selftest")),
    ("存储", "storage.plaintext_len", format_bytes, ("storage", "plaintext_len")),
    ("存储", "storage.max_payload", format_bytes, ("storage", "max_payload")),
    ("存储", "storage.flash_offset", format_offset, ("storage", "flash_offset")),
    # 上次复位时配网卡在哪一步（看门狗 scratch 记录，无需 UART）
    ("Roman", "roman.last_stage", str, ("roman", "last_stage")),
    ("Roman", "roman.device_id", str, ("roman", "device_id")),
    ("Roman", "roman.ed25519_pk", str, ("roman", "ed25519_pk")),
    ("Roman", "roman.x25519_pk", str, ("roman", "x25519_pk")),
)

# internal task keys -> the Chinese name used in the log and status bar
LABEL_ZH = {"snapshot": "快照", "info": "设备信息", "sign": "签名",
            "write": "写入密钥", "clear": "清除存储", "reset": "重启设备"}


def zh_label(label):
    return LABEL_ZH.get(label, label)

# numeric fields for which a delta against the previous snapshot is useful
DELTA_KEYS = {
    "web.requests", "web.sign_ok", "web.sign_bad", "web.write_ok",
    "web.write_bad", "web.clear_ok", "web.clear_bad", "web.not_found",
    "web.too_large", "web.errors",
}

# JSON null also means "no value yet"; these fields still get a row.
NULL_TEXT = {"roman.device_id": "（未配网）"}


def snapshot_rows(doc, previous=None):
    """Flatten a /debug response into [(group, key, value_text, raw), ...].

    Returns [] when doc is not a snapshot (missing or non-dict "debug"), which
    is how the caller detects 404 / DEBUG_AVAILABLE=0 responses.
    """
    body = doc.get("debug") if isinstance(doc, dict) else None
    if not isinstance(body, dict):
        return []
    rows = []
    for group, key, fmt, path in SNAPSHOT_LAYOUT:
        # The group node names the source object, so "web.requests" is shown as
        # plain "requests"; only the stack sub-object keeps its prefix.
        label = key if key.startswith("stack.") else key.rsplit(".", 1)[-1]
        raw = _get(body, *path)
        if raw is None:
            # A field that is legitimately null (the device id before the board
            # has been provisioned) keeps its row so the gap is visible.
            if key in NULL_TEXT:
                rows.append((group, label, NULL_TEXT[key], None))
            continue
        try:
            text = fmt(raw)
        except Exception:
            text = str(raw)
        if previous is not None and key in DELTA_KEYS:
            old = _get(previous, *path)
            if isinstance(raw, int) and isinstance(old, int):
                delta = raw - old
                if delta:
                    text += "  (+%d)" % delta
        rows.append((group, label, text, raw))
    return rows


def selftest_severity(value):
    """Tag name for a storage self-test result."""
    if value == "ok":
        return "ok"
    if value == "corrupt":
        return "err"
    return "muted"


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

AUTO_MIN_MS = 250  # floor for the auto-refresh interval


class DebugApp:
    """The whole window: toolbar, action buttons, telemetry tree, raw, log."""

    def __init__(self, root, client):
        self.root = root
        self.client = client
        self.previous_snapshot = None      # for the (+delta) column
        self.last_snapshot_doc = None
        self.auto = tk.BooleanVar(value=False)
        self.pending_reset = False
        self.inflight = False           # worker is executing a request
        self._auto_job = None           # pending after() handle for auto refresh

        self._tasks = queue.Queue()        # (label, callable) -> worker
        self._results = queue.Queue()      # (label, callable, Result) -> UI
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker.start()

        self._build_ui()
        self._pump()
        self._schedule_auto()
        # Probe once as soon as the window is up: the tool should never open
        # looking empty, and a dead link is reported immediately.
        self.root.after(150, self._initial_probe)
        # Retime the auto refresh as soon as the interval box changes, instead
        # of waiting out an already-scheduled (possibly much longer) delay.
        self.interval_var.trace_add("write", lambda *_: self._schedule_auto())

    # -- construction --------------------------------------------------------

    def _build_ui(self):
        self.root.title("usbnet 调试台 - roman")
        # Fit smaller displays instead of opening partly off-screen.
        w = max(820, min(1020, self.root.winfo_screenwidth() - 60))
        h = max(560, min(740, self.root.winfo_screenheight() - 120))
        self.root.geometry("%dx%d" % (w, h))
        self.root.minsize(820, 560)

        # Chinese labels need a CJK-capable UI font; if the family is missing
        # Tk silently keeps its default, so this cannot break startup.
        for fname in ("TkDefaultFont", "TkTextFont", "TkHeadingFont", "TkMenuFont"):
            try:
                tkfont.nametofont(fname).configure(family="Microsoft YaHei UI", size=10)
            except Exception:
                pass

        pad = {"padx": 6, "pady": 4}

        # --- target toolbar
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", **pad)
        ttk.Label(bar, text="主机").pack(side="left")
        self.host_var = tk.StringVar(value=self.client.host)
        ttk.Entry(bar, textvariable=self.host_var, width=16).pack(side="left", padx=(4, 10))
        ttk.Label(bar, text="端口").pack(side="left")
        self.port_var = tk.StringVar(value=str(self.client.port))
        ttk.Entry(bar, textvariable=self.port_var, width=6).pack(side="left", padx=(4, 10))
        ttk.Label(bar, text="超时(秒)").pack(side="left")
        self.timeout_var = tk.StringVar(value=str(self.client.timeout))
        ttk.Entry(bar, textvariable=self.timeout_var, width=5).pack(side="left", padx=(4, 10))
        ttk.Checkbutton(bar, text="自动刷新", variable=self.auto,
                        command=self._on_auto_toggle).pack(side="left", padx=(0, 6))
        ttk.Label(bar, text="间隔").pack(side="left")
        self.interval_var = tk.StringVar(value="2")
        ttk.Spinbox(bar, from_=0.25, to=60, increment=0.25, width=5,
                    textvariable=self.interval_var).pack(side="left", padx=(4, 4))
        ttk.Label(bar, text="秒").pack(side="left")

        # --- actions
        act = ttk.Frame(self.root)
        act.pack(fill="x", **pad)
        self.btn_snapshot = ttk.Button(act, text="快照 (F5)",
                                       command=lambda: self._submit("snapshot", self.client.snapshot))
        self.btn_snapshot.pack(side="left")
        self.btn_info = ttk.Button(act, text="设备信息",
                                   command=lambda: self._submit("info", self.client.info))
        self.btn_info.pack(side="left", padx=4)
        self.btn_sign = ttk.Button(act, text="试签一个",
                                   command=self._on_sign)
        self.btn_sign.pack(side="left", padx=4)
        self.btn_write = ttk.Button(act, text="写入密钥",
                                    command=self._on_write)
        self.btn_write.pack(side="left", padx=4)
        self.btn_clear = ttk.Button(act, text="清除存储",
                                    command=self._on_clear)
        self.btn_clear.pack(side="left", padx=4)
        self.btn_reset = ttk.Button(act, text="重启设备",
                                    command=self._on_reset)
        self.btn_reset.pack(side="left", padx=4)
        self.btn_clear_log = ttk.Button(act, text="清空日志", command=self._clear_log)
        self.btn_clear_log.pack(side="right")

        # --- provisioning form (POST /write): pk / sk as base64, plus the id
        form = ttk.LabelFrame(self.root, text="POST /write 配网（一次性）")
        form.pack(fill="x", **pad)
        ttk.Label(form, text="device_id").pack(side="left")
        self.device_id_var = tk.StringVar(value="dev-01")
        ttk.Entry(form, textvariable=self.device_id_var, width=14).pack(side="left", padx=(4, 10))
        ttk.Label(form, text="pk (base64)").pack(side="left")
        self.pk_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.pk_var).pack(side="left", fill="x", expand=True, padx=(4, 10))
        ttk.Label(form, text="sk (base64)").pack(side="left")
        self.sk_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.sk_var, show="*").pack(side="left", fill="x", expand=True, padx=(4, 6))

        # --- panes: telemetry | (raw, log)
        outer = ttk.Panedwindow(self.root, orient="horizontal")
        outer.pack(fill="both", expand=True, **pad)

        left = ttk.Frame(outer)
        outer.add(left, weight=3)
        ttk.Label(left, text="遥测 (POST /debug)").pack(anchor="w")
        self.tree = ttk.Treeview(left, columns=("value",), show="tree headings",
                                 selectmode="browse")
        self.tree.heading("#0", text="项目")
        self.tree.heading("value", text="值")
        self.tree.column("#0", width=200, minwidth=120, stretch=False)
        self.tree.column("value", width=240, minwidth=120, anchor="w", stretch=True)
        tree_sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tree_sb.pack(side="right", fill="y")

        right = ttk.Panedwindow(outer, orient="vertical")
        outer.add(right, weight=4)

        raw_frame = ttk.Frame(right)
        right.add(raw_frame, weight=1)
        ttk.Label(raw_frame, text="最近响应体").pack(anchor="w")
        raw_box = ttk.Frame(raw_frame)
        raw_box.pack(fill="both", expand=True)
        self.raw = tk.Text(raw_box, height=10, wrap="none",
                           font=("Consolas", 9), background="#fbfbfb")
        raw_sb = ttk.Scrollbar(raw_box, orient="vertical", command=self.raw.yview)
        raw_xsb = ttk.Scrollbar(raw_box, orient="horizontal", command=self.raw.xview)
        self.raw.configure(yscrollcommand=raw_sb.set, xscrollcommand=raw_xsb.set)
        self.raw.grid(row=0, column=0, sticky="nsew")
        raw_sb.grid(row=0, column=1, sticky="ns")
        raw_xsb.grid(row=1, column=0, sticky="ew")
        raw_box.rowconfigure(0, weight=1)
        raw_box.columnconfigure(0, weight=1)

        log_frame = ttk.Frame(right)
        right.add(log_frame, weight=2)
        ttk.Label(log_frame, text="日志").pack(anchor="w")
        log_box = ttk.Frame(log_frame)
        log_box.pack(fill="both", expand=True)
        self.log = tk.Text(log_box, height=12, wrap="none",
                           font=("Consolas", 9), state="disabled", background="#fbfbfb")
        log_sb = ttk.Scrollbar(log_box, orient="vertical", command=self.log.yview)
        log_xsb = ttk.Scrollbar(log_box, orient="horizontal", command=self.log.xview)
        self.log.configure(yscrollcommand=log_sb.set, xscrollcommand=log_xsb.set)
        self.log.grid(row=0, column=0, sticky="nsew")
        log_sb.grid(row=0, column=1, sticky="ns")
        log_xsb.grid(row=1, column=0, sticky="ew")
        log_box.rowconfigure(0, weight=1)
        log_box.columnconfigure(0, weight=1)
        for tag, colour in (("tx", "#0a58ca"), ("ok", "#146c2e"),
                            ("warn", "#9a6700"), ("err", "#b3261e"),
                            ("muted", "#6c757d")):
            self.log.tag_configure(tag, foreground=colour)

        # --- status bar
        self.status = tk.StringVar(value="就绪")
        ttk.Label(self.root, textvariable=self.status, anchor="w",
                  relief="sunken").pack(fill="x", side="bottom")

        self.root.bind("<F5>", lambda _e: self._submit("snapshot", self.client.snapshot))
        self.root.bind("<Control-l>", lambda _e: self._clear_log())
        self._log("muted", "就绪 - 目标 %s, POST /debug" % self.client.base)

    # -- logging / helpers ---------------------------------------------------

    def _stamp(self):
        return time.strftime("%H:%M:%S")

    def _log(self, tag, message):
        self.log.configure(state="normal")
        self.log.insert("end", "[%s] %s\n" % (self._stamp(), message), tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _set_status(self, text):
        self.status.set(text)

    def _set_raw(self, text):
        self.raw.delete("1.0", "end")
        self.raw.insert("1.0", text)

    def _sync_target(self):
        """Push the entry values into the client (called before each request)."""
        self.client.host = self.host_var.get().strip() or "192.168.7.1"
        try:
            self.client.port = int(self.port_var.get())
        except ValueError:
            self.client.port = 80
            self.port_var.set("80")
        try:
            self.client.timeout = max(0.1, float(self.timeout_var.get()))
        except ValueError:
            self.client.timeout = 5.0
            self.timeout_var.set("5.0")

    def _describe(self, label, result, doc=None):
        """One log line summarising a Result."""
        if result.error:
            return "err", "%s -> %s" % (zh_label(label), result.error)
        tag = "ok" if result.ok else "warn"
        head = "%s -> HTTP %s, 耗时 %.0f ms" % (zh_label(label), result.status, result.ms)
        # Snapshots are summarised rather than dumped: with auto refresh on, the
        # full JSON every second would bury everything else, and the body is
        # already in the "Last response body" pane.
        if label == "snapshot" and result.ok and isinstance(doc, dict) and "debug" in doc:
            uptime = _get(doc, "debug", "uptime_ms")
            selftest = _get(doc, "debug", "storage", "selftest", default="?")
            return tag, "%s | 存储=%s | 运行=%s | 请求=%s | 错误=%s" % (
                head,
                SELFTEST_ZH.get(selftest, selftest),
                format_uptime(uptime) if uptime is not None else "-",
                _get(doc, "debug", "web", "requests", default="?"),
                _get(doc, "debug", "web", "errors", default="?"))
        body = result.text().strip().replace("\n", " ")
        if len(body) > 160:
            body = body[:157] + "..."
        return tag, "%s  %s" % (head, body)

    # -- worker plumbing -----------------------------------------------------

    def _submit(self, label, func):
        self._sync_target()
        self._tasks.put((label, func))
        self._set_status("%s ..." % zh_label(label))

    def _worker_loop(self):
        while True:
            label, func = self._tasks.get()
            self.inflight = True
            try:
                result = func()
            except Exception as e:                       # never kill the worker
                result = Result(None, b"", 0.0, "internal: %r" % (e,))
            finally:
                self.inflight = False
            self._results.put((label, result))

    def _pump(self):
        """Drain worker results into the UI (main thread only)."""
        try:
            while True:
                label, result = self._results.get_nowait()
                self._handle_result(label, result)
        except queue.Empty:
            pass
        self.root.after(50, self._pump)

    # -- result handling -----------------------------------------------------

    def _handle_result(self, label, result):
        doc = None if result.error else result.json()
        tag, line = self._describe(label, result, doc)
        self._log(tag, line)

        if result.error:
            self._set_status("无法连接：%s" % result.error)
            return

        self._set_raw(json.dumps(doc, indent=2) if doc is not None else result.text())

        if label == "snapshot":
            self._apply_snapshot(result, doc)
        elif label in ("info", "sign"):
            self._set_status("%s：HTTP %s，耗时 %.0f ms"
                             % (zh_label(label), result.status, result.ms))
        elif label in ("write", "clear", "reset"):
            self._set_status("%s：HTTP %s" % (zh_label(label), result.status))
            if label == "reset" and result.ok:
                self._after_reset()
            if label == "clear" and result.ok:
                self.previous_snapshot = None

    def _apply_snapshot(self, result, doc):
        if result.status == 404:
            self._log("warn", "POST /debug 未启用：该固件编译时 DEBUG_AVAILABLE 为 0")
            self._set_status("HTTP 404 - /debug 已被编译移除 (DEBUG_AVAILABLE 0)")
            self._fill_tree([])
            return
        if not result.ok:
            self._set_status("快照失败：HTTP %s" % result.status)
            return

        rows = snapshot_rows(doc, self.previous_snapshot)
        if not rows:
            self._log("warn", "快照响应格式异常（缺少 \"debug\" 对象）")
            self._set_status("快照：无法识别的响应体")
            self._fill_tree([])
            return

        self._fill_tree(rows)
        if isinstance(doc, dict) and isinstance(doc.get("debug"), dict):
            self.previous_snapshot = doc["debug"]
        self.last_snapshot_doc = doc

        selftest = _get(doc, "debug", "storage", "selftest")
        if selftest == "corrupt":
            self._log("err", "存储自检失败：已存数据损坏（MAC 校验未通过）"
                             " - 请执行“清除存储”后重新写入")
        self._set_status("快照正常，耗时 %.0f ms | 存储=%s | 运行=%s"
                         % (result.ms, SELFTEST_ZH.get(selftest, selftest),
                            format_uptime(_get(doc, "debug", "uptime_ms"))))

    def _fill_tree(self, rows):
        self.tree.delete(*self.tree.get_children())
        nodes = {}
        for group, key, text, raw in rows:
            parent = nodes.get(group)
            if parent is None:
                parent = self.tree.insert("", "end", text=group, open=True,
                                          values=("",))
                nodes[group] = parent
            tag = ()
            if key == "selftest":
                tag = (selftest_severity(raw),)
            elif key == "available" and raw is False:
                tag = ("muted",)
            self.tree.insert(parent, "end", text=key, values=(text,), tags=tag)
        for tag, colour in (("ok", "#146c2e"), ("err", "#b3261e"), ("muted", "#6c757d")):
            self.tree.tag_configure(tag, foreground=colour)

    # -- button handlers -----------------------------------------------------

    def _on_write(self):
        pk = self.pk_var.get().strip()
        sk = self.sk_var.get().strip()
        device_id = self.device_id_var.get().strip()
        if not pk or not sk or not device_id:
            messagebox.showwarning("配网参数不足",
                                   "pk、sk 与 device_id 都必须填写。", parent=self.root)
            return
        self._submit("write", lambda: self.client.provision(pk, sk, device_id))

    def _on_sign(self):
        # A fixed probe message: enough to prove the stored key signs and that
        # the server is provisioned, without inventing client state.
        self._submit("sign", lambda: self.client.sign("probe", "debug-tool", "0"))

    def _on_clear(self):
        # /clear authenticates with the Ed25519 secret key that was provisioned,
        # which the form above already holds - so no extra credential to type in.
        key = self.sk_var.get().strip()
        if not key:
            messagebox.showwarning("缺少擦除凭据",
                                   "请先在 pk/sk 表单里填入配网时用的 Ed25519 私钥（sk），\n"
                                   "POST /clear 需要它来授权擦除。", parent=self.root)
            return
        if not messagebox.askyesno("清除存储",
                                   "确定要清除 %s 上已存储的密钥与 device_id 吗？\n\n"
                                   "将用表单里的 Ed25519 私钥授权（POST /clear）；"
                                   "清除后 writen 回到 0，可以重新配网。" % self.client.base,
                                   parent=self.root):
            return
        self._submit("clear", lambda: self.client.clear_with_key(key))

    def _on_reset(self):
        if not messagebox.askyesno("重启设备",
                                   "确定要重启 %s 上的设备吗？\n\n"
                                   "USB 连接会中断几秒钟。" % self.client.base,
                                   parent=self.root):
            return
        self._submit("reset", lambda: self.client.debug_action("reset"))

    def _initial_probe(self):
        self._submit("snapshot", self.client.snapshot)

    def _after_reset(self):
        """One retry once the board has had time to re-enumerate."""
        self._log("muted", "设备正在重启；6 秒后自动重试快照")
        self.pending_reset = True
        self.previous_snapshot = None
        self.root.after(6000, self._post_reset_snapshot)

    def _post_reset_snapshot(self):
        self.pending_reset = False
        self._submit("snapshot", self.client.snapshot)

    # -- auto refresh --------------------------------------------------------

    def _on_auto_toggle(self):
        if self.auto.get():
            self._log("muted", "自动刷新已开启（每 %s 秒）" % self.interval_var.get())
            self._submit("snapshot", self.client.snapshot)
        else:
            self._log("muted", "自动刷新已关闭")

    def _interval_ms(self):
        try:
            secs = float(self.interval_var.get())
        except ValueError:
            secs = 2.0
        return max(AUTO_MIN_MS, int(secs * 1000))

    def _schedule_auto(self):
        """(Re)arm the auto-refresh timer with the current interval."""
        if self._auto_job is not None:
            self.root.after_cancel(self._auto_job)
        self._auto_job = self.root.after(self._interval_ms(), self._auto_tick)

    def _auto_tick(self):
        self._auto_job = None
        # Skip while a request is still running or queued, so a slow or dead
        # link cannot build up a backlog of snapshots.
        if (self.auto.get() and not self.pending_reset
                and not self.inflight and self._tasks.empty()):
            self._submit("snapshot", self.client.snapshot)
        self._schedule_auto()


# ---------------------------------------------------------------------------


def enable_dpi_awareness():
    """Sharper text on high-DPI Windows displays; harmless elsewhere."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


def main(argv=None):
    ap = argparse.ArgumentParser(description="usbnet web 服务 Tkinter 调试台")
    ap.add_argument("--host", default="192.168.7.1",
                    help="Pico 地址（默认 192.168.7.1）")
    ap.add_argument("--port", type=int, default=80, help="HTTP 端口（默认 80）")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="单次请求超时秒数（默认 5）")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="自动刷新间隔秒数（默认 2）")
    ap.add_argument("--auto", action="store_true",
                    help="启动即开启自动刷新（每次快照都会在板上跑一遍存储自检，"
                         "因此默认关闭）")
    args = ap.parse_args(argv)

    enable_dpi_awareness()
    client = UsbNetClient(args.host, args.port, args.timeout)
    root = tk.Tk()
    app = DebugApp(root, client)
    app.interval_var.set(str(args.interval))
    if args.auto:
        app.auto.set(True)
        app._log("muted", "已通过命令行开启自动刷新")
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
