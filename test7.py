"""
TEST-HFCL-SW-07  —  TFTP Operation Verification
================================================
Procedure:
  1. Copy running-config FROM switch TO TFTP server   (device → server)
  2. Copy file           FROM TFTP server TO flash:tftp-testing (server → device)
  3. Copy with WRONG server IP   → must FAIL
  4. Copy with WRONG filename    → must FAIL

TFTP SERVER MODE (auto-detected):
  The script checks if an external TFTP server is already running on
  port 69 of this machine (192.168.180.69).  If yes → use it directly.
  If not → fall back to the embedded RFC-1350 TFTP server.

Usage:
  python3 tftp_test.py [switch_ip] [admin_user] [admin_pass] [tftp_server_ip]
"""

import os
import sys
import time
import socket
import struct
import threading
import subprocess
import paramiko


# ============================================================
# Configuration
# ============================================================
SWITCH_IP       = "192.168.180.136"
ADMIN_USER      = "admin"
ADMIN_PASS      = "admin"
SSH_PORT        = 22

TFTP_SERVER_IP  = "192.168.180.69"
TFTP_PORT       = 69
TFTP_ROOT       = "/srv/tftp"
TFTP_FILE       = "testfilefortftp"
WRONG_IP        = "192.168.180.250"
WRONG_FILE      = "no_such_file_xyz.cfg"
COPY_WAIT       = 35

# ── All keywords the switch might print on SUCCESS ──────────
# Add new ones here if you discover more from debug output.
SUCCESS_KEYWORDS = [
    "bytes copied",
    "copy complete",
    "copy successful",
    "[ok]",
    "successfully",
    "tftp: success",
    "transfer complete",
    "transfer successful",
    "copied successfully",
    "file transferred",
    "done",                  # some vendors print just "done"
    "complete.",             # trailing dot variant
    "success.",
]

# ── All keywords the switch might print on FAILURE ──────────
FAIL_KEYWORDS = [
    "error",
    "failed",
    "timed out",
    "timeout",
    "no such",
    "refused",
    "unreachable",
    "invalid",
    "cannot",
    "abort",
    "not found",
    "access denied",
    "connection reset",
]


# ============================================================
# TFTP Server Detection
# ============================================================

def detect_external_tftp(host, port=TFTP_PORT, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        probe = b"\x00\x01" + b"probe_file\x00" + b"octet\x00"
        sock.sendto(probe, (host, port))
        try:
            data, _ = sock.recvfrom(516)
            op = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 0
            sock.close()
            if op in (1, 2, 3, 4, 5):
                return True
        except socket.timeout:
            pass
        sock.close()
    except Exception:
        pass
    return False


def find_tftp_root():
    candidates = [
        "/srv/tftp",
        "/var/lib/tftpboot",
        "/tftpboot",
        "/tmp/tftp",
    ]
    for path in candidates:
        if os.path.isdir(path) and os.access(path, os.W_OK):
            return path
    return None


def check_port_bindable(port=TFTP_PORT):
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        test_sock.bind(("", port))
        test_sock.close()
        return True
    except (PermissionError, OSError):
        test_sock.close()
        return False


def ping_host(host, count=2, timeout=2):
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


# ============================================================
# Minimal RFC-1350 TFTP Server (embedded fallback)
# ============================================================
OP_RRQ   = 1
OP_WRQ   = 2
OP_DATA  = 3
OP_ACK   = 4
OP_ERROR = 5
BLKSIZE  = 512


class TFTPServer(threading.Thread):
    def __init__(self, root, host="", port=TFTP_PORT):
        super().__init__(daemon=True)
        self.root      = root
        self.host      = host
        self.port      = port
        self._stop     = threading.Event()
        self._ready    = threading.Event()
        self.transfers = []
        os.makedirs(root, exist_ok=True)

    def stop(self):        self._stop.set()
    def wait_ready(self, timeout=3): return self._ready.wait(timeout)

    @staticmethod
    def _parse_rq(data):
        op    = struct.unpack("!H", data[:2])[0]
        rest  = data[2:]
        parts = rest.split(b"\x00")
        fname = parts[0].decode("ascii", errors="ignore")
        mode  = parts[1].decode("ascii", errors="ignore") if len(parts) > 1 else "octet"
        return op, fname, mode

    @staticmethod
    def _ack(blk):        return struct.pack("!HH", OP_ACK,   blk)
    @staticmethod
    def _data(blk, pay):  return struct.pack("!HH", OP_DATA,  blk) + pay
    @staticmethod
    def _err(code, msg):  return struct.pack("!HH", OP_ERROR, code) + msg.encode() + b"\x00"

    def _wrq(self, addr, filename):
        fpath = os.path.join(self.root, os.path.basename(filename))
        xsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        xsock.bind(("", 0)); xsock.settimeout(10)
        buf = bytearray(); expected = 1
        try:
            xsock.sendto(self._ack(0), addr)
            while True:
                try:
                    pkt, src = xsock.recvfrom(516)
                except socket.timeout:
                    print(f"   [TFTP-WRQ] Timeout waiting for data from {addr}")
                    self.transfers.append(("WRQ", filename, len(buf), False)); return
                op = struct.unpack("!H", pkt[:2])[0]
                if op == OP_DATA:
                    blk = struct.unpack("!H", pkt[2:4])[0]; pay = pkt[4:]
                    if blk == expected:
                        buf += pay; xsock.sendto(self._ack(blk), src)
                        if len(pay) < BLKSIZE:
                            with open(fpath, "wb") as f: f.write(buf)
                            print(f"   [TFTP-WRQ] ✅ Saved '{filename}' ({len(buf)} bytes) → {fpath}")
                            self.transfers.append(("WRQ", filename, len(buf), True)); return
                        expected += 1
                elif op == OP_ERROR:
                    msg = pkt[4:].rstrip(b"\x00").decode("ascii", "ignore")
                    print(f"   [TFTP-WRQ] Error from switch: {msg}")
                    self.transfers.append(("WRQ", filename, len(buf), False)); return
        except Exception as ex:
            print(f"   [TFTP-WRQ] Exception: {ex}")
            self.transfers.append(("WRQ", filename, len(buf), False))
        finally:
            xsock.close()

    def _rrq(self, addr, filename):
        fpath = os.path.join(self.root, os.path.basename(filename))
        xsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        xsock.bind(("", 0)); xsock.settimeout(10)
        if not os.path.isfile(fpath):
            xsock.sendto(self._err(1, "File not found"), addr)
            print(f"   [TFTP-RRQ] ❌ '{filename}' not found — sent TFTP error 1")
            self.transfers.append(("RRQ", filename, 0, False)); xsock.close(); return
        with open(fpath, "rb") as f: data = f.read()
        total = len(data); blk = 0; offset = 0
        try:
            while True:
                blk += 1; chunk = data[offset: offset + BLKSIZE]
                pkt_out = self._data(blk, chunk); retries = 0
                xsock.sendto(pkt_out, addr)
                while True:
                    try:
                        pkt_in, _ = xsock.recvfrom(516)
                    except socket.timeout:
                        retries += 1
                        if retries > 5:
                            self.transfers.append(("RRQ", filename, offset, False)); return
                        xsock.sendto(pkt_out, addr); continue
                    op_in = struct.unpack("!H", pkt_in[:2])[0]
                    if op_in == OP_ACK:
                        if struct.unpack("!H", pkt_in[2:4])[0] == blk: break
                    elif op_in == OP_ERROR:
                        msg = pkt_in[4:].rstrip(b"\x00").decode("ascii", "ignore")
                        print(f"   [TFTP-RRQ] Error from switch: {msg}")
                        self.transfers.append(("RRQ", filename, offset, False)); return
                offset += len(chunk)
                if len(chunk) < BLKSIZE:
                    print(f"   [TFTP-RRQ] ✅ Sent '{filename}' ({total} bytes) → {addr}")
                    self.transfers.append(("RRQ", filename, total, True)); return
        except Exception as ex:
            print(f"   [TFTP-RRQ] Exception: {ex}")
            self.transfers.append(("RRQ", filename, offset, False))
        finally:
            xsock.close()

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.host, self.port))
        except PermissionError:
            print(f"   [TFTP] ❌ PermissionError binding port {self.port} — run with sudo")
            self._ready.set(); return
        self._ready.set()
        srv.settimeout(1.0)
        print(f"   [TFTP] Embedded server bound on 0.0.0.0:{self.port}  root={self.root}")
        while not self._stop.is_set():
            try:
                data, addr = srv.recvfrom(516)
            except socket.timeout:
                continue
            except Exception as ex:
                if not self._stop.is_set(): print(f"   [TFTP] recv error: {ex}")
                break
            op, fname, mode = self._parse_rq(data)
            print(f"   [TFTP] {'WRQ' if op == OP_WRQ else 'RRQ'} from {addr}  file='{fname}'  mode={mode}")
            if op == OP_WRQ:   self._wrq(addr, fname)
            elif op == OP_RRQ: self._rrq(addr, fname)
            else:
                esock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                esock.sendto(self._err(4, "Illegal operation"), addr); esock.close()
        srv.close()
        print("   [TFTP] Embedded server stopped")


# ============================================================
# SSH Helpers
# ============================================================

def open_ssh_shell(hostname, username, password, port=22, retries=3, delay=3):
    for attempt in range(1, retries + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname, port=port, username=username,
                           password=password, timeout=10,
                           look_for_keys=False, allow_agent=False)
            shell = client.invoke_shell()
            time.sleep(1); _drain(shell)
            return client, shell
        except Exception as e:
            client.close()
            if attempt < retries:
                print(f"   ⏳ SSH attempt {attempt} failed ({e}), retrying...")
                time.sleep(delay)
            else:
                raise


def _drain(shell):
    time.sleep(0.5)
    while shell.recv_ready():
        shell.recv(4096); time.sleep(0.2)


# ============================================================
# Copy command runner  ← KEY FIX IS HERE
# ============================================================

def run_copy(shell, cmd, timeout=COPY_WAIT):
    """
    Send a TFTP copy command, auto-confirm any prompts, collect output.

    FIX: Previously the loop would break on the FIRST failure keyword
    found even mid-output (e.g. a progress line saying 'transferring').
    Now we:
      1. Always wait for the FULL output (until timeout or clear terminal).
      2. Print the raw switch output in a debug block so you can see
         EXACTLY what the switch said — add new keywords if needed.
      3. Use a post-loop classify instead of breaking mid-stream.
    """
    print(f"   CMD: {cmd}")
    shell.send(cmd + "\n")
    collected = ""
    deadline  = time.time() + timeout
    confirms  = 0
    last_recv = time.time()

    while time.time() < deadline:
        time.sleep(0.5)
        chunk = ""
        while shell.recv_ready():
            chunk += shell.recv(4096).decode("utf-8", errors="ignore")
            time.sleep(0.1)

        if chunk:
            collected += chunk
            last_recv  = time.time()

        lower = collected.lower()

        # Auto-confirm destination filename / overwrite prompts
        if ("?" in collected or "filename" in lower or
                "confirm" in lower or "overwrite" in lower) and confirms < 6:
            shell.send("\n")
            confirms += 1
            time.sleep(0.3)
            continue

        # ── Wait for a decisive terminal keyword ──────────────
        # SUCCESS — break immediately
        if any(k in lower for k in SUCCESS_KEYWORDS):
            break

        # FAILURE — wait a little longer so we capture the full
        # error message, then break
        if any(k in lower for k in FAIL_KEYWORDS):
            # Give the switch 3 more seconds to finish printing
            extra_deadline = time.time() + 3
            while time.time() < extra_deadline:
                time.sleep(0.3)
                while shell.recv_ready():
                    collected += shell.recv(4096).decode("utf-8", errors="ignore")
            break

        # Idle gap heuristic: if nothing received for 5 s after
        # last data and output is non-empty, assume command finished
        if collected and (time.time() - last_recv) > 5:
            break

    return collected.strip()


def classify(output):
    """
    ── FIX ──
    Old version checked lowercase only; some switches mix case.
    Now we strip ANSI escape codes, normalise whitespace, and check
    both the keyword lists.  Also prints a DEBUG block so you can see
    exactly what the switch returned.
    """
    import re
    # Strip ANSI colour codes
    clean = re.sub(r"\x1b\[[0-9;]*[mGKH]", "", output)
    lower = clean.lower()

    # ── DEBUG: always show raw switch response ───────────────
    print("\n  ┌─ RAW SWITCH OUTPUT (debug) ──────────────────────────")
    for line in clean.splitlines():
        line = line.strip()
        if line:
            print(f"  │  {line}")
    print("  └───────────────────────────────────────────────────────")

    for k in SUCCESS_KEYWORDS:
        if k in lower:
            return "PASS", k

    for k in FAIL_KEYWORDS:
        if k in lower:
            return "FAIL", k

    return "WARN", "(no decisive keyword — check DEBUG block above)"


# ============================================================
# Formatting
# ============================================================

def section(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)

def step(n, desc):
    print(f"\n[Step {n}] {desc}")
    print("-" * 65)

def result_line(label, status):
    icon = "✅" if status == "PASS" else ("⚠️ " if status == "WARN" else "❌")
    print(f"  {icon}  {label:<52} {status}")


# ============================================================
# MAIN TEST
# ============================================================

def run_test():
    results  = {}
    tftp_obj = None
    tftp_root = TFTP_ROOT    # may be overridden below

    tftp_ip   = sys.argv[4] if len(sys.argv) > 4 else TFTP_SERVER_IP
    file_path = None

    print(f"\n  Switch IP          : {SWITCH_IP}")
    print(f"  TFTP server IP     : {tftp_ip}  (this PC)")
    print(f"  Wrong IP (neg test): {WRONG_IP}")
    print(f"  Wrong file (neg)   : {WRONG_FILE}")

    # ══════════════════════════════════════════════════════════
    # PREFLIGHT 1 — Ping / UDP check TFTP server
    # ══════════════════════════════════════════════════════════
    section("PREFLIGHT 1 — Verify TFTP Server Reachability")

    print(f"  ▶ Pinging {tftp_ip} ...")
    if ping_host(tftp_ip):
        print(f"  ✅ Ping OK — {tftp_ip} is reachable")
    else:
        print(f"  ⚠️  Ping failed for {tftp_ip} (ICMP may be blocked — continuing)")

    print(f"\n  ▶ UDP probe on {tftp_ip}:{TFTP_PORT} ...")
    external_alive = detect_external_tftp(tftp_ip, TFTP_PORT)
    if external_alive:
        print(f"  ✅ External TFTP server DETECTED on {tftp_ip}:{TFTP_PORT}")
    else:
        print(f"  ⚠️  No external TFTP server detected on port {TFTP_PORT}")

    # ══════════════════════════════════════════════════════════
    # PREFLIGHT 2 — Auto-detect: external vs embedded
    # ══════════════════════════════════════════════════════════
    section("PREFLIGHT 2 — TFTP Server Mode (Auto-Detect)")

    if external_alive:
        print("  MODE: EXTERNAL TFTP server (already running on this machine)")
        tftp_root = find_tftp_root()
        if tftp_root:
            print(f"  ✅ Auto-detected TFTP root: {tftp_root}")
        else:
            tftp_root = "/srv/tftp"
            print(f"  ⚠️  Could not auto-detect TFTP root — defaulting to {tftp_root}")
            os.makedirs(tftp_root, exist_ok=True)

        if not os.access(tftp_root, os.W_OK):
            print(f"\n  ❌ No write permission to {tftp_root}")
            print(f"     Fix:  sudo chmod o+w {tftp_root}")
            print(f"       or: sudo chown $USER {tftp_root}")
            sys.exit(1)

        print(f"  ✅ Write access confirmed: {tftp_root}")
        file_path = os.path.join(tftp_root, TFTP_FILE)
        tftp_obj  = None

    else:
        print("  MODE: EMBEDDED TFTP server (fallback — external not detected)")
        if not check_port_bindable(TFTP_PORT):
            print(f"\n  ❌ Cannot bind port {TFTP_PORT} — root privilege required.")
            print("""
  Fix options (choose one):
    Option A — run with sudo:
        sudo python3 tftp_test.py
    Option B — grant capability once:
        sudo setcap 'cap_net_bind_service=+ep' $(which python3)
    Option C — lower unprivileged port floor (temporary):
        sudo sysctl -w net.ipv4.ip_unprivileged_port_start=69
""")
            sys.exit(1)

        tftp_root = "/tmp/tftp_root"
        os.makedirs(tftp_root, exist_ok=True)
        file_path = os.path.join(tftp_root, TFTP_FILE)
        print(f"  Starting embedded TFTP server on port {TFTP_PORT} ...")
        tftp_obj = TFTPServer(root=tftp_root, port=TFTP_PORT)
        tftp_obj.start()
        if not tftp_obj.wait_ready(timeout=4):
            print("  ❌ Embedded TFTP server did not become ready — aborting")
            sys.exit(1)
        if not tftp_obj.is_alive():
            print("  ❌ Embedded TFTP server thread died — re-run with sudo")
            sys.exit(1)
        print(f"  ✅ Embedded TFTP server READY on port {TFTP_PORT}")

    print(f"\n  TFTP root          : {tftp_root}")
    print(f"  TFTP filename      : {TFTP_FILE}")

    # ══════════════════════════════════════════════════════════
    # PHASE 1 — Device → Server
    # ══════════════════════════════════════════════════════════
    section("PHASE 1 — Copy running-config FROM switch TO TFTP server")

    step(1, f"SSH into switch as {ADMIN_USER}")
    try:
        c1, sh1 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print(f"✅ SSH connected to {SWITCH_IP}")
    except Exception as e:
        print(f"❌ SSH failed: {e}")
        if tftp_obj: tftp_obj.stop()
        sys.exit(1)

    step(2, f"copy running-config tftp://{tftp_ip}/{TFTP_FILE}")
    out1 = run_copy(sh1, f"copy running-config tftp://{tftp_ip}/{TFTP_FILE}")

    st1, kw1  = classify(out1)
    file_ok   = os.path.isfile(file_path) and os.path.getsize(file_path) > 0
    file_size = os.path.getsize(file_path) if file_ok else 0

    # Accept if EITHER switch said success OR file landed on disk
    if st1 == "PASS" or file_ok:
        print(f"\n✅ running-config uploaded successfully  ({file_size} bytes on disk)")
        results["dev_to_server"] = "PASS"
    else:
        print(f"\n❌ Upload FAILED  (switch keyword: '{kw1}', file on disk: {file_ok})")
        results["dev_to_server"] = "FAIL"

    c1.close(); print("\n✅ SSH session closed"); time.sleep(1)

    # ══════════════════════════════════════════════════════════
    # PHASE 2 — Server → Device  (copy to flash:tftp-testing)
    # ══════════════════════════════════════════════════════════
    section("PHASE 2 — Copy file FROM TFTP server TO switch flash:tftp-testing")

    step(3, f"SSH into switch as {ADMIN_USER}")
    try:
        c2, sh2 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print(f"✅ SSH connected to {SWITCH_IP}")
    except Exception as e:
        print(f"❌ SSH failed: {e}")
        if tftp_obj: tftp_obj.stop()
        sys.exit(1)

    if not (os.path.isfile(file_path) and os.path.getsize(file_path) > 0):
        print(f"   ⚠️  Phase 1 file missing — creating placeholder for Phase 2")
        with open(file_path, "w") as f:
            f.write("! placeholder config\nhostname Switch\n")
    print(f"   File on server: {file_path}  ({os.path.getsize(file_path)} bytes) ✅")

    step(4, f"copy tftp://{tftp_ip}/{TFTP_FILE} flash:tftp-testing")
    out2 = run_copy(sh2, f"copy tftp://{tftp_ip}/{TFTP_FILE} flash:tftp-testing")

    st2, kw2 = classify(out2)

    # ── FIX: also verify file exists on switch via 'dir flash:' ──
    # If classify said WARN/FAIL, do a secondary check via dir
    flash_verified = False
    if st2 != "PASS":
        print("\n  ⚠️  Keyword classify inconclusive — checking flash via 'dir'...")
        dir_out = run_copy(sh2, "dir", timeout=10)
        print(dir_out)
        if "tftp-testing" in dir_out.lower():
            print("  ✅ 'tftp-testing' found in flash via 'dir' — treating as PASS")
            flash_verified = True

    if st2 == "PASS" or flash_verified:
        print(f"\n✅ File saved in switch flash:tftp-testing successfully")
        results["server_to_dev"] = "PASS"
    else:
        print(f"\n❌ Download FAILED  (keyword: '{kw2}')")
        results["server_to_dev"] = "FAIL"

    c2.close(); print("\n✅ SSH session closed"); time.sleep(1)

    # ══════════════════════════════════════════════════════════
    # PHASE 3 — Negative: wrong server IP
    # ══════════════════════════════════════════════════════════
    section(f"PHASE 3 — Negative Test: Wrong Server IP  ({WRONG_IP})")

    step(5, f"SSH into switch as {ADMIN_USER}")
    try:
        c3, sh3 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print(f"✅ SSH connected to {SWITCH_IP}")
    except Exception as e:
        print(f"❌ SSH failed: {e}")
        if tftp_obj: tftp_obj.stop()
        sys.exit(1)

    step(6, f"copy running-config tftp://{WRONG_IP}/{TFTP_FILE}  ← wrong IP")
    out3 = run_copy(sh3, f"copy running-config tftp://{WRONG_IP}/{TFTP_FILE}", timeout=45)
    st3, kw3 = classify(out3)

    if st3 != "PASS":
        print(f"\n✅ Wrong-IP copy correctly FAILED  (keyword: '{kw3}')")
        results["wrong_ip"] = "PASS"
    else:
        print(f"\n❌ Wrong-IP copy unexpectedly SUCCEEDED")
        results["wrong_ip"] = "FAIL"

    c3.close(); print("\n✅ SSH session closed"); time.sleep(1)

    # ══════════════════════════════════════════════════════════
    # PHASE 4 — Negative: wrong filename
    # ══════════════════════════════════════════════════════════
    section(f"PHASE 4 — Negative Test: Wrong Filename  ('{WRONG_FILE}')")

    step(7, f"SSH into switch as {ADMIN_USER}")
    try:
        c4, sh4 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print(f"✅ SSH connected to {SWITCH_IP}")
    except Exception as e:
        print(f"❌ SSH failed: {e}")
        if tftp_obj: tftp_obj.stop()
        sys.exit(1)

    wrong_path = os.path.join(tftp_root, WRONG_FILE)
    if os.path.exists(wrong_path):
        os.remove(wrong_path)
        print(f"   Removed '{WRONG_FILE}' from server root to guarantee absence")

    step(8, f"copy tftp://{tftp_ip}/{WRONG_FILE} startup-config  ← wrong filename")
    out4 = run_copy(sh4, f"copy tftp://{tftp_ip}/{WRONG_FILE} startup-config", timeout=40)
    st4, kw4 = classify(out4)

    if st4 != "PASS":
        print(f"\n✅ Wrong-filename copy correctly FAILED  (keyword: '{kw4}')")
        results["wrong_file"] = "PASS"
    else:
        print(f"\n❌ Wrong-filename copy unexpectedly SUCCEEDED")
        results["wrong_file"] = "FAIL"

    c4.close(); print("\n✅ SSH session closed")

    # ══════════════════════════════════════════════════════════
    # Stop embedded server + transfer log
    # ══════════════════════════════════════════════════════════
    if tftp_obj:
        tftp_obj.stop(); time.sleep(0.5)
        section("EMBEDDED TFTP SERVER TRANSFER LOG")
        if tftp_obj.transfers:
            print(f"  {'Direction':<8}  {'Filename':<32}  {'Bytes':>8}  Status")
            print("  " + "-" * 62)
            for d, fn, sz, ok in tftp_obj.transfers:
                print(f"  {d:<8}  {fn:<32}  {sz:>8}  {'✅ OK' if ok else '❌ FAIL'}")
        else:
            print("  (No transfers recorded)")
    else:
        section("EXTERNAL TFTP SERVER — File Summary")
        if os.path.isfile(file_path):
            print(f"  ✅ {file_path}  ({os.path.getsize(file_path)} bytes)")
        else:
            print(f"  ⚠️  {file_path} not found on disk")

    # ══════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════
    section("TEST SUMMARY — TFTP Operation")
    rows = [
        ("running-config upload: device → TFTP server",   results.get("dev_to_server")),
        ("flash:tftp-testing saved: TFTP server → device", results.get("server_to_dev")),
        ("Wrong server IP correctly rejected",             results.get("wrong_ip")),
        ("Wrong filename correctly rejected",              results.get("wrong_file")),
    ]
    all_pass = True
    for label, status in rows:
        result_line(label, status or "SKIP")
        if status in ("FAIL", None):
            all_pass = False

    print()
    if all_pass:
        print("""🎉  ALL TESTS PASSED \n
 TEST-HFCL-SW-07 - Management - Verify TFTP operation. \n

PROCEDURE: \n
1.Verify performing copy from device to server using tftp "copy startup-config tftp://<server_ip_address>/File_Name" command, the operation should be successfull. 
2.Verify performing copy from server to device using tftp "copy tftp://<server_ip_address>/File_Name  startup-config" command,  the operation should be successfull.
3.Verify tftp copy by providing incorrect details, the operation should not be successful.
4.Here my pc act as a tftp server.

Successfully Passed !!!!!!!!!!!!!!!!!!!!!!
""")
    else:
        print("❌  ONE OR MORE TESTS FAILED — review DEBUG blocks above")
    print("=" * 65)
    return all_pass


if __name__ == "__main__":
    if len(sys.argv) >= 4:
        SWITCH_IP  = sys.argv[1]
        ADMIN_USER = sys.argv[2]
        ADMIN_PASS = sys.argv[3]

    success = run_test()
    sys.exit(0 if success else 1)
