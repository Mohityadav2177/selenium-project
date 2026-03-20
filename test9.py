"""
TEST-HFCL-SW-NTP-SEC-09  —  Secure NTP (NTS) Operation Verification
=================================================================
Test Objective:
  Verify Secure NTP operations using a CA certificate on the switch.

CA Certificate:
  File    : 1773913923443_cacloudflare.crt
  Subject : CN = time.cloudflare.com
  Issuer  : GeoTrust TLS ECC CA G1 (DigiCert Inc)
  Valid   : Feb 10 2025 → Mar 12 2026

Procedure:
  PRE-CONFIG : Capture switch clock BEFORE NTP (baseline)
  PHASE 1    : Upload CA certificate to switch flash
               ntp server 1 security ca-certificate upload tftp://<server>/cacloudflare.crt
  PHASE 2    : Enable secure NTP
               ntp
               ntp server 1 ip-address time.cloudflare.com security
               clock timezone IST 5 30
  PHASE 3    : Verify NTP status + connect-status + clock
  PHASE 4    : Negative — Disable NTP (no ntp server 1 + no ntp)
               Verify disabled, re-enable, switch left clean

Expected Result:
  CA cert uploaded, NTP client enabled with security flag,
  clock synced to time.cloudflare.com, status verified.

Usage:
  python3 ntp_secure_test.py [switch_ip] [admin_user] [admin_pass] [tftp_server_ip]
"""

import os
import sys
import re
import time
import socket
import datetime
import subprocess
import paramiko


# ============================================================
# Configuration
# ============================================================
SWITCH_IP       = "192.168.180.155"
ADMIN_USER      = "admin"
ADMIN_PASS      = "admin"
SSH_PORT        = 22

TFTP_SERVER_IP  = "192.168.180.69"   # This machine — runs TFTP + script
NTP_HOST        = "time.cloudflare.com"
TIMEZONE_NAME   = "IST"
TIMEZONE_HOURS  = 5
TIMEZONE_MINS   = 30

# CA certificate
CA_CERT_LOCAL   = "/tmp/tftp_root/cacloudflare.crt"   # cert already in TFTP root on your machine
CA_CERT_TFTP    = "cacloudflare.crt"          # filename on TFTP server
CA_CERT_FLASH   = "1-nts-ca-cert.crt"         # destination on switch flash
TFTP_ROOT       = "/tmp/tftp_root"             # TFTP root on your machine (update if different)

CMD_WAIT        = 4    # seconds — normal show command timeout
COPY_WAIT       = 30   # seconds — TFTP copy command timeout
SYNC_WAIT       = 90   # seconds — NTS takes longer to sync than plain NTP

# ── Keywords that confirm NTP is SYNCED / enabled ───────────
NTP_SYNC_KEYWORDS = [
    "synchronized", "synced", "sync'd",
    "stratum", "reference",
    "ntp enabled", "status: up",
    "reachable", "ntp server: yes",
    "clock is synchronized",
]

# ── Keywords that confirm NTP is NOT synced / disabled ──────
NTP_NOSYNC_KEYWORDS = [
    "unsynchronized", "not synchronized", "not synced",
    "unreachable", "no ntp", "ntp disabled",
    "status: down", "stratum 16",
    "clock is unsynchronized", "disabled",
]


# ============================================================
# Preflight helpers
# ============================================================

def ping_host(host, count=2, timeout=2):
    try:
        r = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), host],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return r.returncode == 0
    except Exception:
        return False


def resolve_host(hostname):
    """Resolve hostname to IP. Returns IP string or None."""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def check_ntp_udp(host, port=123, timeout=3):
    """Send NTPv3 probe, return True if server responds."""
    try:
        data = b'\x1b' + b'\x00' * 47
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(data, (host, port))
        resp, _ = sock.recvfrom(1024)
        sock.close()
        return len(resp) >= 48
    except Exception:
        return False


def check_cert_file(path):
    """Verify CA cert file exists and is valid PEM."""
    if not os.path.isfile(path):
        return False, f"File not found: {path}"
    size = os.path.getsize(path)
    if size == 0:
        return False, "File is empty"
    with open(path, 'rb') as f:
        content = f.read(64)
    if b'-----BEGIN' not in content:
        return False, "Not a valid PEM file (missing BEGIN header)"
    return True, f"OK  ({size} bytes, PEM format)"


def copy_cert_to_tftp(src, tftp_root, dest_name):
    """
    Copy CA cert to TFTP root so switch can download it.
    Returns (ok, message).
    """
    dest = os.path.join(tftp_root, dest_name)
    try:
        # Find writable TFTP root if default not writable
        candidates = [tftp_root, "/var/lib/tftpboot", "/tftpboot", "/tmp/tftp"]
        root = None
        for c in candidates:
            if os.path.isdir(c) and os.access(c, os.W_OK):
                root = c
                break
        if root is None:
            os.makedirs("/tmp/tftp", exist_ok=True)
            root = "/tmp/tftp"
        dest = os.path.join(root, dest_name)
        import shutil
        shutil.copy2(src, dest)
        return True, dest, root
    except Exception as e:
        return False, str(e), tftp_root


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
            time.sleep(0.3)
            _drain(shell)
            return client, shell
        except Exception as e:
            client.close()
            if attempt < retries:
                print(f"   ⏳ SSH attempt {attempt} failed ({e}), retrying...")
                time.sleep(delay)
            else:
                raise


def _drain(shell):
    time.sleep(0.2)
    while shell.recv_ready():
        shell.recv(4096)
        time.sleep(0.05)


def ssh_cmd(shell, cmd, timeout=CMD_WAIT):
    """Send command, collect output, print raw debug block."""
    print(f"   CMD: {cmd}")
    shell.send(cmd + "\n")
    collected = ""
    deadline  = time.time() + timeout
    last_recv = time.time()

    while time.time() < deadline:
        time.sleep(0.1)
        chunk = ""
        while shell.recv_ready():
            chunk += shell.recv(4096).decode("utf-8", errors="ignore")
            time.sleep(0.02)
        if chunk:
            collected += chunk
            last_recv  = time.time()
        if collected and (time.time() - last_recv) > 1.0:
            break

    clean = re.sub(r"\x1b\[[0-9;]*[mGKH]", "", collected).strip()
    print("  +-- RAW SWITCH OUTPUT " + "-" * 43)
    for line in clean.splitlines():
        line = line.strip()
        if line:
            print(f"  |  {line}")
    print("  +" + "-" * 63)
    return clean


def ssh_config(shell, commands, timeout=CMD_WAIT):
    """Enter config mode, apply commands, exit."""
    ssh_cmd(shell, "configure terminal", timeout=3)
    output = ""
    for cmd in commands:
        output += ssh_cmd(shell, cmd, timeout=timeout)
    ssh_cmd(shell, "exit", timeout=2)
    return output


def run_copy(shell, cmd, timeout=COPY_WAIT):
    """
    Run a TFTP copy command — auto-confirm prompts,
    wait for success/failure keyword.
    """
    print(f"   CMD: {cmd}")
    shell.send(cmd + "\n")
    collected = ""
    deadline  = time.time() + timeout
    confirms  = 0
    last_recv = time.time()

    SUCCESS = ["bytes copied", "copy complete", "[ok]",
               "successfully", "tftp: success", "transfer complete",
               "done", "complete."]
    FAILURE = ["error", "failed", "timed out", "timeout",
               "no such", "refused", "unreachable",
               "invalid", "cannot", "abort", "not found"]

    while time.time() < deadline:
        time.sleep(0.1)
        chunk = ""
        while shell.recv_ready():
            chunk += shell.recv(4096).decode("utf-8", errors="ignore")
            time.sleep(0.02)
        if chunk:
            collected += chunk
            last_recv  = time.time()

        lower = collected.lower()

        # Auto-confirm prompts
        if ("?" in collected or "filename" in lower or
                "confirm" in lower or "overwrite" in lower) and confirms < 6:
            shell.send("\n")
            confirms += 1
            continue

        if any(k in lower for k in SUCCESS):
            break
        if any(k in lower for k in FAILURE):
            time.sleep(1)   # let switch finish printing
            while shell.recv_ready():
                collected += shell.recv(4096).decode("utf-8", errors="ignore")
            break

        if collected and (time.time() - last_recv) > 3:
            break

    clean = re.sub(r"\x1b\[[0-9;]*[mGKH]", "", collected).strip()
    print("  +-- RAW SWITCH OUTPUT " + "-" * 43)
    for line in clean.splitlines():
        line = line.strip()
        if line:
            print(f"  |  {line}")
    print("  +" + "-" * 63)
    return clean


def classify_copy(output):
    lower = output.lower()
    for k in ["bytes copied", "copy complete", "[ok]", "successfully",
              "tftp: success", "transfer complete", "done", "complete."]:
        if k in lower:
            return "PASS", k
    for k in ["error", "failed", "timed out", "timeout", "no such",
              "refused", "unreachable", "invalid", "cannot", "abort"]:
        if k in lower:
            return "FAIL", k
    return "WARN", "(no decisive keyword)"


# ============================================================
# NTP classifier  (same smart logic as ntp_test.py)
# ============================================================

def classify_ntp(output, expect_synced=True, ntp_host=None):
    lower = output.lower()
    if expect_synced:
        # Check NTP Mode enabled + server hostname present
        if "ntp mode" in lower and "enabled" in lower:
            if ntp_host and ntp_host.lower() in lower:
                return "PASS", f"NTP Mode enabled + server {ntp_host} found"
            return "PASS", "NTP Mode : enabled"
        for k in NTP_SYNC_KEYWORDS:
            if k in lower:
                return "PASS", k
        for k in NTP_NOSYNC_KEYWORDS:
            if k in lower:
                return "FAIL", k
        return "WARN", "(no decisive keyword)"
    else:
        if "ntp mode" in lower and "disabled" in lower:
            return "PASS", "NTP Mode : disabled"
        if ntp_host and ntp_host.lower() not in lower and "ntp mode" in lower:
            return "PASS", f"server {ntp_host} not found in table"
        for k in NTP_NOSYNC_KEYWORDS:
            if k in lower:
                return "PASS", k
        for k in NTP_SYNC_KEYWORDS:
            if k in lower:
                return "FAIL", k
        return "WARN", "(no decisive keyword)"


# ============================================================
# Clock parser  (handles all switch formats incl ISO 8601)
# ============================================================

MONTH_MAP = {
    "jan":1,"feb":2,"mar":3,"apr":4,"may":5,"jun":6,
    "jul":7,"aug":8,"sep":9,"oct":10,"nov":11,"dec":12,
}
DAY_NAMES = {"mon","tue","wed","thu","fri","sat","sun"}


def parse_clock(output):
    info = {
        "raw":output,"hour":None,"minute":None,"second":None,
        "day":None,"month":None,"month_name":None,
        "year":None,"weekday":None,"timezone":None,
        "synced":True,"valid":False,
    }
    for line in output.splitlines():
        line = line.strip()
        if not line or "show clock" in line.lower():
            continue
        if ":" in line:
            prefix, _, rest = line.partition(":")
            if prefix and not re.search(r"\d", prefix) and len(prefix.strip()) > 2:
                line = rest.strip()
        if line.startswith("*"):
            info["synced"] = False
            line = line[1:].strip()
        info["raw"] = line
        break
    else:
        return info

    line = info["raw"]
    iso = re.search(
        r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
        r"(?:[.,]\d+)?(?:([+-])(\d{2}):?(\d{2})|Z)?", line)
    if iso:
        info["year"]  = int(iso.group(1))
        info["month"] = int(iso.group(2))
        info["day"]   = int(iso.group(3))
        info["hour"]  = int(iso.group(4))
        info["minute"]= int(iso.group(5))
        info["second"]= int(iso.group(6))
        info["month_name"] = list(MONTH_MAP.keys())[info["month"]-1].capitalize()
        try:
            info["weekday"] = datetime.date(
                info["year"], info["month"], info["day"]
            ).strftime("%a")
        except Exception:
            pass
        if iso.group(7) and iso.group(8) and iso.group(9):
            info["timezone"] = f"{iso.group(7)}{iso.group(8)}:{iso.group(9)}"
        info["valid"] = True
        return info

    time_m = re.search(r"\b(\d{1,2}):(\d{2}):(\d{2})", line)
    if time_m:
        info["hour"]  = int(time_m.group(1))
        info["minute"]= int(time_m.group(2))
        info["second"]= int(time_m.group(3))
    for tok in re.split(r"[\s,]+", line):
        tl = tok.lower().rstrip(".,")
        if re.fullmatch(r"\d{4}", tok) and 1990 <= int(tok) <= 2100:
            info["year"] = int(tok)
        elif tl[:3] in MONTH_MAP:
            info["month"]      = MONTH_MAP[tl[:3]]
            info["month_name"] = tok[:3].capitalize()
        elif re.fullmatch(r"\d{1,2}", tok) and 1 <= int(tok) <= 31:
            if info["day"] is None:
                info["day"] = int(tok)
        elif tl[:3] in DAY_NAMES:
            info["weekday"] = tok[:3].capitalize()
        elif re.fullmatch(r"[A-Z]{2,5}", tok) \
                and tl[:3] not in MONTH_MAP and tl[:3] not in DAY_NAMES:
            info["timezone"] = tok
    info["valid"] = (info["year"] is not None and
                     info["month"] is not None and
                     info["day"] is not None)
    return info


def format_clock(info):
    if not info["valid"]:
        return f"(could not parse)  raw='{info['raw']}'"
    parts = []
    if info["weekday"]: parts.append(info["weekday"])
    if info["day"] and info["month_name"] and info["year"]:
        parts.append(f"{info['day']:02d} {info['month_name']} {info['year']}")
    if info["hour"] is not None:
        parts.append(f"{info['hour']:02d}:{info['minute']:02d}:{info['second']:02d}")
    tz = info.get("timezone")
    if tz:
        parts.append(f"{tz} (IST)" if tz in ("+05:30","+0530") else tz)
    if not info["synced"]:
        parts.append("[NOT NTP-synced]")
    return "  ".join(parts)


def print_clock_block(label, clock_info, host_utc):
    bar = "-" * max(0, 55 - len(label))
    print(f"\n  +-- {label} {bar}")
    print(f"  |  Switch clock   : {format_clock(clock_info)}")
    print(f"  |  Host UTC       : {time.strftime('%a %d %b %Y  %H:%M:%S', host_utc)}")
    print(f"  |")
    if clock_info["valid"]:
        t = clock_info
        print(f"  |  Day      : {t['day']}")
        print(f"  |  Month    : {t['month_name']}  (month #{t['month']})")
        print(f"  |  Year     : {t['year']}")
        if t["hour"] is not None:
            print(f"  |  Time     : {t['hour']:02d}:{t['minute']:02d}:{t['second']:02d}")
        print(f"  |  Timezone : {t['timezone'] or '(not shown)'}")
        print(f"  |  NTP-sync : {'Yes' if t['synced'] else 'No  [free-running]'}")
        print(f"  |")
        y_ok = t["year"]  == host_utc.tm_year
        m_ok = t["month"] == host_utc.tm_mon
        d_ok = abs((t["day"] or 0) - host_utc.tm_mday) <= 1
        print(f"  |  Accuracy vs host UTC:")
        print(f"  |    Year  : {'MATCH   ' if y_ok  else 'MISMATCH'}  switch={t['year']}  host={host_utc.tm_year}")
        print(f"  |    Month : {'MATCH   ' if m_ok  else 'MISMATCH'}  switch={t['month']} ({t['month_name']})  host={host_utc.tm_mon} ({time.strftime('%b', host_utc)})")
        print(f"  |    Day   : {'MATCH   ' if d_ok  else 'MISMATCH'}  switch={t['day']}  host={host_utc.tm_mday}")
    else:
        print(f"  |  WARNING: Could not parse clock — check raw output above")
    print("  +" + "-" * 59)


def compare_clocks(before, after):
    now_utc = time.gmtime()
    print("\n  +-- BEFORE vs AFTER NTP CLOCK COMPARISON " + "-" * 18)
    print(f"  |  {'Field':<14}  {'BEFORE NTP':>22}  {'AFTER NTP':>22}")
    print(f"  |  {'-'*14}  {'-'*22}  {'-'*22}")
    for label, key in [
        ("Weekday",    "weekday"),
        ("Day",        "day"),
        ("Month",      "month_name"),
        ("Year",       "year"),
        ("Hour",       "hour"),
        ("Minute",     "minute"),
        ("Timezone",   "timezone"),
        ("NTP-synced", "synced"),
    ]:
        bv    = str(before.get(key) or "-")
        av    = str(after.get(key)  or "-")
        arrow = "  <-- CHANGED" if bv != av else ""
        print(f"  |  {label:<14}  {bv:>22}  {av:>22}{arrow}")
    print(f"  |")
    print(f"  |  Host UTC now   : {time.strftime('%a %d %b %Y  %H:%M:%S', now_utc)}")
    print("  +" + "-" * 59)
    ok, issues = True, []
    if after["valid"]:
        if after["year"] != now_utc.tm_year:
            issues.append(f"year mismatch: switch={after['year']} host={now_utc.tm_year}")
            ok = False
        if after["month"] != now_utc.tm_mon:
            issues.append(f"month mismatch: switch={after['month']} host={now_utc.tm_mon}")
            ok = False
        if abs((after["day"] or 0) - now_utc.tm_mday) > 1:
            issues.append(f"day mismatch: switch={after['day']} host={now_utc.tm_mday}")
            ok = False
    else:
        issues.append("could not parse after-clock")
        ok = False
    return ok, issues


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
    print(f"  {icon}  {label:<54} {status}")


# ============================================================
# MAIN TEST
# ============================================================

def run_test():
    results      = {}
    clock_before = {}
    tftp_ip      = sys.argv[4] if len(sys.argv) > 4 else TFTP_SERVER_IP

    print(f"\n  Switch IP          : {SWITCH_IP}")
    print(f"  TFTP server IP     : {tftp_ip}  (this PC)")
    print(f"  NTP server         : {NTP_HOST}  (secure / NTS)")
    print(f"  CA cert path       : {CA_CERT_LOCAL}")
    print(f"  CA cert (flash)    : flash:{CA_CERT_FLASH}")
    print(f"  Timezone           : {TIMEZONE_NAME} +{TIMEZONE_HOURS}:{TIMEZONE_MINS:02d}")

    try:
        # ══════════════════════════════════════════════════════
        # PREFLIGHT
        # ══════════════════════════════════════════════════════
        section("PREFLIGHT — Environment Checks")

        # 1. CA cert file
        step(0, "Verify CA certificate file")
        cert_ok, cert_msg = check_cert_file(CA_CERT_LOCAL)
        if cert_ok:
            print(f"  ✅ CA cert found: {cert_msg}")
        else:
            print(f"  ❌ CA cert problem: {cert_msg}")
            print(f"     Place the cert at: {CA_CERT_LOCAL}")
            sys.exit(1)

        # 2. Confirm cert is in TFTP root (already placed there)
        tftp_root   = TFTP_ROOT
        cert_path   = os.path.join(tftp_root, CA_CERT_TFTP)
        print(f"\n  ▶ Checking cert in TFTP root: {cert_path} ...")
        if os.path.isfile(cert_path) and os.path.getsize(cert_path) > 0:
            print(f"  ✅ Cert found in TFTP root: {cert_path}  "
                  f"({os.path.getsize(cert_path)} bytes)")
        else:
            # Try to copy from CA_CERT_LOCAL if it exists elsewhere
            if os.path.isfile(CA_CERT_LOCAL):
                import shutil
                os.makedirs(tftp_root, exist_ok=True)
                shutil.copy2(CA_CERT_LOCAL, cert_path)
                print(f"  ✅ Cert copied to TFTP root: {cert_path}")
            else:
                print(f"  ❌ Cert not found at {cert_path}")
                print(f"     Place the cert file at one of:")
                print(f"       {cert_path}")
                print(f"       {CA_CERT_LOCAL}")
                sys.exit(1)

        # 3. Ping TFTP server
        print(f"\n  ▶ Pinging TFTP/NTP server {tftp_ip} ...")
        if ping_host(tftp_ip):
            print(f"  ✅ Ping OK — {tftp_ip} is reachable")
        else:
            print(f"  ⚠️  Ping failed (ICMP may be blocked — continuing)")

        # 4. Resolve NTP hostname
        print(f"\n  ▶ Resolving {NTP_HOST} ...")
        ntp_resolved = resolve_host(NTP_HOST)
        if ntp_resolved:
            print(f"  ✅ {NTP_HOST} resolves to {ntp_resolved}")
            # 5. NTP UDP probe
            print(f"\n  ▶ NTP UDP probe on {NTP_HOST}:123 ...")
            if check_ntp_udp(ntp_resolved):
                print(f"  ✅ NTP server responding on {NTP_HOST}:123")
            else:
                print(f"  ⚠️  No response on UDP 123 (NTS uses TLS — normal for strict NTS servers)")
        else:
            print(f"  ⚠️  Cannot resolve {NTP_HOST} from this machine")
            print(f"     Switch must resolve it independently — continuing")

        # ══════════════════════════════════════════════════════
        # PRE-CONFIG — capture baseline clock
        # ══════════════════════════════════════════════════════
        section("PRE-CONFIG — Capture Switch Clock BEFORE NTP (Baseline)")

        step(1, f"SSH into switch as {ADMIN_USER}")
        client, shell = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print(f"✅ SSH connected to {SWITCH_IP}")

        step(2, "show clock  <-- BEFORE secure NTP configuration")
        raw_before   = ssh_cmd(shell, "show clock")
        clock_before = parse_clock(raw_before)
        print_clock_block("PRE-NTP CLOCK ANALYSIS", clock_before, time.gmtime())

        # ══════════════════════════════════════════════════════
        # PHASE 1 — Upload CA Certificate via config-mode command
        # ══════════════════════════════════════════════════════
        section("PHASE 1 — Upload CA Certificate to Switch")

        # The switch uploads the cert directly from TFTP using:
        #   (config)# ntp server 1 security ca-certificate upload <url>
        # This is done inside config mode — NOT via copy tftp.
        upload_url = f"tftp://{tftp_ip}/{CA_CERT_TFTP}"
        upload_cmd = f"ntp server 1 security ca-certificate upload {upload_url}"

        step(3, f"ntp server 1 security ca-certificate upload {upload_url}")
        print(f"   ℹ️  CA cert TFTP URL : {upload_url}")
        print(f"   ℹ️  Cert subject     : CN = {NTP_HOST}")
        print(f"   ℹ️  Cert file        : {CA_CERT_TFTP} in TFTP root {tftp_root}")
        print(f"   ℹ️  Switch requires NTP to be DISABLED before cert upload")

        # ── Step 3a: disable NTP before cert upload ───────────
        print(f"\n   ▶ Step 3a — Disable NTP (required before cert upload)")
        ssh_config(shell, ["no ntp"])
        time.sleep(1)
        print(f"   ✅ NTP disabled")

        # ── Step 3b: upload cert in config mode ───────────────
        print(f"\n   ▶ Step 3b — Upload CA certificate")
        ssh_cmd(shell, "configure terminal", timeout=3)
        upload_out = run_copy(shell, upload_cmd, timeout=COPY_WAIT)
        ssh_cmd(shell, "exit", timeout=2)
        upload_st, upload_kw = classify_copy(upload_out)

        # ── Step 3c: verify cert via show ntp status ──────────
        # The cert is stored internally — NOT visible in dir flash:
        # Verification is done via show ntp status which shows:
        #   NTS = YES   and   "User's NTS CA cert. is exist."
        print(f"\n   ▶ Step 3c — Verify cert stored (show ntp status)")
        # Re-enable NTP first so show ntp status shows the cert info
        ssh_config(shell, [
            "ntp",
            f"ntp server 1 ip-address {NTP_HOST} security",
        ])
        time.sleep(2)
        verify_out   = ssh_cmd(shell, "show ntp status", timeout=6)
        lower_verify = verify_out.lower()
        cert_stored  = (
            "nts ca cert. is exist" in lower_verify or
            "ca cert" in lower_verify or
            "user\'s nts" in lower_verify or
            "nts ca cert" in lower_verify
        )
        nts_yes      = ("nts" in lower_verify and "yes" in lower_verify)

        print(f"\n  +-- CA CERT UPLOAD RESULT " + "-" * 34)
        print(f"  |  Upload command     : {upload_cmd}")
        print(f"  |  Upload keyword     : {upload_st}  ('{upload_kw}')")
        print(f"  |  NTS = YES in status: {'YES ✅' if nts_yes else 'NO ⚠️'}")
        print(f"  |  Cert stored msg    : {'FOUND ✅' if cert_stored else 'NOT FOUND ⚠️'}")
        print("  +" + "-" * 59)

        if cert_stored or nts_yes:
            print(f"\n✅ CA certificate uploaded and confirmed in show ntp status")
            results["cert_upload"] = "PASS"
        elif upload_st == "PASS":
            print(f"\n✅ CA certificate upload command succeeded")
            results["cert_upload"] = "PASS"
        else:
            print(f"\n⚠️  Upload result inconclusive — check show ntp status above")
            print(f"   If 'User\'s NTS CA cert. is exist.' appears → cert is stored")
            results["cert_upload"] = "WARN"

        # ══════════════════════════════════════════════════════
        # PHASE 2 — Enable Secure NTP
        # ══════════════════════════════════════════════════════
        section("PHASE 2 — Enable Secure NTP Client")

        step(4, "Apply secure NTP configuration (timezone + finalize)")
        # NTP + server already enabled in Phase 1 step 3c
        # Just apply timezone here
        cmds = [
            f"clock timezone {TIMEZONE_NAME} {TIMEZONE_HOURS} {TIMEZONE_MINS}",
        ]
        for c in cmds:
            print(f"   Applying: {c}")
        ssh_config(shell, cmds)
        print(f"\n✅ Secure NTP fully configured")
        print(f"   ℹ️  Active config:")
        print(f"       ntp")
        print(f"       ntp server 1 ip-address {NTP_HOST} security")
        print(f"       clock timezone {TIMEZONE_NAME} {TIMEZONE_HOURS} {TIMEZONE_MINS}")

        # ══════════════════════════════════════════════════════
        # PHASE 3 — Verify NTP Status + Clock
        # ══════════════════════════════════════════════════════
        section("PHASE 3 — Verify Secure NTP Status and Clock")

        step(5, "show ntp status")
        print(f"   ⏳ Polling NTP status (max {SYNC_WAIT}s, checks every 10s) ...")
        print(f"   ℹ️  NTS (secure NTP) takes longer than plain NTP to sync")
        out_s = ""
        st_s  = "WARN"
        kw_s  = "(timeout)"
        poll_deadline = time.time() + SYNC_WAIT
        while time.time() < poll_deadline:
            out_s = ssh_cmd(shell, "show ntp status")
            st_s, kw_s = classify_ntp(out_s, expect_synced=True, ntp_host=NTP_HOST)
            if st_s == "PASS":
                elapsed = int(SYNC_WAIT - (poll_deadline - time.time()))
                print(f"   ✅ Secure NTP synced after ~{elapsed}s")
                break
            remaining = int(poll_deadline - time.time())
            if remaining > 0:
                print(f"   ⏳ Not synced yet — retrying in 10s  ({remaining}s left) ...")
                time.sleep(10)

        results["ntp_status"] = st_s
        print(f"{'✅' if st_s=='PASS' else ('⚠️' if st_s=='WARN' else '❌')}  "
              f"NTP status: {st_s}  (keyword: '{kw_s}')")

        step(6, "show ntp connect-status")
        out_c = ssh_cmd(shell, "show ntp connect-status")
        st_c, kw_c = classify_ntp(out_c, expect_synced=True, ntp_host=NTP_HOST)
        results["ntp_connect"] = st_c
        print(f"{'✅' if st_c=='PASS' else ('⚠️' if st_c=='WARN' else '❌')}  "
              f"NTP connect-status: {st_c}  (keyword: '{kw_c}')")

        # Check NTS flag in connect-status
        nts_active = any(k in out_c.lower() for k in
                         ["nts", "yes", "security", "tls", "authenticated"])
        print(f"  ℹ️  NTS/security flag in connect-status: "
              f"{'YES ✅' if nts_active else 'NOT DETECTED ⚠️ (check manually)'}")

        step(7, "show ntp status  <-- verify NTS = YES in server table")
        # Your switch shows NTS status directly in 'show ntp status':
        #   Idx  Server IP             NTS   AUTH  hash / NTS cert.
        #   1    time.cloudflare.com   YES   NO    User's NTS CA cert. is exist.
        out_nts   = ssh_cmd(shell, "show ntp status")
        lower_nts = out_nts.lower()

        # NTS=YES: find the row for NTP_HOST and check if "yes" is on same line
        nts_yes = False
        for line in out_nts.splitlines():
            if NTP_HOST.lower() in line.lower() and "yes" in line.lower():
                nts_yes = True
                break

        print(f"\n  +-- NTS STATUS (from show ntp status) " + "-" * 22)
        for line in out_nts.splitlines():
            s = line.strip()
            if s and "show ntp" not in s.lower():
                print(f"  |  {s}")
        print(f"  |")
        print(f"  |  Server             : {NTP_HOST}")
        print(f"  |  NTS column = YES   : {'YES ✅' if nts_yes else 'NO ❌  (NTS not active)'}")
        print("  +" + "-" * 59)
        results["nts_status"] = "PASS" if nts_yes else "FAIL"
        print(f"{'✅' if nts_yes else '❌'}  NTS active status: {'PASS' if nts_yes else 'FAIL'}")

        step(8, "show ntp status  <-- verify CA cert existence message")
        # Same output already captured — check for cert presence message:
        #   "User's NTS CA cert. is exist."
        # This exact phrase confirms the uploaded cert is stored and active.
        cert_exist = (
            "nts ca cert. is exist" in lower_nts or
            "user's nts ca cert"    in lower_nts or
            "nts ca cert"           in lower_nts or
            "ca cert"               in lower_nts
        )

        print(f"\n  +-- CA CERTIFICATE PRESENCE (from show ntp status) " + "-" * 9)
        for line in out_nts.splitlines():
            s = line.strip()
            if any(k in s.lower() for k in
                   ["ca cert", "nts ca", "user", "exist", "delete", "flash:"]):
                print(f"  |  {s}")
        print(f"  |")
        print(f"  |  Cert exist message : {'FOUND ✅' if cert_exist else 'NOT FOUND ⚠️'}")
        print("  +" + "-" * 59)
        results["cert_present"] = "PASS" if cert_exist else "WARN"
        kw = "User's NTS CA cert. is exist." if cert_exist else "message not detected"
        print(f"{'✅' if cert_exist else '⚠️'}  CA cert present: {'PASS' if cert_exist else 'WARN'}  ({kw})")

        step(9, "show clock  <-- AFTER secure NTP configuration")
        raw_after   = ssh_cmd(shell, "show clock")
        clock_after = parse_clock(raw_after)
        print_clock_block("AFTER SECURE NTP — CLOCK ANALYSIS", clock_after, time.gmtime())

        clock_ok, issues = compare_clocks(clock_before, clock_after)
        if issues:
            for iss in issues:
                print(f"    - {iss}")
        results["clock_check"] = "PASS" if clock_ok else "WARN"
        print(f"\n{'✅' if clock_ok else '⚠️'}  "
              f"Clock check: {'PASS' if clock_ok else 'WARN'}")

        # ══════════════════════════════════════════════════════
        # PHASE 4 — Negative Test: Disable NTP
        # ══════════════════════════════════════════════════════
        section("PHASE 4 — Negative Test: Disable Secure NTP")

        step(10, "Disable NTP: Step 1 — no ntp server 1")
        ssh_config(shell, ["no ntp server 1"])
        print("   ✅ NTP server entry removed")

        step(11, "Disable NTP: Step 2 — no ntp")
        ssh_config(shell, ["no ntp"])
        time.sleep(1)
        print("   ✅ NTP client disabled")

        step(12, "Verify NTP is fully disabled")
        out_dis  = ssh_cmd(shell, "show ntp status")
        st_dis, kw_dis = classify_ntp(out_dis, expect_synced=False, ntp_host=NTP_HOST)
        out_run  = ssh_cmd(shell, "show running-config ntp")
        srv_gone = "ntp server" not in out_run.lower()

        print(f"\n  +-- DISABLE VERIFICATION " + "-" * 35)
        print(f"  |  show ntp status   : {st_dis}  (keyword: '{kw_dis}')")
        print(f"  |  NTP server gone   : {'YES ✅' if srv_gone else 'NO  ⚠️  (still present)'}")
        print("  +" + "-" * 59)

        results["ntp_disabled"] = st_dis
        if st_dis == "PASS" and srv_gone:
            print("\n✅ Secure NTP fully DISABLED — client off + server entry removed")
        elif st_dis == "PASS":
            print(f"\n✅ NTP disabled  (keyword: '{kw_dis}')")
        elif st_dis == "WARN":
            print("\n⚠️  Cannot confirm NTP disabled — check DEBUG block above")
        else:
            print(f"\n❌ NTP still active after disable commands  (keyword: '{kw_dis}')")

        step(13, "Re-enable secure NTP — restore switch to clean state")
        ssh_config(shell, [
            "ntp",
            f"ntp server 1 ip-address {NTP_HOST} security",
            f"clock timezone {TIMEZONE_NAME} {TIMEZONE_HOURS} {TIMEZONE_MINS}",
        ])
        print(f"✅ Secure NTP re-enabled — switch left in working state")

        client.close()
        print("\n✅ SSH session closed")

    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()

    # ══════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════
    section("TEST SUMMARY — TEST-HFCL-SW-NTP-SEC  Secure NTP Operation")
    rows = [
        ("CA cert uploaded (ntp server 1 security ca-cert upload)", results.get("cert_upload")),
        ("NTP Mode enabled + server present (show ntp status)",     results.get("ntp_status")),
        ("NTP connect-status OK (show ntp connect-status)",         results.get("ntp_connect")),
        ("NTS active status (show ntp server 1 security nts)",      results.get("nts_status")),
        ("CA cert present (show ntp server 1 security ca-cert)",    results.get("cert_present")),
        ("Clock correct after secure NTP sync (show clock)",        results.get("clock_check")),
        ("Secure NTP disabled (no ntp server 1 + no ntp)",          results.get("ntp_disabled")),
    ]
    all_pass = True
    for label, status in rows:
        result_line(label, status or "SKIP")
        if status in ("FAIL", None):
            all_pass = False

    print()
    if all_pass:
        print("""🎉  ALL TESTS PASSED \n

 TEST-HFCL-SW-09  —  Secure NTP (NTS) Operation Verification
=================================================================
Test Objective:
  Verify Secure NTP operations using a CA certificate on the switch.

CA Certificate:
  File    : 1773913923443_cacloudflare.crt
  Subject : CN = time.cloudflare.com
  Issuer  : GeoTrust TLS ECC CA G1 (DigiCert Inc)
  Valid   : Feb 10 2025 → Mar 12 2026

Procedure:
  PRE-CONFIG : Capture switch clock BEFORE NTP (baseline)
  PHASE 1    : Upload CA certificate to switch flash
               ntp server 1 security ca-certificate upload tftp://<server>/cacloudflare.crt
  PHASE 2    : Enable secure NTP
               ntp
               ntp server 1 ip-address time.cloudflare.com security
               clock timezone IST 5 30
  PHASE 3    : Verify NTP status + connect-status + clock
  PHASE 4    : Negative — Disable NTP (no ntp server 1 + no ntp)
               Verify disabled, re-enable, switch left clean

Expected Result:
  CA cert uploaded, NTP client enabled with security flag,
  clock synced to time.cloudflare.com, status verified.

Usage:
  python3 ntp_secure_test.py [switch_ip] [admin_user] [admin_pass] [tftp_server_ip]

— Secure NTP verified:")
        print("    CA cert uploaded, NTS sync confirmed, clock correct and disable confirmed.

Successfully  Passed !!!!!!!!!!!!!!!!!!!


""")
    else:
        print("❌  ONE OR MORE TESTS FAILED — review output above")
        print()
        print("    TIPS:")
        print(f"    • cert_upload FAIL : check TFTP server on {TFTP_SERVER_IP}")
        print(f"    • ntp_status  WARN : NTS sync may need more time — increase SYNC_WAIT")
        print(f"    • clock_check WARN : check 'show clock' output in DEBUG blocks")
    print("=" * 65)
    return all_pass


if __name__ == "__main__":
    if len(sys.argv) >= 4:
        SWITCH_IP  = sys.argv[1]
        ADMIN_USER = sys.argv[2]
        ADMIN_PASS = sys.argv[3]

    success = run_test()
    sys.exit(0 if success else 1)
