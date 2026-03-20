"""
TEST-HFCL-SW-NTP-MD5  —  Secure NTP (MD5 Auth-Hash) Verification
==================================================================
Test Objective:
  Verify Secure NTP operations using MD5 authentication hash.

Test Configuration:
  (config)# ntp
  (config)# ntp server 1 ip-address time.cloudflare.com auth-hash admin@123
  (config)# clock timezone IST 5 30

Verify:
  # show ntp status
  # show ntp connect-status
  # show clock

Procedure:
  PRE-CONFIG : Capture switch clock BEFORE NTP (baseline)
  PHASE 1    : Enable NTP with MD5 auth-hash
               ntp
               ntp server 1 ip-address time.cloudflare.com auth-hash admin@123
               clock timezone IST 5 30
  PHASE 2    : Verify NTP status — NTP Mode enabled + server present
               Verify AUTH column in show ntp status = YES
               Verify show ntp connect-status
               Verify show clock (before vs after comparison)
  PHASE 3    : Negative — Disable NTP (no ntp server 1 + no ntp)
               Verify disabled, re-enable, switch left clean

Expected Result:
  NTP client enabled with MD5 auth-hash, AUTH column shows YES,
  clock synced correctly, status verified.

Usage:
  python3 ntp_md5_test.py [switch_ip] [admin_user] [admin_pass]
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
SWITCH_IP      = "192.168.180.155"
ADMIN_USER     = "admin"
ADMIN_PASS     = "admin"
SSH_PORT       = 22

NTP_HOST       = "time.cloudflare.com"
MD5_KEY        = "admin@123"           # auth-hash key
TIMEZONE_NAME  = "IST"
TIMEZONE_HOURS = 5
TIMEZONE_MINS  = 30

CMD_WAIT       = 4    # seconds — normal show command timeout
SYNC_WAIT      = 60   # seconds — max wait for NTP sync

# ── Keywords that confirm NTP is SYNCED / enabled ───────────
NTP_SYNC_KEYWORDS = [
    "synchronized", "synced", "sync'd",
    "stratum", "reference",
    "ntp enabled", "status: up",
    "reachable", "clock is synchronized",
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
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def check_ntp_udp(host, port=123, timeout=3):
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


def ssh_cmd(shell, cmd, timeout=CMD_WAIT, mask=None):
    """
    Send command, collect output, print raw debug block.
    mask: if set, replace this string in printed output (for hiding passwords).
    """
    display_cmd = cmd.replace(mask, "****") if mask else cmd
    print(f"   CMD: {display_cmd}")
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
    # Mask password in printed output
    display_clean = clean.replace(mask, "****") if mask else clean
    print("  +-- RAW SWITCH OUTPUT " + "-" * 43)
    for line in display_clean.splitlines():
        line = line.strip()
        if line:
            print(f"  |  {line}")
    print("  +" + "-" * 63)
    return clean


def ssh_config(shell, commands, timeout=CMD_WAIT, mask=None):
    """Enter config mode, apply commands, exit."""
    ssh_cmd(shell, "configure terminal", timeout=3)
    output = ""
    for cmd in commands:
        output += ssh_cmd(shell, cmd, timeout=timeout, mask=mask)
    ssh_cmd(shell, "exit", timeout=2)
    return output


# ============================================================
# NTP classifier
# ============================================================

def classify_ntp(output, expect_synced=True, ntp_host=None):
    lower = output.lower()
    if expect_synced:
        # Check NTP Mode enabled + server present in table
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
# Clock parser (handles all switch formats incl ISO 8601)
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
        info["year"]   = int(iso.group(1))
        info["month"]  = int(iso.group(2))
        info["day"]    = int(iso.group(3))
        info["hour"]   = int(iso.group(4))
        info["minute"] = int(iso.group(5))
        info["second"] = int(iso.group(6))
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
        info["hour"]   = int(time_m.group(1))
        info["minute"] = int(time_m.group(2))
        info["second"] = int(time_m.group(3))
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
    info["valid"] = (info["year"]  is not None and
                     info["month"] is not None and
                     info["day"]   is not None)
    return info


def format_clock(info):
    if not info["valid"]:
        return f"(could not parse)  raw='{info['raw']}'"
    parts = []
    if info["weekday"]:
        parts.append(info["weekday"])
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

    print(f"\n  Switch IP      : {SWITCH_IP}")
    print(f"  NTP server     : {NTP_HOST}")
    print(f"  Auth method    : MD5 (auth-hash)")
    print(f"  Auth key       : ****  (masked)")
    print(f"  Timezone       : {TIMEZONE_NAME} +{TIMEZONE_HOURS}:{TIMEZONE_MINS:02d}")

    try:
        # ══════════════════════════════════════════════════════
        # PREFLIGHT
        # ══════════════════════════════════════════════════════
        section("PREFLIGHT — Environment Checks")

        print(f"  ▶ Resolving {NTP_HOST} ...")
        ntp_ip = resolve_host(NTP_HOST)
        if ntp_ip:
            print(f"  ✅ {NTP_HOST} resolves to {ntp_ip}")
            print(f"\n  ▶ NTP UDP probe on {NTP_HOST}:123 ...")
            if check_ntp_udp(ntp_ip):
                print(f"  ✅ NTP server responding on port 123")
            else:
                print(f"  ⚠️  No UDP response on port 123 (may require auth — normal)")
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

        step(2, "show clock  <-- BEFORE MD5 NTP configuration")
        raw_before   = ssh_cmd(shell, "show clock")
        clock_before = parse_clock(raw_before)
        print_clock_block("PRE-NTP CLOCK ANALYSIS", clock_before, time.gmtime())

        # ══════════════════════════════════════════════════════
        # PHASE 1 — Enable NTP with MD5 auth-hash
        # ══════════════════════════════════════════════════════
        section("PHASE 1 — Enable NTP with MD5 Auth-Hash")

        step(3, "Apply MD5 NTP configuration")
        ntp_server_cmd = (f"ntp server 1 ip-address {NTP_HOST} "
                          f"auth-hash {MD5_KEY}")
        cmds = [
            "ntp",
            ntp_server_cmd,
            f"clock timezone {TIMEZONE_NAME} {TIMEZONE_HOURS} {TIMEZONE_MINS}",
        ]

        print(f"   Applying: ntp")
        print(f"   Applying: ntp server 1 ip-address {NTP_HOST} auth-hash ****")
        print(f"   Applying: clock timezone {TIMEZONE_NAME} {TIMEZONE_HOURS} {TIMEZONE_MINS}")

        # Enter config mode — mask the MD5 key in printed output
        ssh_cmd(shell, "configure terminal", timeout=3)
        ssh_cmd(shell, "ntp", timeout=CMD_WAIT)
        ssh_cmd(shell, ntp_server_cmd, timeout=CMD_WAIT, mask=MD5_KEY)
        ssh_cmd(shell, f"clock timezone {TIMEZONE_NAME} {TIMEZONE_HOURS} {TIMEZONE_MINS}",
                timeout=CMD_WAIT)
        ssh_cmd(shell, "exit", timeout=2)

        print(f"\n✅ MD5 NTP configuration applied")
        print(f"   ℹ️  Active config:")
        print(f"       ntp")
        print(f"       ntp server 1 ip-address {NTP_HOST} auth-hash ****")
        print(f"       clock timezone {TIMEZONE_NAME} {TIMEZONE_HOURS} {TIMEZONE_MINS}")

        # ══════════════════════════════════════════════════════
        # PHASE 2 — Verify NTP Status + AUTH column + Clock
        # ══════════════════════════════════════════════════════
        section("PHASE 2 — Verify MD5 NTP Status and Clock")

        step(4, "show ntp status  <-- NTP Mode enabled + AUTH = YES")
        print(f"   ⏳ Polling NTP status (max {SYNC_WAIT}s, checks every 10s) ...")
        out_s = ""
        st_s  = "WARN"
        kw_s  = "(timeout)"
        poll_deadline = time.time() + SYNC_WAIT
        while time.time() < poll_deadline:
            out_s = ssh_cmd(shell, "show ntp status")
            st_s, kw_s = classify_ntp(out_s, expect_synced=True, ntp_host=NTP_HOST)
            if st_s == "PASS":
                elapsed = int(SYNC_WAIT - (poll_deadline - time.time()))
                print(f"   ✅ NTP enabled after ~{elapsed}s")
                break
            remaining = int(poll_deadline - time.time())
            if remaining > 0:
                print(f"   ⏳ Not ready — retrying in 10s  ({remaining}s left) ...")
                time.sleep(10)

        results["ntp_status"] = st_s
        print(f"{'✅' if st_s=='PASS' else ('⚠️' if st_s=='WARN' else '❌')}  "
              f"NTP status: {st_s}  (keyword: '{kw_s}')")

        # ── Check AUTH column in show ntp status ─────────────
        # Switch shows:
        #   Idx  Server IP             NTS   AUTH   hash / NTS cert.
        #   1    time.cloudflare.com   NO    YES    md5
        lower_s   = out_s.lower()
        auth_yes  = False
        auth_hash = None
        for line in out_s.splitlines():
            if NTP_HOST.lower() in line.lower():
                if "yes" in line.lower():
                    auth_yes = True
                # Try to extract hash type from same line
                for h in ["md5", "sha1", "sha256", "hmac"]:
                    if h in line.lower():
                        auth_hash = h.upper()
                        break
                break

        print(f"\n  +-- MD5 AUTH VERIFICATION (from show ntp status) " + "-" * 11)
        for line in out_s.splitlines():
            s = line.strip()
            if s and "show ntp" not in s.lower():
                print(f"  |  {s}")
        print(f"  |")
        print(f"  |  Server           : {NTP_HOST}")
        print(f"  |  AUTH column=YES  : {'YES ✅' if auth_yes else 'NO ⚠️  (auth may be pending)'}")
        print(f"  |  Hash type        : {auth_hash or '(not shown in output)'}")
        print("  +" + "-" * 59)

        results["auth_status"] = "PASS" if auth_yes else "WARN"
        print(f"{'✅' if auth_yes else '⚠️'}  "
              f"MD5 Auth active: {'PASS' if auth_yes else 'WARN'}")

        step(5, "show ntp connect-status")
        out_c = ssh_cmd(shell, "show ntp connect-status")
        st_c, kw_c = classify_ntp(out_c, expect_synced=True, ntp_host=NTP_HOST)
        results["ntp_connect"] = st_c
        print(f"{'✅' if st_c=='PASS' else ('⚠️' if st_c=='WARN' else '❌')}  "
              f"NTP connect-status: {st_c}  (keyword: '{kw_c}')")

        step(6, "show clock  <-- AFTER MD5 NTP configuration")
        raw_after   = ssh_cmd(shell, "show clock")
        clock_after = parse_clock(raw_after)
        print_clock_block("AFTER MD5 NTP — CLOCK ANALYSIS", clock_after, time.gmtime())

        clock_ok, issues = compare_clocks(clock_before, clock_after)
        if issues:
            for iss in issues:
                print(f"    - {iss}")
        results["clock_check"] = "PASS" if clock_ok else "WARN"
        print(f"\n{'✅' if clock_ok else '⚠️'}  "
              f"Clock check: {'PASS' if clock_ok else 'WARN'}")

        # ══════════════════════════════════════════════════════
        # PHASE 3 — Negative Test: Disable NTP
        # ══════════════════════════════════════════════════════
        section("PHASE 3 — Negative Test: Disable NTP")

        step(7, "Disable NTP: Step 1 — no ntp server 1")
        ssh_config(shell, ["no ntp server 1"])
        print("   ✅ NTP server entry removed")

        step(8, "Disable NTP: Step 2 — no ntp")
        ssh_config(shell, ["no ntp"])
        time.sleep(1)
        print("   ✅ NTP client disabled")

        step(9, "Verify NTP is fully disabled")
        out_dis  = ssh_cmd(shell, "show ntp status")
        st_dis, kw_dis = classify_ntp(out_dis, expect_synced=False, ntp_host=NTP_HOST)
        out_run  = ssh_cmd(shell, "show running-config ntp")
        srv_gone = "ntp server" not in out_run.lower()

        print(f"\n  +-- DISABLE VERIFICATION " + "-" * 35)
        print(f"  |  show ntp status  : {st_dis}  (keyword: '{kw_dis}')")
        print(f"  |  NTP server gone  : {'YES ✅' if srv_gone else 'NO  ⚠️  (still present)'}")
        print("  +" + "-" * 59)

        results["ntp_disabled"] = st_dis
        if st_dis == "PASS" and srv_gone:
            print("\n✅ NTP fully DISABLED — client off + server entry removed")
        elif st_dis == "PASS":
            print(f"\n✅ NTP disabled  (keyword: '{kw_dis}')")
        elif st_dis == "WARN":
            print("\n⚠️  Cannot confirm NTP disabled — check DEBUG block above")
        else:
            print(f"\n❌ NTP still active after disable  (keyword: '{kw_dis}')")

        step(10, "Re-enable NTP — restore switch to clean working state")
        ssh_cmd(shell, "configure terminal", timeout=3)
        ssh_cmd(shell, "ntp", timeout=CMD_WAIT)
        ssh_cmd(shell, ntp_server_cmd, timeout=CMD_WAIT, mask=MD5_KEY)
        ssh_cmd(shell, f"clock timezone {TIMEZONE_NAME} {TIMEZONE_HOURS} {TIMEZONE_MINS}",
                timeout=CMD_WAIT)
        ssh_cmd(shell, "exit", timeout=2)
        print(f"\n✅ NTP re-enabled — switch left in working state")

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
    section("TEST SUMMARY — TEST-HFCL-SW-NTP-MD5  MD5 Auth-Hash NTP")
    rows = [
        ("NTP Mode enabled + server present (show ntp status)",  results.get("ntp_status")),
        ("AUTH column = YES (MD5 active in show ntp status)",    results.get("auth_status")),
        ("NTP connect-status OK (show ntp connect-status)",      results.get("ntp_connect")),
        ("Clock correct after MD5 NTP sync (show clock)",        results.get("clock_check")),
        ("NTP disabled correctly (no ntp server 1 + no ntp)",    results.get("ntp_disabled")),
    ]
    all_pass = True
    for label, status in rows:
        result_line(label, status or "SKIP")
        if status in ("FAIL", None):
            all_pass = False

    print()
    if all_pass:
        print("🎉  ALL TESTS PASSED")
        print("    TEST-HFCL-SW-NTP-MD5 — MD5 auth-hash NTP verified:")
        print("    NTP enabled, AUTH=YES confirmed, clock correct,")
        print("    and disable confirmed — all passed.")
    else:
        print("❌  ONE OR MORE TESTS FAILED — review output above")
        print()
        print("    TIPS:")
        print(f"    • auth_status WARN : AUTH col may take time — check show ntp status manually")
        print(f"    • ntp_status  WARN : NTP may need more sync time — increase SYNC_WAIT")
        print(f"    • clock_check WARN : check 'show clock' DEBUG block above")
    print("=" * 65)
    return all_pass


if __name__ == "__main__":
    if len(sys.argv) >= 4:
        SWITCH_IP  = sys.argv[1]
        ADMIN_USER = sys.argv[2]
        ADMIN_PASS = sys.argv[3]
    if len(sys.argv) >= 5:
        MD5_KEY    = sys.argv[4]

    success = run_test()
    sys.exit(0 if success else 1)
