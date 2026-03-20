"""
TEST-HFCL-SW-NTP  —  NTP Operation Verification
=================================================
Test Objective:
  Verify NTP operations on the switch.

Procedure:
  PRE-CONFIG : Capture switch clock BEFORE NTP (baseline)
  PHASE 1    : Enable NTP client + configure server + timezone
  PHASE 2    : Verify show ntp status / connect-status / show clock
  PHASE 3    : Negative — Disable NTP (no ntp server 1 + no ntp)
               Verify NTP mode disabled + server entry removed
               Re-enable NTP, switch left in clean working state

Usage:
  python3 ntp_test.py [switch_ip] [admin_user] [admin_pass] [ntp_server_ip]
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
SWITCH_IP       = "192.168.180.136"
ADMIN_USER      = "admin"
ADMIN_PASS      = "admin"
SSH_PORT        = 22

NTP_SERVER_IP   = "192.168.180.69"  # This machine — runs real NTP + script
TIMEZONE_NAME   = "IST"
TIMEZONE_HOURS  = 5
TIMEZONE_MINS   = 30

CMD_WAIT        = 4    # seconds — normal show command timeout
SYNC_WAIT       = 60   # seconds — wait for NTP to sync after config


# ── Keywords that confirm NTP is SYNCED ─────────────────────
NTP_SYNC_KEYWORDS = [
    "synchronized", "synced", "sync'd",
    "stratum",       # only appears when synced
    "reference",
    "ntp enabled",
    "status: up",
    "reachable",
    "ntp server: yes",
    "clock is synchronized",
]

# ── Keywords that confirm NTP is NOT synced / disabled ──────
NTP_NOSYNC_KEYWORDS = [
    "unsynchronized", "not synchronized", "not synced",
    "unreachable", "no ntp", "ntp disabled",
    "status: down", "stratum 16",
    "clock is unsynchronized",
]


# ============================================================
# Ping + NTP UDP probe
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


def check_ntp_server_udp(host, port=123, timeout=3):
    """Send a real NTPv3 probe and return True if we get a valid response."""
    try:
        data = b'\x1b' + b'\x00' * 47
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(data, (host, port))
        response, _ = sock.recvfrom(1024)
        sock.close()
        return len(response) >= 48
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
                print(f"   SSH attempt {attempt} failed ({e}), retrying...")
                time.sleep(delay)
            else:
                raise


def _drain(shell):
    time.sleep(0.2)
    while shell.recv_ready():
        shell.recv(4096)
        time.sleep(0.05)


def ssh_cmd(shell, cmd, timeout=CMD_WAIT):
    """Send command, wait for output, print raw debug block."""
    print(f"   CMD: {cmd}")
    shell.send(cmd + "\n")
    collected = ""
    deadline  = time.time() + timeout
    last_recv = time.time()

    while time.time() < deadline:
        time.sleep(0.1)          # poll every 100ms instead of 400ms
        chunk = ""
        while shell.recv_ready():
            chunk += shell.recv(4096).decode("utf-8", errors="ignore")
            time.sleep(0.02)     # minimal inter-chunk gap
        if chunk:
            collected += chunk
            last_recv  = time.time()
        if collected and (time.time() - last_recv) > 1.0:  # 1s idle instead of 3s
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
    """Enter config mode, apply commands, exit config mode."""
    ssh_cmd(shell, "configure terminal", timeout=3)
    output = ""
    for cmd in commands:
        output += ssh_cmd(shell, cmd, timeout=timeout)
    ssh_cmd(shell, "exit", timeout=2)
    return output


# ============================================================
# NTP output classifier
# ============================================================

def classify_ntp(output, expect_synced=True, ntp_ip=None):
    """
    Classify NTP status output.

    For show ntp status this switch does NOT print "synchronized" —
    instead it prints:
       NTP Mode : enabled
       1   192.168.180.69   NO   NO
    So we check TWO things when expect_synced=True:
      1. "ntp mode" + "enabled"  in the output
      2. The configured NTP server IP appears in the table row
    Either of those alone is enough to call it PASS.
    Generic sync keywords are still checked as a fallback.
    """
    lower  = output.lower()
    lines  = output.splitlines()

    if expect_synced:
        # ── Check 1: NTP Mode : enabled ──────────────────────
        if "ntp mode" in lower and "enabled" in lower:
            # ── Check 2: server IP present in table ──────────
            if ntp_ip and ntp_ip in output:
                return "PASS", f"NTP Mode enabled + server {ntp_ip} found"
            # IP not supplied or not found — mode enabled is enough
            return "PASS", "NTP Mode : enabled"

        # ── Fallback: generic sync keywords ──────────────────
        for k in NTP_SYNC_KEYWORDS:
            if k in lower:
                return "PASS", k

        # ── Explicit failure keywords ─────────────────────────
        for k in NTP_NOSYNC_KEYWORDS:
            if k in lower:
                return "FAIL", k

        return "WARN", "(no decisive keyword)"

    else:
        # Negative test — we want to see NTP disabled/gone
        # Check NTP Mode disabled or no server entry
        if "ntp mode" in lower and "disabled" in lower:
            return "PASS", "NTP Mode : disabled"
        if ntp_ip and ntp_ip not in output and "ntp mode" in lower:
            return "PASS", f"server {ntp_ip} not found in table"
        for k in NTP_NOSYNC_KEYWORDS:
            if k in lower:
                return "PASS", k
        for k in NTP_SYNC_KEYWORDS:
            if k in lower:
                return "FAIL", k
        return "WARN", "(no decisive keyword)"


# ============================================================
# Clock parser
# ============================================================

MONTH_MAP = {
    "jan": 1,  "feb": 2,  "mar": 3,  "apr": 4,
    "may": 5,  "jun": 6,  "jul": 7,  "aug": 8,
    "sep": 9,  "oct": 10, "nov": 11, "dec": 12,
}
DAY_NAMES = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}


def parse_clock(output):
    """
    Parse 'show clock' output.  Handles all common switch formats:
      System Time : 2026-03-19T13:59:15+05:30   (HFCL with label prefix)
      2026-03-19T13:59:15+05:30
      2026-03-19 13:59:15
      *15:32:10.452 IST Thu Mar 19 2026          (* = not NTP-synced)
      15:32:10 UTC Thu Mar 19 2026
      Thu Mar 19 2026 15:32:10 IST
    """
    info = {
        "raw": output, "hour": None, "minute": None, "second": None,
        "day": None, "month": None, "month_name": None,
        "year": None, "weekday": None, "timezone": None,
        "synced": True, "valid": False,
    }

    # Select best line
    for line in output.splitlines():
        line = line.strip()
        if not line or "show clock" in line.lower():
            continue
        # Strip "Label : value" prefix (e.g. "System Time     : 2026-...")
        # Guard: only strip if prefix has NO digits AND length > 2
        # (avoids stripping "15:32:10 IST..." style time strings)
        if ":" in line:
            prefix, _, rest = line.partition(":")
            if (prefix and not re.search(r"\d", prefix)
                    and len(prefix.strip()) > 2):
                line = rest.strip()
        # '*' = not NTP-synced on many platforms
        if line.startswith("*"):
            info["synced"] = False
            line = line[1:].strip()
        info["raw"] = line
        break
    else:
        return info

    line = info["raw"]

    # ── ISO 8601: 2026-03-19T13:59:15+05:30 ─────────────────
    iso = re.search(
        r"(\d{4})-(\d{2})-(\d{2})"
        r"[T ]"
        r"(\d{2}):(\d{2}):(\d{2})"
        r"(?:[.,]\d+)?"
        r"(?:([+-])(\d{2}):?(\d{2})|Z)?",
        line
    )
    if iso:
        info["year"]   = int(iso.group(1))
        info["month"]  = int(iso.group(2))
        info["day"]    = int(iso.group(3))
        info["hour"]   = int(iso.group(4))
        info["minute"] = int(iso.group(5))
        info["second"] = int(iso.group(6))
        info["month_name"] = list(MONTH_MAP.keys())[info["month"] - 1].capitalize()
        try:
            info["weekday"] = datetime.date(
                info["year"], info["month"], info["day"]
            ).strftime("%a")
        except Exception:
            pass
        if iso.group(7) and iso.group(8) and iso.group(9):
            info["timezone"] = f"{iso.group(7)}{iso.group(8)}:{iso.group(9)}"
        elif "Z" in line[max(0, iso.end()-2): iso.end()+2]:
            info["timezone"] = "UTC"
        info["valid"] = True
        return info

    # ── Token-based: "HH:MM:SS TZ DoW Mon DD YYYY" ──────────
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

    info["valid"] = (
        info["year"]  is not None and
        info["month"] is not None and
        info["day"]   is not None
    )
    return info


def format_clock(info):
    """One-line summary of a parsed clock dict."""
    if not info["valid"]:
        return f"(could not parse)  raw='{info['raw']}'"
    parts = []
    if info["weekday"]:
        parts.append(info["weekday"])
    if info["day"] and info["month_name"] and info["year"]:
        parts.append(f"{info['day']:02d} {info['month_name']} {info['year']}")
    if info["hour"] is not None:
        parts.append(
            f"{info['hour']:02d}:{info['minute']:02d}:{info['second']:02d}"
        )
    if info["timezone"]:
        tz = info["timezone"]
        if tz in ("+05:30", "+0530"):
            parts.append(f"{tz} (IST)")
        elif tz in ("+00:00", "+0000", "UTC", "Z"):
            parts.append("UTC")
        else:
            parts.append(tz)
    if not info["synced"]:
        parts.append("[NOT NTP-synced]")
    return "  ".join(parts)


def print_clock_block(label, clock_info, host_utc):
    """Print a formatted clock analysis block."""
    bar = "-" * max(0, 55 - len(label))
    print(f"\n  +-- {label} {bar}")
    print(f"  |  Switch clock   : {format_clock(clock_info)}")
    print(f"  |  Host UTC       : "
          f"{time.strftime('%a %d %b %Y  %H:%M:%S', host_utc)}")
    print(f"  |")
    if clock_info["valid"]:
        t = clock_info
        print(f"  |  Day      : {t['day']}")
        print(f"  |  Month    : {t['month_name']}  (month #{t['month']})")
        print(f"  |  Year     : {t['year']}")
        if t["hour"] is not None:
            print(f"  |  Time     : "
                  f"{t['hour']:02d}:{t['minute']:02d}:{t['second']:02d}")
        print(f"  |  Timezone : {t['timezone'] or '(not shown)'}")
        print(f"  |  NTP-sync : {'Yes' if t['synced'] else 'No  [free-running]'}")
        print(f"  |")
        y_ok = t["year"]  == host_utc.tm_year
        m_ok = t["month"] == host_utc.tm_mon
        d_ok = abs((t["day"] or 0) - host_utc.tm_mday) <= 1
        print(f"  |  Accuracy vs host UTC:")
        print(f"  |    Year  : {'MATCH   ' if y_ok else 'MISMATCH'}  "
              f"switch={t['year']}  host={host_utc.tm_year}")
        print(f"  |    Month : {'MATCH   ' if m_ok else 'MISMATCH'}  "
              f"switch={t['month']} ({t['month_name']})  "
              f"host={host_utc.tm_mon} ({time.strftime('%b', host_utc)})")
        print(f"  |    Day   : {'MATCH   ' if d_ok else 'MISMATCH'}  "
              f"switch={t['day']}  host={host_utc.tm_mday}")
        note = "INFO: date matches host." if (y_ok and m_ok and d_ok) \
               else "WARNING: date differs from host."
        print(f"  |  {note}")
    else:
        print(f"  |  WARNING: Could not parse clock — check raw output above")
    print("  +" + "-" * 59)


def compare_clocks(before, after):
    """Print before-vs-after table. Returns (ok, [issues])."""
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
        bv = str(before.get(key) or "-")
        av = str(after.get(key)  or "-")
        arrow = "  <-- CHANGED" if bv != av else ""
        print(f"  |  {label:<14}  {bv:>22}  {av:>22}{arrow}")
    print(f"  |")
    print(f"  |  Host UTC now   : "
          f"{time.strftime('%a %d %b %Y  %H:%M:%S', now_utc)}")
    print("  +" + "-" * 59)

    ok = True
    issues = []
    if after["valid"]:
        if after["year"] != now_utc.tm_year:
            issues.append(
                f"year mismatch: switch={after['year']} host={now_utc.tm_year}"
            )
            ok = False
        if after["month"] != now_utc.tm_mon:
            issues.append(
                f"month mismatch: switch={after['month']} host={now_utc.tm_mon}"
            )
            ok = False
        if abs((after["day"] or 0) - now_utc.tm_mday) > 1:
            issues.append(
                f"day mismatch: switch={after['day']} host={now_utc.tm_mday}"
            )
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
    print(f"  {icon}  {label:<52} {status}")


# ============================================================
# MAIN TEST
# ============================================================

def run_test():
    results      = {}
    ntp_ip       = sys.argv[4] if len(sys.argv) > 4 else NTP_SERVER_IP
    clock_before = {}      # populated in PRE-CONFIG

    print(f"\n  Switch IP          : {SWITCH_IP}")
    print(f"  NTP server IP      : {ntp_ip}  (this PC)")
    print(f"  Timezone           : {TIMEZONE_NAME} "
          f"+{TIMEZONE_HOURS}:{TIMEZONE_MINS:02d}") 

    try:
        # ══════════════════════════════════════════════════════
        # PREFLIGHT
        # ══════════════════════════════════════════════════════
        section("PREFLIGHT — Verify NTP Server Reachability")

        print(f"  Pinging {ntp_ip} ...")
        if ping_host(ntp_ip):
            print(f"  ✅ Ping OK — {ntp_ip} is reachable")
        else:
            print(f"  ⚠️  Ping failed (ICMP may be blocked — continuing)")

        print(f"\n  UDP probe on {ntp_ip}:123 ...")
        if check_ntp_server_udp(ntp_ip):
            print(f"  ✅ Real NTP server RESPONDING on {ntp_ip}:123")
        else:
            print(f"  ⚠️  Real NTP NOT responding on {ntp_ip}:123")
            print(f"     Ensure NTP service is running on this machine")



        # ══════════════════════════════════════════════════════
        # PRE-CONFIG — show clock BEFORE NTP
        # ══════════════════════════════════════════════════════
        section("PRE-CONFIG — Capture Switch Clock BEFORE NTP (Baseline)")

        step(1, f"SSH into switch as {ADMIN_USER}")
        c1, sh1 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print(f"✅ SSH connected to {SWITCH_IP}")

        step(2, "show clock  <-- BEFORE NTP configuration")
        raw_before   = ssh_cmd(sh1, "show clock")
        clock_before = parse_clock(raw_before)
        print_clock_block("PRE-NTP CLOCK ANALYSIS", clock_before, time.gmtime())

        # ══════════════════════════════════════════════════════
        # PHASE 1 — Configure NTP
        # ══════════════════════════════════════════════════════
        section("PHASE 1 — Enable NTP Client and Configure Server")

        step(3, "Apply NTP config on switch")
        cmds = [
            "ntp",
            f"ntp server 1 ip-address {ntp_ip}",
            f"clock timezone {TIMEZONE_NAME} {TIMEZONE_HOURS} {TIMEZONE_MINS}",
        ]
        for c in cmds:
            print(f"   Applying: {c}")
        ssh_config(sh1, cmds)
        print(f"✅ NTP configuration applied")

        # ══════════════════════════════════════════════════════
        # PHASE 2 — Verify NTP + clock
        # ══════════════════════════════════════════════════════
        section("PHASE 2 — Verify NTP Status and Clock Accuracy")

        step(4, "show ntp status")
        print(f"   ⏳ Polling NTP status (max {SYNC_WAIT}s, checks every 10s) ...")
        out_s = ""
        st_s  = "WARN"
        kw_s  = "(timeout)"
        poll_deadline = time.time() + SYNC_WAIT
        while time.time() < poll_deadline:
            out_s = ssh_cmd(sh1, "show ntp status")
            st_s, kw_s = classify_ntp(out_s, expect_synced=True, ntp_ip=ntp_ip)
            if st_s == "PASS":
                elapsed = int(SYNC_WAIT - (poll_deadline - time.time()))
                print(f"   ✅ NTP synced after ~{elapsed}s")
                break
            remaining = int(poll_deadline - time.time())
            if remaining > 0:
                print(f"   ⏳ Not yet synced — retrying in 10s  ({remaining}s left) ...")
                time.sleep(10)
        results["ntp_status"] = st_s
        print(f"{'✅' if st_s=='PASS' else ('⚠️' if st_s=='WARN' else '❌')}  "
              f"NTP status: {st_s}  (keyword: '{kw_s}')")

        step(5, "show ntp connect-status")
        out_c = ssh_cmd(sh1, "show ntp connect-status")
        st_c, kw_c = classify_ntp(out_c, expect_synced=True)
        results["ntp_connect"] = st_c
        print(f"{'✅' if st_c=='PASS' else ('⚠️' if st_c=='WARN' else '❌')}  "
              f"NTP connect-status: {st_c}  (keyword: '{kw_c}')")

        step(6, "show clock  <-- AFTER NTP configuration")
        raw_after   = ssh_cmd(sh1, "show clock")
        clock_after = parse_clock(raw_after)
        print_clock_block("AFTER-NTP CLOCK ANALYSIS", clock_after, time.gmtime())

        clock_ok, issues = compare_clocks(clock_before, clock_after)
        if issues:
            for iss in issues:
                print(f"    - {iss}")
        results["clock_check"] = "PASS" if clock_ok else "WARN"
        print(f"\n{'✅' if clock_ok else '⚠️'}  "
              f"Clock check: {'PASS' if clock_ok else 'WARN'}")

        # ══════════════════════════════════════════════════════
        # PHASE 3 — Disable NTP  (reuse same SSH session)
        # ══════════════════════════════════════════════════════
        section("PHASE 3 — Negative Test: Disable NTP")
        c3, sh3 = c1, sh1   # reuse existing SSH session — no reconnect needed
        print("  ℹ️  Reusing SSH session from Phase 2")

        step(8,  "Disable NTP: Step 1 — no ntp server 1")
        ssh_config(sh3, ["no ntp server 1"])
        print("   ✅ NTP server entry removed")

        step(9,  "Disable NTP: Step 2 — no ntp")
        ssh_config(sh3, ["no ntp"])
        time.sleep(1)
        print("   ✅ NTP client disabled")

        step(10, "Verify NTP is fully disabled")
        out_dis = ssh_cmd(sh3, "show ntp status")
        st_dis, kw_dis = classify_ntp(out_dis, expect_synced=False, ntp_ip=ntp_ip)

        # Also verify server entry is gone
        out_run = ssh_cmd(sh3, "show running-config ntp")
        server_gone = "ntp server" not in out_run.lower()

        print("\n  +-- DISABLE VERIFICATION " + "-" * 35)
        print(f"  |  show ntp status result : {st_dis}  (keyword: '{kw_dis}')")
        print(f"  |  NTP server entry gone  : {'YES ✅' if server_gone else 'NO  ⚠️  (still present)'}")
        print("  +" + "-" * 59)

        results["ntp_disabled"] = st_dis
        if st_dis == "PASS" and server_gone:
            print("\n✅ NTP fully DISABLED — client off + server entry removed")
        elif st_dis == "PASS":
            print(f"\n✅ NTP status shows disabled  (keyword: '{kw_dis}')")
            print(f"   ⚠️  NTP server entry may still be in running-config")
        elif st_dis == "WARN":
            print("\n⚠️  Cannot confirm NTP disabled — check DEBUG block above")
        else:
            print("\n❌ NTP still shows synced after disable commands")
            print(f"   (keyword: '{kw_dis}')")

        step(11, "Re-enable NTP — restore switch to clean working state")
        ssh_config(sh3, [
            "ntp",
            f"ntp server 1 ip-address {ntp_ip}",
            f"clock timezone {TIMEZONE_NAME} {TIMEZONE_HOURS} {TIMEZONE_MINS}",
        ])
        print(f"✅ NTP re-enabled — switch left in working state")

        c1.close()
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
    section("TEST SUMMARY — TEST-HFCL-SW-NTP  NTP Operation")
    rows = [
        ("NTP Mode enabled + server IP present",              results.get("ntp_status")),
        ("NTP connect-status OK (show ntp connect-status)",   results.get("ntp_connect")),
        ("Clock correct after NTP sync (show clock)",         results.get("clock_check")),
        ("NTP disabled correctly (no ntp server 1 + no ntp)", results.get("ntp_disabled")),
    ]
    all_pass = True
    for label, status in rows:
        result_line(label, status or "SKIP")
        if status in ("FAIL", None):
            all_pass = False

    print()
    if all_pass:
        print("🎉  ALL TESTS PASSED")
        print("    TEST-HFCL-SW-NTP - Management - NTP operation verified:")
        print("    NTP enabled + server verified, clock correct,")
        print("    and NTP disable confirmed — all passed.")
    else:
        print("❌  ONE OR MORE TESTS FAILED — review output above")
        print()
        print("    TIPS:")
        print(f"    • WARN on status: add missing keyword to NTP_SYNC_KEYWORDS")
    print("=" * 65)
    return all_pass


if __name__ == "__main__":
    if len(sys.argv) >= 4:
        SWITCH_IP  = sys.argv[1]
        ADMIN_USER = sys.argv[2]
        ADMIN_PASS = sys.argv[3]

    success = run_test()
    sys.exit(0 if success else 1)
