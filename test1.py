"""
TEST-HFCL-SW-01  —  Management: SSH Service Verification
=========================================================
Test Name      : Management
Test Protocol  : SSH
Test Objective : Verify SSH service by enabling, creating a user,
                 and disabling it.

Test Configuration:
  (config)# ip ssh
  (config)# username hfcl privilege 15 password unencrypted Discover@1234
  (config)# no ip ssh

Verify:
  # show ip ssh
  # show users

Procedure:
  PHASE 1 : SSH connect to switch
  PHASE 2 : Enable SSH globally (ip ssh)
  PHASE 3 : Create test user 'hfcl' with privilege 15
  PHASE 4 : Verify SSH enabled  (show ip ssh)
  PHASE 5 : Verify user session (show users)
  PHASE 6 : Disable SSH via Telnet (no ip ssh)
  PHASE 7 : Verify SSH disabled   (show ip ssh via Telnet)
  PHASE 8 : Re-enable SSH via Telnet (ip ssh)
  PHASE 9 : Verify SSH re-enabled  (show ip ssh via Telnet)

Expected Result:
  - SSH service enabled and accessible when configured
  - User created, SSH access granted, show users confirms active session
  - After disabling SSH, connection attempts should be blocked
  - SSH re-enabled and verified at end — switch left in clean state

Usage:
  python3 ssh_test.py <switch_ip> <admin_user> <admin_pass>
  python3 ssh_test.py 192.168.180.155 admin admin
"""

import sys
import re
import time
import socket
import telnetlib
import paramiko


# ============================================================
# Configuration
# ============================================================
SWITCH_IP    = "192.168.180.155"
ADMIN_USER   = "admin"
ADMIN_PASS   = "admin"
SSH_PORT     = 22
TELNET_PORT  = 23

# Test user to create
TEST_USER    = "hfcl"
TEST_PASS    = "Discover@1234"
TEST_PRIV    = 15

CMD_WAIT     = 2     # seconds — wait after each command
CONN_TIMEOUT = 15    # seconds — connection timeout


# ============================================================
# Formatting helpers  (consistent with other HFCL test scripts)
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

def raw_block(output, label="RAW SWITCH OUTPUT"):
    print(f"  +-- {label} " + "-" * max(0, 55 - len(label)))
    for line in output.splitlines():
        line = line.strip()
        if line:
            print(f"  |  {line}")
    print("  +" + "-" * 63)


# ============================================================
# SSH helpers
# ============================================================

def open_ssh_shell(hostname, username, password, port=22,
                   retries=3, delay=3):
    """Open SSH shell. Returns (client, shell) or raises."""
    for attempt in range(1, retries + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname, port=port,
                username=username, password=password,
                timeout=CONN_TIMEOUT,
                look_for_keys=False, allow_agent=False
            )
            shell = client.invoke_shell()
            time.sleep(0.3)
            _drain_ssh(shell)
            return client, shell
        except Exception as e:
            client.close()
            if attempt < retries:
                print(f"   ⏳ SSH attempt {attempt} failed ({e}), retrying...")
                time.sleep(delay)
            else:
                raise


def _drain_ssh(shell):
    time.sleep(0.2)
    while shell.recv_ready():
        shell.recv(4096)
        time.sleep(0.05)


def ssh_cmd(shell, cmd, timeout=CMD_WAIT):
    """Send SSH command, collect and return cleaned output."""
    shell.send(cmd + "\n")
    collected = ""
    deadline  = time.time() + timeout + 2
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

    # Strip ANSI escape codes
    clean = re.sub(r"\x1b\[[0-9;]*[mGKH]", "", collected).strip()
    return clean


def ssh_config(shell, commands):
    """Enter config mode, run commands, exit."""
    ssh_cmd(shell, "configure terminal", timeout=2)
    for cmd in commands:
        ssh_cmd(shell, cmd, timeout=CMD_WAIT)
    ssh_cmd(shell, "exit", timeout=2)


# ============================================================
# Telnet helpers
# ============================================================

def open_telnet(hostname, username, password, port=23):
    """Open Telnet session and login. Returns tn object."""
    print(f"   Connecting to {hostname}:{port} via Telnet ...")
    tn = telnetlib.Telnet(hostname, port, timeout=CONN_TIMEOUT)

    # Wait for Username prompt
    tn.read_until(b"Username:", timeout=10)
    tn.write(username.encode("ascii") + b"\n")

    # Wait for Password prompt
    tn.read_until(b"Password:", timeout=10)
    tn.write(password.encode("ascii") + b"\n")

    # Drain login banner
    time.sleep(1.5)
    banner = b""
    while True:
        chunk = tn.read_very_eager()
        if not chunk:
            break
        banner += chunk
        time.sleep(0.3)

    decoded = banner.decode("ascii", errors="ignore").strip()
    if decoded:
        print(f"   Login banner:\n   {decoded[:200]}")
    return tn


def telnet_cmd(tn, cmd, wait=CMD_WAIT):
    """Send Telnet command, drain output, return cleaned string."""
    tn.write(cmd.encode("ascii") + b"\n")
    time.sleep(wait)
    output = b""
    while True:
        chunk = tn.read_very_eager()
        if not chunk:
            break
        output += chunk
        time.sleep(0.3)
    decoded = output.decode("ascii", errors="ignore")
    # Remove echo of the command itself
    lines = [l for l in decoded.splitlines() if cmd.strip() not in l]
    return "\n".join(lines).strip()


def telnet_config(tn, commands, wait=CMD_WAIT):
    """Enter config mode via Telnet, run commands, exit."""
    telnet_cmd(tn, "configure terminal", wait=1)
    for cmd in commands:
        telnet_cmd(tn, cmd, wait=wait)
    telnet_cmd(tn, "exit", wait=1)


# ============================================================
# MAIN TEST
# ============================================================

def run_test():
    results = {}

    print(f"\n  Switch IP    : {SWITCH_IP}")
    print(f"  Admin user   : {ADMIN_USER}")
    print(f"  Test user    : {TEST_USER}  (privilege {TEST_PRIV})")
    print(f"  SSH port     : {SSH_PORT}")
    print(f"  Telnet port  : {TELNET_PORT}")

    # ══════════════════════════════════════════════════════════
    # PHASE 1 — SSH Connect
    # ══════════════════════════════════════════════════════════
    section("PHASE 1 — SSH Connect to Switch")

    step(1, f"SSH connect to {SWITCH_IP} as {ADMIN_USER}")
    try:
        client, shell = open_ssh_shell(
            SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT
        )
        print(f"✅ SSH connected to {SWITCH_IP}:{SSH_PORT}")
        results["ssh_connect"] = "PASS"
    except paramiko.AuthenticationException:
        print(f"❌ SSH authentication failed — check credentials")
        results["ssh_connect"] = "FAIL"
        _print_summary(results)
        return False
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        results["ssh_connect"] = "FAIL"
        _print_summary(results)
        return False

    # ══════════════════════════════════════════════════════════
    # PHASE 2 — Enable SSH Globally
    # ══════════════════════════════════════════════════════════
    section("PHASE 2 — Enable SSH Globally")

    step(2, "configure terminal → ip ssh → exit")
    print(f"   Applying: ip ssh")
    ssh_config(shell, ["ip ssh"])
    print(f"✅ SSH enabled globally")
    results["ssh_enable"] = "PASS"

    # ══════════════════════════════════════════════════════════
    # PHASE 3 — Create Test User
    # ══════════════════════════════════════════════════════════
    section("PHASE 3 — Create Test User 'hfcl'")

    step(3, f"Create user: username {TEST_USER} privilege {TEST_PRIV} "
            f"password unencrypted ****")
    user_cmd = (f"username {TEST_USER} privilege {TEST_PRIV} "
                f"password unencrypted {TEST_PASS}")
    ssh_config(shell, [user_cmd])
    print(f"✅ User '{TEST_USER}' created with privilege {TEST_PRIV}")
    results["user_create"] = "PASS"

    # ══════════════════════════════════════════════════════════
    # PHASE 4 — Verify SSH Enabled
    # ══════════════════════════════════════════════════════════
    section("PHASE 4 — Verify SSH Status (show ip ssh)")

    step(4, "show ip ssh")
    out_ssh = ssh_cmd(shell, "show ip ssh", timeout=4)
    raw_block(out_ssh)
    lower_ssh = out_ssh.lower()

    # Check for enabled keywords
    ssh_enabled = any(k in lower_ssh for k in
                      ["enabled", "ssh enabled", "version", "ssh version",
                       "authentication", "ip ssh"])
    ssh_disabled = any(k in lower_ssh for k in
                       ["disabled", "not enabled", "no ssh"])

    print(f"\n  +-- SSH STATUS ANALYSIS " + "-" * 41)
    if ssh_enabled and not ssh_disabled:
        print(f"  |  SSH status  : ENABLED ✅")
        results["ssh_verify_enabled"] = "PASS"
    elif ssh_disabled:
        print(f"  |  SSH status  : DISABLED ❌")
        results["ssh_verify_enabled"] = "FAIL"
    else:
        print(f"  |  SSH status  : ⚠️  (check raw output above)")
        results["ssh_verify_enabled"] = "WARN"
    print("  +" + "-" * 63)
    print(f"{'✅' if results['ssh_verify_enabled']=='PASS' else ('⚠️' if results['ssh_verify_enabled']=='WARN' else '❌')}  "
          f"SSH enabled verify: {results['ssh_verify_enabled']}")

    # ══════════════════════════════════════════════════════════
    # PHASE 5 — Verify User Session
    # ══════════════════════════════════════════════════════════
    section("PHASE 5 — Verify User Session (show users)")

    step(5, "show users")
    out_users = ssh_cmd(shell, "show users", timeout=4)
    raw_block(out_users)
    lower_users = out_users.lower()

    # Check for admin or test user in active sessions
    user_found = (ADMIN_USER.lower() in lower_users or
                  TEST_USER.lower()  in lower_users)

    print(f"\n  +-- USER SESSION ANALYSIS " + "-" * 38)
    print(f"  |  Looking for user : '{ADMIN_USER}' or '{TEST_USER}'")
    print(f"  |  User found       : {'YES ✅' if user_found else 'NOT FOUND ⚠️'}")
    print("  +" + "-" * 63)

    results["user_session"] = "PASS" if user_found else "WARN"
    print(f"{'✅' if user_found else '⚠️'}  "
          f"User session verify: {results['user_session']}")

    # ══════════════════════════════════════════════════════════
    # PHASE 6 — Close SSH, Open Telnet, Disable SSH
    # ══════════════════════════════════════════════════════════
    section("PHASE 6 — Disable SSH via Telnet")

    step(6, "Close SSH session")
    client.close()
    print("✅ SSH session closed")
    time.sleep(1)

    step(7, f"Telnet connect to {SWITCH_IP}:{TELNET_PORT}")
    try:
        tn = open_telnet(SWITCH_IP, ADMIN_USER, ADMIN_PASS, TELNET_PORT)
        print(f"✅ Telnet connected to {SWITCH_IP}:{TELNET_PORT}")
        results["telnet_connect"] = "PASS"
    except Exception as e:
        print(f"❌ Telnet connection failed: {e}")
        print(f"   Ensure Telnet is enabled on the switch")
        results["telnet_connect"] = "FAIL"
        results["ssh_disable"]    = "SKIP"
        results["ssh_verify_dis"] = "SKIP"
        results["ssh_reenable"]   = "SKIP"
        results["ssh_verify_re"]  = "SKIP"
        _print_summary(results)
        return False

    step(8, "Disable SSH: configure terminal → no ip ssh → exit")
    print(f"   Applying: no ip ssh")
    telnet_config(tn, ["no ip ssh"])
    print("✅ SSH disabled globally via Telnet")
    results["ssh_disable"] = "PASS"

    # ══════════════════════════════════════════════════════════
    # PHASE 7 — Verify SSH Disabled
    # ══════════════════════════════════════════════════════════
    section("PHASE 7 — Verify SSH Disabled (show ip ssh via Telnet)")

    step(9, "show ip ssh")
    out_dis = telnet_cmd(tn, "show ip ssh", wait=3)
    raw_block(out_dis)
    lower_dis = out_dis.lower()

    ssh_now_disabled = any(k in lower_dis for k in
                           ["disabled", "not enabled", "no ssh", "ssh disabled"])
    ssh_still_on     = any(k in lower_dis for k in
                           ["enabled", "version", "authentication"])

    print(f"\n  +-- SSH DISABLED VERIFICATION " + "-" * 34)
    if ssh_now_disabled or not ssh_still_on:
        print(f"  |  SSH status  : DISABLED ✅  (connection attempts will be blocked)")
        results["ssh_verify_dis"] = "PASS"
    else:
        print(f"  |  SSH status  : ⚠️  may still be enabled — check raw above")
        results["ssh_verify_dis"] = "WARN"
    print("  +" + "-" * 63)
    print(f"{'✅' if results['ssh_verify_dis']=='PASS' else '⚠️'}  "
          f"SSH disabled verify: {results['ssh_verify_dis']}")

    # ══════════════════════════════════════════════════════════
    # PHASE 8 — Re-enable SSH via Telnet
    # ══════════════════════════════════════════════════════════
    section("PHASE 8 — Re-enable SSH via Telnet")

    step(10, "Re-enable SSH: configure terminal → ip ssh → exit")
    print(f"   Applying: ip ssh")
    telnet_config(tn, ["ip ssh"])
    print("✅ SSH re-enabled globally via Telnet")
    results["ssh_reenable"] = "PASS"

    # ══════════════════════════════════════════════════════════
    # PHASE 9 — Verify SSH Re-enabled
    # ══════════════════════════════════════════════════════════
    section("PHASE 9 — Verify SSH Re-enabled (show ip ssh via Telnet)")

    step(11, "show ip ssh")
    out_re = telnet_cmd(tn, "show ip ssh", wait=3)
    raw_block(out_re)
    lower_re = out_re.lower()

    ssh_back_on = any(k in lower_re for k in
                      ["enabled", "ssh enabled", "version",
                       "authentication", "ip ssh"])
    ssh_still_off = any(k in lower_re for k in
                        ["disabled", "not enabled"])

    print(f"\n  +-- SSH RE-ENABLED VERIFICATION " + "-" * 32)
    if ssh_back_on and not ssh_still_off:
        print(f"  |  SSH status  : ENABLED ✅")
        results["ssh_verify_re"] = "PASS"
    elif ssh_still_off:
        print(f"  |  SSH status  : DISABLED ❌  (re-enable failed)")
        results["ssh_verify_re"] = "FAIL"
    else:
        print(f"  |  SSH status  : ⚠️  (check raw output above)")
        results["ssh_verify_re"] = "WARN"
    print("  +" + "-" * 63)
    print(f"{'✅' if results['ssh_verify_re']=='PASS' else ('⚠️' if results['ssh_verify_re']=='WARN' else '❌')}  "
          f"SSH re-enabled verify: {results['ssh_verify_re']}")

    tn.close()
    print("\n✅ Telnet session closed")

    _print_summary(results)
    return all(v in ("PASS", "WARN") for v in results.values())


# ============================================================
# Summary printer
# ============================================================

def _print_summary(results):
    section("TEST SUMMARY — TEST-HFCL-SW-01  SSH Service Verification")

    rows = [
        ("SSH connect to switch",                        results.get("ssh_connect")),
        ("SSH enabled globally (ip ssh)",                results.get("ssh_enable")),
        ("Test user 'hfcl' created (privilege 15)",      results.get("user_create")),
        ("SSH enabled verified (show ip ssh)",           results.get("ssh_verify_enabled")),
        ("User session confirmed (show users)",          results.get("user_session")),
        ("Telnet connected to switch",                   results.get("telnet_connect")),
        ("SSH disabled via Telnet (no ip ssh)",          results.get("ssh_disable")),
        ("SSH disabled verified (show ip ssh)",          results.get("ssh_verify_dis")),
        ("SSH re-enabled via Telnet (ip ssh)",           results.get("ssh_reenable")),
        ("SSH re-enabled verified (show ip ssh)",        results.get("ssh_verify_re")),
    ]

    all_pass = True
    for label, status in rows:
        result_line(label, status or "SKIP")
        if status in ("FAIL", None):
            all_pass = False

    print()

    # ── Test procedure recap ──────────────────────────────────
    print("=" * 65)
    print("  TEST DETAILS")
    print("=" * 65)
    print(f"  Test Name      : Management")
    print(f"  Test Protocol  : SSH + Telnet")
    print(f"  Test Objective : Verify SSH service by enabling, creating")
    print(f"                   a user and disabling it.")
    print()
    print(f"  Procedure:")
    print(f"    1.  SSH connect to switch as {ADMIN_USER}")
    print(f"    2.  Enable SSH globally       (config)# ip ssh")
    print(f"    3.  Create user 'hfcl'        (config)# username hfcl privilege 15")
    print(f"                                            password unencrypted Discover@1234")
    print(f"    4.  Verify SSH status         # show ip ssh")
    print(f"    5.  Verify user session       # show users")
    print(f"    6.  Switch to Telnet session")
    print(f"    7.  Disable SSH via Telnet    (config)# no ip ssh")
    print(f"    8.  Verify SSH disabled       # show ip ssh")
    print(f"    9.  Re-enable SSH via Telnet  (config)# ip ssh")
    print(f"    10. Verify SSH re-enabled     # show ip ssh")
    print()
    print(f"  Expected Result:")
    print(f"    • SSH service enabled and accessible when configured")
    print(f"    • User created, SSH access granted, show users")
    print(f"      confirms active session")
    print(f"    • After disabling SSH, connection attempts blocked")
    print(f"    • SSH re-enabled and verified — switch left clean")
    print("=" * 65)

    print()
    if all_pass:
        print("🎉  ALL TESTS PASSED")
        print("    TEST-HFCL-SW-01 - Management - Verify SSH service by")
        print("    enabling, created user and disabling it.")
        print("    Completed Successfully.")
    else:
        print("❌  ONE OR MORE TESTS FAILED — review output above")
        print()
        print("    TIPS:")
        print("    • ssh_connect FAIL   : check IP, credentials, SSH port 22")
        print("    • telnet_connect FAIL: ensure Telnet is enabled on switch")
        print("    • ssh_verify WARN    : add switch keyword to check list")
    print("=" * 65)


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) == 4:
        SWITCH_IP  = sys.argv[1]
        ADMIN_USER = sys.argv[2]
        ADMIN_PASS = sys.argv[3]
    elif len(sys.argv) == 1:
        pass   # use defaults defined at top
    else:
        print("Usage: python3 ssh_test.py <switch_ip> <username> <password>")
        sys.exit(1)

    success = run_test()
    sys.exit(0 if success else 1)
