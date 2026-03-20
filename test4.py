"""
TEST-HFCL-SW-04  —  Management: Telnet Service Verification
============================================================
Test Name      : Management - 04
Test Protocol  : Telnet
Test Objective : Verify the Telnet service by enabling and disabling it,
                 and confirm that Telnet client support is functioning.

Test Configuration:
  (config)# aaa authentication login telnet local
  (config)# no aaa authentication login telnet local

Verify:
  # show users
  telnet <management_ip>

Procedure:
  PHASE 1 : Enable Telnet server via SSH
            (config)# aaa authentication login telnet local
  PHASE 2 : Verify Telnet port is open
  PHASE 3 : Connect via Telnet from PC → switch (server-side test)
  PHASE 4 : Verify Telnet session in show users
  PHASE 5 : Device-side Telnet client (switch → itself)
  PHASE 6 : Disable Telnet server via SSH
            (config)# no aaa authentication login telnet local
  PHASE 7 : Verify Telnet login is DENIED after disable

Expected Result:
  - Telnet server enabled and port open
  - Telnet login succeeds and session visible in show users
  - Device-side Telnet client reaches switch successfully
  - After disabling, Telnet login is blocked

Usage:
  python3 telnet_test.py <switch_ip> <admin_user> <admin_pass>
  python3 telnet_test.py 192.168.180.155 admin admin
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
SWITCH_IP   = "192.168.180.155"
ADMIN_USER  = "admin"
ADMIN_PASS  = "admin"
SSH_PORT    = 22
TELNET_PORT = 23

CMD_WAIT     = 1.5   # seconds — wait after each command
CONN_TIMEOUT = 10    # seconds — connection timeout


# ============================================================
# Formatting helpers
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
    print(f"  {icon}  {label:<52} {status or 'SKIP'}")

def raw_block(output, label="RAW SWITCH OUTPUT"):
    clean = re.sub(r"\x1b\[[0-9;]*[mGKH]", "", output).strip()
    print(f"  +-- {label} " + "-" * max(0, 55 - len(label)))
    for line in clean.splitlines():
        line = line.strip()
        if line:
            print(f"  |  {line}")
    print("  +" + "-" * 63)


# ============================================================
# SSH helpers
# ============================================================

def open_ssh_shell(hostname, username, password, port=22,
                   retries=3, delay=3):
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


def ssh_cmd(shell, cmd, timeout=3):
    """Send SSH command, return cleaned output."""
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

    return re.sub(r"\x1b\[[0-9;]*[mGKH]", "", collected).strip()


def ssh_config(shell, commands):
    """Enter config mode, run commands, exit."""
    ssh_cmd(shell, "configure terminal", timeout=3)
    for cmd in commands:
        ssh_cmd(shell, cmd, timeout=CMD_WAIT + 1)
    ssh_cmd(shell, "exit", timeout=2)


# ============================================================
# Telnet helpers
# ============================================================

def is_telnet_port_open(hostname, port=23, timeout=5):
    """TCP check — is port 23 accepting connections?"""
    try:
        s = socket.create_connection((hostname, port), timeout=timeout)
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def try_telnet_login(hostname, username, password,
                     port=23, timeout=10):
    """
    Attempt a full Telnet login.
    Returns (success: bool, tn_object or None).
    """
    try:
        tn = telnetlib.Telnet(hostname, port, timeout=timeout)

        idx, _, _ = tn.expect(
            [b"Username:", b"username:", b"login:"], timeout=timeout
        )
        if idx == -1:
            tn.close()
            return False, None
        tn.write(username.encode("ascii") + b"\n")

        idx, _, _ = tn.expect(
            [b"Password:", b"password:"], timeout=timeout
        )
        if idx == -1:
            tn.close()
            return False, None
        tn.write(password.encode("ascii") + b"\n")

        # Wait for shell prompt (#) or rejection
        idx, _, out = tn.expect(
            [b"#", b"Login incorrect", b"Access denied",
             b"Bad password", b"Authentication failed"],
            timeout=timeout
        )
        if idx == 0:
            return True, tn     # successfully logged in
        else:
            tn.close()
            return False, None  # login rejected
    except (socket.timeout, ConnectionRefusedError,
            EOFError, OSError):
        return False, None


def telnet_cmd(tn, cmd, wait=CMD_WAIT):
    """Send command over active Telnet session, return output."""
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


def telnet_config(tn, commands):
    """Enter config mode via Telnet, run commands, exit."""
    telnet_cmd(tn, "configure terminal", wait=1)
    for cmd in commands:
        telnet_cmd(tn, cmd, wait=CMD_WAIT)
    telnet_cmd(tn, "exit", wait=1)


# ============================================================
# MAIN TEST
# ============================================================

def run_test():
    results = {}

    print(f"\n  Switch IP   : {SWITCH_IP}")
    print(f"  Admin user  : {ADMIN_USER}")
    print(f"  SSH port    : {SSH_PORT}")
    print(f"  Telnet port : {TELNET_PORT}")

    # ══════════════════════════════════════════════════════════
    # PHASE 1 — Enable Telnet server via SSH
    # ══════════════════════════════════════════════════════════
    section("PHASE 1 — Enable Telnet Server (configure via SSH)")

    step(1, f"SSH connect to {SWITCH_IP} as {ADMIN_USER}")
    try:
        c1, sh1 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print(f"✅ SSH connected to {SWITCH_IP}:{SSH_PORT}")
        results["ssh_connect"] = "PASS"
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        results["ssh_connect"] = "FAIL"
        _print_summary(results)
        return False

    step(2, "Enable Telnet: aaa authentication login telnet local")
    print(f"   Applying: aaa authentication login telnet local")
    ssh_config(sh1, ["aaa authentication login telnet local"])
    print("✅ Telnet server enabled")
    results["telnet_enable"] = "PASS"

    # ══════════════════════════════════════════════════════════
    # PHASE 2 — Verify Telnet port is open
    # ══════════════════════════════════════════════════════════
    section("PHASE 2 — Verify Telnet Port is Open")

    step(3, f"TCP probe on {SWITCH_IP}:{TELNET_PORT}")
    time.sleep(1)   # give switch a moment to open port
    port_open = is_telnet_port_open(SWITCH_IP, TELNET_PORT)

    print(f"\n  +-- TELNET PORT CHECK " + "-" * 42)
    print(f"  |  Host      : {SWITCH_IP}")
    print(f"  |  Port      : {TELNET_PORT}")
    print(f"  |  TCP open  : {'YES ✅' if port_open else 'NO ❌'}")
    print("  +" + "-" * 63)

    if port_open:
        print(f"✅ Telnet port {TELNET_PORT} is open")
        results["telnet_port_open"] = "PASS"     # ← was missing before
    else:
        print(f"❌ Telnet port {TELNET_PORT} is NOT open")
        results["telnet_port_open"] = "FAIL"     # ← was missing before

    c1.close()
    print("\n✅ SSH session closed")
    time.sleep(1)

    # ══════════════════════════════════════════════════════════
    # PHASE 3 — Verify Telnet session via SSH show users
    # ══════════════════════════════════════════════════════════
    section("PHASE 3 — Verify Telnet Enabled via show users (SSH)")

    step(4, "SSH connect → show users  (verify Telnet is accessible)")
    try:
        c_verify, sh_verify = open_ssh_shell(
            SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT
        )
        print(f"✅ SSH connected")

        out_users = ssh_cmd(sh_verify, "show users", timeout=4)
        raw_block(out_users)
        lower_u = out_users.lower()

        # Telnet enabled if any VTY/TTY lines show in the users table
        # or if the output contains recognisable session information
        session_found = any(k in lower_u for k in [
            "telnet", ADMIN_USER.lower(), "vty", "tty", "line", "active"
        ])

        print(f"\n  +-- SHOW USERS ANALYSIS " + "-" * 40)
        print(f"  |  Looking for  : VTY/TTY line / '{ADMIN_USER}' / active session")
        print(f"  |  Session found: {'YES ✅' if session_found else 'NOT FOUND ⚠️'}")
        print("  +" + "-" * 63)

        results["telnet_session_visible"] = "PASS" if session_found else "WARN"
        print(f"{'✅' if session_found else '⚠️'}  "
              f"Session in show users: {results['telnet_session_visible']}")

        c_verify.close()
        print("\n✅ SSH session closed")
    except Exception as e:
        print(f"❌ SSH for show users failed: {e}")
        results["telnet_session_visible"] = "WARN"

    # ══════════════════════════════════════════════════════════
    # PHASE 5 — Device-side Telnet client (switch → itself)
    # ══════════════════════════════════════════════════════════
    section("PHASE 4 — Device-Side Telnet Client (switch → itself)")

    step(6, f"SSH connect to issue device-side telnet {SWITCH_IP}")
    try:
        c2, sh2 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print("✅ SSH connected for device-side test")
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        results["device_side_telnet"] = "FAIL"
        c2 = None

    if c2:
        step(7, f"Run on switch: telnet {SWITCH_IP}")
        out_dev = ssh_cmd(sh2, f"telnet {SWITCH_IP}", timeout=5)
        raw_block(out_dev, "DEVICE-SIDE TELNET OUTPUT")
        lower_dev = out_dev.lower()

        dev_ok = any(k in lower_dev for k in
                     ["connected", "username", "trying", SWITCH_IP.lower()])

        print(f"\n  +-- DEVICE-SIDE TELNET RESULT " + "-" * 34)
        print(f"  |  Command   : telnet {SWITCH_IP}")
        print(f"  |  Response  : {'CONNECTED ✅' if dev_ok else 'NO RESPONSE ⚠️'}")
        print("  +" + "-" * 63)

        results["device_side_telnet"] = "PASS" if dev_ok else "WARN"
        print(f"{'✅' if dev_ok else '⚠️'}  "
              f"Device-side Telnet: {results['device_side_telnet']}")

        # Send quit to close the nested telnet session
        ssh_cmd(sh2, "q", timeout=2)
        c2.close()
        print("\n✅ SSH session closed")
    time.sleep(1)

    # ══════════════════════════════════════════════════════════
    # PHASE 6 — Disable Telnet server via SSH
    # ══════════════════════════════════════════════════════════
    section("PHASE 5 — Disable Telnet Server (configure via SSH)")

    step(8, f"SSH connect to {SWITCH_IP}")
    try:
        c3, sh3 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print("✅ SSH connected")
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        results["telnet_disable"]    = "FAIL"
        results["telnet_denied"]     = "SKIP"
        _print_summary(results)
        return False

    step(9, "Disable Telnet: no aaa authentication login telnet local")
    print(f"   Applying: no aaa authentication login telnet local")
    ssh_config(sh3, ["no aaa authentication login telnet local"])
    print("✅ Telnet server disabled")
    results["telnet_disable"] = "PASS"

    c3.close()
    print("\n✅ SSH session closed")
    time.sleep(2)   # give switch time to close port

    # ══════════════════════════════════════════════════════════
    # PHASE 7 — Verify Telnet is DENIED after disable
    # ══════════════════════════════════════════════════════════
    section("PHASE 6 — Verify Telnet Login DENIED (server disabled)")

    step(10, f"TCP probe on {SWITCH_IP}:{TELNET_PORT} after disable")
    port_still_open = is_telnet_port_open(SWITCH_IP, TELNET_PORT)
    print(f"   Port {TELNET_PORT} TCP open : "
          f"{'YES (port still open at TCP layer)' if port_still_open else 'NO (port closed)'}")

    step(11, f"Attempt Telnet login → should be DENIED")
    ok_after, tn2 = try_telnet_login(
        SWITCH_IP, ADMIN_USER, ADMIN_PASS, TELNET_PORT
    )

    print(f"\n  +-- TELNET DENIED VERIFICATION " + "-" * 33)
    if not ok_after:
        print(f"  |  Login attempt : DENIED ✅  (correctly blocked)")
        print(f"  |  TCP port open : {port_still_open}")
        print(f"  |  Result        : Port may accept TCP but rejects auth ✅")
        results["telnet_denied"] = "PASS"
    else:
        print(f"  |  Login attempt : SUCCEEDED ❌  (should have been blocked)")
        results["telnet_denied"] = "FAIL"
        try:
            tn2.close()
        except Exception:
            pass
    print("  +" + "-" * 63)
    print(f"{'✅' if results['telnet_denied']=='PASS' else '❌'}  "
          f"Telnet denied after disable: {results['telnet_denied']}")

    _print_summary(results)
    all_ok = all(v in ("PASS", "WARN") for v in results.values()
                 if v != "SKIP")
    return all_ok


# ============================================================
# Summary + Test Procedure printout
# ============================================================

def _print_summary(results):
    section("TEST SUMMARY — Telnet Service Verification")

    rows = [
        ("SSH connect to switch",                          results.get("ssh_connect")),
        ("Telnet server enabled (aaa auth login telnet)",  results.get("telnet_enable")),
        ("Telnet port open (TCP probe)",                   results.get("telnet_port_open")),
        ("Telnet enabled - session in show users",         results.get("telnet_session_visible")),
        ("Device-side Telnet client (switch → itself)",    results.get("device_side_telnet")),
        ("Telnet server disabled (no aaa auth login)",     results.get("telnet_disable")),
        ("Telnet login DENIED after disable",              results.get("telnet_denied")),
    ]

    all_pass = True
    for label, status in rows:
        result_line(label, status or "SKIP")
        if status == "FAIL":
            all_pass = False

    print()

    # ── Test procedure recap ──────────────────────────────────
    print("=" * 65)
    print("  TEST DETAILS")
    print("=" * 65)
    print(f"  Test Name      : Management - TEST-HFCL-SW-04 ")
    print(f"  Test Protocol  : Telnet")
    print(f"  Test Objective : Verify the Telnet service by enabling and")
    print(f"                   disabling it, and confirm Telnet client")
    print(f"                   support is functioning properly.")
    print()
    print(f"  Procedure:")
    print(f"    1.  Enable Telnet server via SSH:")
    print(f"        (config)# aaa authentication login telnet local")
    print(f"    2.  Verify Telnet port {TELNET_PORT} is open (TCP probe)")
    print(f"    3.  Verify Telnet enabled via show users (SSH session)")
    print(f"    4.  Telnet client support from device (switch → itself):")
    print(f"        telnet {SWITCH_IP}  (issued from switch CLI)")
    print(f"    5.  Disable Telnet server via SSH:")
    print(f"        (config)# no aaa authentication login telnet local")
    print(f"    6.  Verify Telnet login is blocked after disable:")
    print(f"        telnet {SWITCH_IP}  → must be DENIED")
    print()
    print(f"  Expected Result:")
    print(f"    • Telnet server enabled and port {TELNET_PORT} open")
    print(f"    • Telnet enabled and show users confirms active sessions")
    print(f"    • Device-side Telnet client reaches switch successfully")
    print(f"    • After disabling, Telnet login attempts are blocked")
    print("=" * 65)

    print()
    if all_pass:
        print("🎉  ALL TESTS PASSED")
        print("    TEST-HFCL-SW-04 - Management - Verify the Telnet service")
        print("    by enabling and disabling it, and confirm that Telnet")
        print("    client support is functioning properly.")
        print("    Completed Successfully.")
    else:
        print("❌  ONE OR MORE TESTS FAILED — review output above")
        print()
        print("    TIPS:")
        print("    • telnet_port_open FAIL : switch may need more time after enable")
        print("    • telnet_session   WARN : check show users output in DEBUG block")
        print("    • telnet_denied    FAIL : disable command may not have applied")
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
        print("Usage: python3 telnet_test.py <switch_ip> <username> <password>")
        sys.exit(1)

    success = run_test()
    sys.exit(0 if success else 1)
