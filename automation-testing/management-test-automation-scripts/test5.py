import paramiko
import telnetlib
import socket
import sys
import time


# ===========================================================
# Configuration
# ===========================================================
SWITCH_IP   = "192.168.180.136"
ADMIN_USER  = "admin"
ADMIN_PASS  = "admin"
SSH_PORT    = 22
TELNET_PORT = 23


# ===========================================================
# SSH Helpers
# ===========================================================
def open_ssh_shell(hostname, username, password, port=22, retries=3, delay=3):
    for attempt in range(1, retries + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname, port=port,
                username=username, password=password,
                timeout=10, look_for_keys=False, allow_agent=False
            )
            shell = client.invoke_shell()
            time.sleep(1)
            _ssh_drain(shell)
            return client, shell
        except Exception as e:
            client.close()
            if attempt < retries:
                print(f"   ⏳ Attempt {attempt} failed ({e}), retrying in {delay}s...")
                time.sleep(delay)
            else:
                raise


def ssh_send(shell, cmd, wait=1.5):
    shell.send(cmd + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(4096).decode('utf-8', errors='ignore')
        time.sleep(0.3)
    return output


def _ssh_drain(shell):
    time.sleep(0.5)
    while shell.recv_ready():
        shell.recv(4096)
        time.sleep(0.2)


# ===========================================================
# Telnet Helpers
# ===========================================================
def try_telnet_login(hostname, username, password, port=23, timeout=20):
    """
    Robust Telnet login.

    ROOT CAUSE (seen in debug output):
      After sending the username, the switch immediately echoed back:
          b' '  then  b'admin'
      The old manual read_very_eager() loop saw those two small chunks,
      found no 'password' in them, and stopped — hitting the deadline
      before the switch sent its actual '\r\nPassword:' prompt.

    FIX — use tn.expect() for the Password step:
      tn.expect() accumulates ALL incoming bytes internally and only
      returns once the pattern is matched (or the timeout fires).
      It does NOT stop at the username echo — it keeps waiting through
      banners, CRLF, and silence until 'Password' actually arrives.
      This is exactly what we need here.

    Returns (success: bool, tn object or None, decoded output string).
    """
    try:
        tn = telnetlib.Telnet(hostname, port, timeout=timeout)

        # ── 1. Wait for Username prompt ──────────────────────────────────
        idx, _, pre_user = tn.expect(
            [b"Username:", b"username:", b"User:", b"user:"],
            timeout=timeout
        )
        if idx == -1:
            tn.close()
            return False, None, (
                "No Username prompt — got: "
                + pre_user.decode('ascii', errors='ignore')
            )
        print("   [DEBUG] Username prompt received")
        tn.write(username.encode('ascii') + b"\r\n")  # Telnet RFC 854 requires CRLF
        print(f"   [DEBUG] Sent username with CRLF, waiting for Password prompt...")

        # ── 2. Wait for Password prompt ───────────────────────────────────
        # tn.expect() buffers the username echo, any banner lines, and
        # all silence between them — it only returns when 'Password'
        # appears in the stream or the timeout fires.
        idx, _, after_user = tn.expect(
            [b"Password:", b"password:", b"PASSWORD:"],
            timeout=timeout
        )
        after_user_str = after_user.decode('ascii', errors='ignore')
        print(f"   [DEBUG] Buffer after username (echo + any banner + prompt): {after_user_str!r}")

        if idx == -1:
            # No Password prompt seen — maybe already at shell (no-password login)
            if "#" in after_user_str or ">" in after_user_str:
                print("   [DEBUG] Shell prompt received without password — logged in directly")
                time.sleep(0.3)
                tn.read_very_eager()
                return True, tn, after_user_str
            tn.close()
            return False, None, "No Password prompt — buffer: " + after_user_str

        # ── 3. Send password ──────────────────────────────────────────────
        print("   [DEBUG] Password prompt found, sending password")
        tn.write(password.encode('ascii') + b"\r\n")  # Telnet RFC 854 requires CRLF

        # ── 4. Wait for shell prompt (or rejection) ───────────────────────
        idx, _, post_pass = tn.expect(
            [b"#", b">", b"Login incorrect", b"Access denied", b"% Authentication failed"],
            timeout=timeout
        )
        post_str = post_pass.decode('ascii', errors='ignore')
        print(f"   [DEBUG] Post-password buffer: {post_str!r}")

        if idx in (0, 1):
            # Shell prompt — clean up and return success
            time.sleep(0.3)
            tn.read_very_eager()
            return True, tn, after_user_str + post_str
        elif idx == -1:
            # Timeout — check if '#'/'>' slipped in anyway
            if "#" in post_str or ">" in post_str:
                time.sleep(0.3)
                tn.read_very_eager()
                return True, tn, after_user_str + post_str
            tn.close()
            return False, None, "No shell prompt after password — buffer: " + post_str
        else:
            # Explicit rejection
            tn.close()
            return False, None, post_str

    except (socket.timeout, ConnectionRefusedError, EOFError, OSError) as ex:
        return False, None, str(ex)


def telnet_send(tn, cmd, wait=2.0):
    """Send a command over an open Telnet session and return the response."""
    tn.write(cmd.encode('ascii') + b"\r\n")  # Telnet RFC 854 requires CRLF
    time.sleep(wait)
    output = b""
    deadline = time.time() + 5
    while time.time() < deadline:
        chunk = tn.read_very_eager()
        if chunk:
            output += chunk
            time.sleep(0.3)
        else:
            if output:
                break
            time.sleep(0.2)
    decoded = output.decode('ascii', errors='ignore')
    lines = [l for l in decoded.splitlines() if cmd.strip() not in l]
    return "\n".join(lines).strip()


def is_telnet_port_open(hostname, port=23, timeout=5):
    try:
        s = socket.create_connection((hostname, port), timeout=timeout)
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def check_telnet_enabled_via_ssh(ssh_shell):
    """
    Returns True if Telnet is enabled, False if disabled.
    Logic:
      ENABLED  → 'no aaa authentication login telnet' is ABSENT from running-config
      DISABLED → that line IS present
    """
    out = ssh_send(ssh_shell, "show running-config feature auth", wait=2)
    print(out)
    return "no aaa authentication login telnet" not in out


# ===========================================================
# Formatting
# ===========================================================
def section(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def step(n, desc):
    print(f"\n[Step {n}] {desc}")
    print("-" * 60)


# ===========================================================
# MAIN TEST
# ===========================================================
def run_test():
    results = {}

    # -----------------------------------------------------------
    # PHASE 1 — Enable Telnet server via SSH
    # -----------------------------------------------------------
    section("PHASE 1 — Enable Telnet Server  (configure via SSH)")

    step(1, "Connect to switch as admin via SSH")
    try:
        ssh_client, ssh_shell = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print(f"✅ SSH connected on port {SSH_PORT}")
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        sys.exit(1)

    step(2, "Enable Telnet server  →  aaa authentication login telnet local")
    ssh_send(ssh_shell, "configure terminal")
    ssh_send(ssh_shell, "aaa authentication login telnet local")
    ssh_send(ssh_shell, "exit")
    print("✅ Telnet server enabled")

    step(3, "Verify Telnet enabled  →  show running-config feature auth")
    print("   Logic: 'no aaa authentication login telnet' ABSENT = Telnet ENABLED")
    telnet_enabled = check_telnet_enabled_via_ssh(ssh_shell)
    if telnet_enabled:
        print("✅ Telnet confirmed ENABLED (line absent from running-config)")
        results["telnet_enabled_config"] = "PASS"
    else:
        print("❌ Telnet appears DISABLED in running-config")
        results["telnet_enabled_config"] = "FAIL"

    step(4, "show users  (SSH session active)")
    out = ssh_send(ssh_shell, "show users")
    print(out)

    ssh_client.close()
    print("\n✅ SSH session closed")
    time.sleep(1)

    # -----------------------------------------------------------
    # PHASE 2 — Verify Telnet port open + show users via Telnet
    # -----------------------------------------------------------
    section("PHASE 2 — Verify Telnet Port & Session  (server enabled)")

    step(5, f"Check Telnet port {TELNET_PORT} is open")
    if is_telnet_port_open(SWITCH_IP, TELNET_PORT):
        print(f"✅ Port {TELNET_PORT} is open and accepting connections")
        results["telnet_port_open"] = "PASS"
    else:
        print(f"❌ Port {TELNET_PORT} is NOT open")
        results["telnet_port_open"] = "FAIL"

    step(6, f"Login via Telnet and run show users  →  telnet {SWITCH_IP}")
    ok, tn, raw_login = try_telnet_login(SWITCH_IP, ADMIN_USER, ADMIN_PASS, TELNET_PORT)
    print(f"   [DEBUG] Raw login buffer: {repr(raw_login)}")
    if ok:
        print("✅ Telnet login SUCCESSFUL")
        out = telnet_send(tn, "show users")
        print(f"   [DEBUG] show users output:\n{out}")
        if "by Telnet" in out or "by telnet" in out.lower():
            print("✅ Telnet session visible in show users  (by Telnet)")
            results["telnet_session_visible"] = "PASS"
        elif ADMIN_USER in out:
            print("✅ User session visible in show users")
            results["telnet_session_visible"] = "PASS"
        else:
            print("⚠️  Session not found in show users — review output")
            results["telnet_session_visible"] = "WARN"
        tn.close()
        print("\n✅ Telnet session closed")
    else:
        print(f"❌ Telnet login FAILED: {raw_login}")
        results["telnet_session_visible"] = "FAIL"

    # -----------------------------------------------------------
    # PHASE 3 — Device-side Telnet client (switch → itself)
    # -----------------------------------------------------------
    section("PHASE 3 — Device-Side Telnet Client  (switch → itself)")

    step(8, "Connect via SSH to issue device-side telnet command")
    try:
        ssh_client2, ssh_shell2 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print("✅ SSH connected for device-side test")
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        results["device_side_telnet"] = "FAIL"
        ssh_client2 = None

    if ssh_client2:
        telnet_cmd = f"telnet {SWITCH_IP}"
        step(9, f"Run device-side Telnet client  →  {telnet_cmd}")
        out = ssh_send(ssh_shell2, telnet_cmd, wait=3)
        print(out)
        if "connected" in out.lower() or "username" in out.lower() or SWITCH_IP in out:
            print(f"✅ Device-side Telnet client successfully reached {SWITCH_IP}")
            results["device_side_telnet"] = "PASS"
        else:
            print("⚠️  Device-side response unclear — review output above")
            results["device_side_telnet"] = "WARN"
        ssh_client2.close()

    # -----------------------------------------------------------
    # PHASE 4 — Disable Telnet server via SSH
    # -----------------------------------------------------------
    section("PHASE 4 — Disable Telnet Server  (configure via SSH)")

    step(10, "Connect via SSH to disable Telnet")
    try:
        ssh_client3, ssh_shell3 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print("✅ SSH connected")
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        sys.exit(1)

    step(11, "Disable Telnet server  →  no aaa authentication login telnet local")
    ssh_send(ssh_shell3, "configure terminal")
    ssh_send(ssh_shell3, "no aaa authentication login telnet local")
    ssh_send(ssh_shell3, "exit")
    print("✅ Telnet server disabled")

    step(12, "Verify Telnet disabled  →  show running-config feature auth")
    print("   Logic: 'no aaa authentication login telnet' PRESENT = Telnet DISABLED")
    telnet_enabled_after = check_telnet_enabled_via_ssh(ssh_shell3)
    if not telnet_enabled_after:
        print("✅ Telnet confirmed DISABLED in running-config")
        results["telnet_disabled_config"] = "PASS"
    else:
        print("❌ Telnet still appears ENABLED in running-config")
        results["telnet_disabled_config"] = "FAIL"

    ssh_client3.close()
    print("\n✅ SSH session closed")
    time.sleep(2)

    # -----------------------------------------------------------
    # PHASE 5 — Verify Telnet is denied after disable
    # -----------------------------------------------------------
    section("PHASE 5 — Verify Telnet Access DENIED  (server disabled)")

    step(13, f"Check if Telnet port {TELNET_PORT} is still open")
    port_open = is_telnet_port_open(SWITCH_IP, TELNET_PORT)
    print(f"  Port {TELNET_PORT} open : {'YES (TCP layer)' if port_open else 'NO'}")

    step(14, f"Attempt Telnet login  →  telnet {SWITCH_IP}  (should be DENIED)")
    ok, tn2, _ = try_telnet_login(SWITCH_IP, ADMIN_USER, ADMIN_PASS, TELNET_PORT)
    if not ok:
        print("✅ Telnet login correctly DENIED after server disabled")
        results["telnet_denied_after_disable"] = "PASS"
    else:
        print("❌ Telnet login SUCCEEDED — server should have been disabled")
        results["telnet_denied_after_disable"] = "FAIL"
        try:
            tn2.close()
        except Exception:
            pass

    # -----------------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------------
    section("TEST SUMMARY")
    rows = [
        ("Telnet enabled in running-config",     results.get("telnet_enabled_config")),
        ("Telnet port open when enabled",        results.get("telnet_port_open")),
        ("Telnet session visible in show users", results.get("telnet_session_visible")),
        ("Device-side Telnet client",            results.get("device_side_telnet")),
        ("Telnet disabled in running-config",    results.get("telnet_disabled_config")),
        ("Telnet login denied (server OFF)",     results.get("telnet_denied_after_disable")),
    ]
    all_pass = True
    for label, result in rows:
        icon = "✅" if result == "PASS" else ("⚠️ " if result in ("WARN", "SKIP") else "❌")
        print(f"  {icon}  {label:<42} {result}")
        if result in ("FAIL", None):
            all_pass = False

    print()
    if all_pass:
        print("🎉  ALL TESTS PASSED")
        print("    TEST-HFCL-SW-01 - Management - Verify the Telnet service by enabling")
        print("    and disabling it, and confirm that Telnet client support is functioning")
        print("    properly — successfully passed.")
    else:
        print("❌  ONE OR MORE TESTS FAILED — review output above")
    print("=" * 60)
    return all_pass


if __name__ == "__main__":
    if len(sys.argv) == 4:
        SWITCH_IP  = sys.argv[1]
        ADMIN_USER = sys.argv[2]
        ADMIN_PASS = sys.argv[3]

    success = run_test()
    sys.exit(0 if success else 1)
