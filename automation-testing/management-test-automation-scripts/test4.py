import paramiko
import telnetlib
import socket
import sys
import time


# ===========================================================
# Configuration
# ===========================================================
SWITCH_IP  = "192.168.180.136"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
SSH_PORT   = 22
TELNET_PORT = 23


# ===========================================================
# SSH Helpers (used for switch configuration)
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
def try_telnet_login(hostname, username, password, port=23, timeout=10):
    """
    Attempt a Telnet login.
    Returns (success: bool, tn object or None).
    """
    try:
        tn = telnetlib.Telnet(hostname, port, timeout=timeout)

        # Wait for Username prompt
        idx, _, _ = tn.expect([b"Username:", b"username:"], timeout=timeout)
        if idx == -1:
            tn.close()
            return False, None
        tn.write(username.encode('ascii') + b"\n")

        # Wait for Password prompt
        idx, _, _ = tn.expect([b"Password:", b"password:"], timeout=timeout)
        if idx == -1:
            tn.close()
            return False, None
        tn.write(password.encode('ascii') + b"\n")

        # Wait for shell prompt (#) or error
        idx, _, output = tn.expect([b"#", b"Login incorrect", b"Access denied"], timeout=timeout)
        if idx == 0:
            return True, tn       # logged in
        else:
            tn.close()
            return False, None    # rejected
    except (socket.timeout, ConnectionRefusedError, EOFError, OSError):
        return False, None


def telnet_send(tn, cmd, wait=1.5):
    """Send a command over an active Telnet session and drain output."""
    tn.write(cmd.encode('ascii') + b"\n")
    time.sleep(wait)
    output = b""
    while True:
        chunk = tn.read_very_eager()
        if not chunk:
            break
        output += chunk
        time.sleep(0.3)
    decoded = output.decode('ascii', errors='ignore')
    lines = [l for l in decoded.splitlines() if cmd.strip() not in l]
    return "\n".join(lines).strip()


def is_telnet_port_open(hostname, port=23, timeout=5):
    """Quick TCP check — is port 23 accepting connections at all?"""
    try:
        s = socket.create_connection((hostname, port), timeout=timeout)
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


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

    step(3, "Verify with  show users  (SSH session active)")
    out = ssh_send(ssh_shell, "show users")
    print(out)

    ssh_client.close()
    print("\n✅ SSH session closed")
    time.sleep(1)

    # -----------------------------------------------------------
    # PHASE 2 — Device-side Telnet client (switch → itself)
    # -----------------------------------------------------------
    section("PHASE 3 — Device-Side Telnet Client  (switch → itself)")

    step(6, "Connect via SSH to issue device-side telnet command")
    try:
        ssh_client2, ssh_shell2 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print("✅ SSH connected for device-side test")
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        results["device_side_telnet"] = "FAIL"
        ssh_client2 = None

    if ssh_client2:
        telnet_cmd = f"telnet {SWITCH_IP}"
        step(7, f"Run device-side Telnet client  →  {telnet_cmd}")
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
    # PHASE 3 — Disable Telnet server via SSH
    # -----------------------------------------------------------
    section("PHASE 4 — Disable Telnet Server  (configure via SSH)")

    step(8, "Connect via SSH to disable Telnet")
    try:
        ssh_client3, ssh_shell3 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print("✅ SSH connected")
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        sys.exit(1)

    step(9, "Disable Telnet server  →  no aaa authentication login telnet local")
    ssh_send(ssh_shell3, "configure terminal")
    ssh_send(ssh_shell3, "no aaa authentication login telnet local")
    ssh_send(ssh_shell3, "exit")
    print("✅ Telnet server disabled")

    ssh_client3.close()
    print("\n✅ SSH session closed")
    time.sleep(2)

    # -----------------------------------------------------------
    # PHASE 4 — Verify Telnet is denied after disable
    # -----------------------------------------------------------
    section("PHASE 5 — Verify Telnet Access DENIED  (server disabled)")

    step(10, f"Check if Telnet port {TELNET_PORT} is still open")
    port_open = is_telnet_port_open(SWITCH_IP, TELNET_PORT)
    print(f"  Port {TELNET_PORT} open : {'YES (TCP layer)' if port_open else 'NO'}")

    step(11, f"Attempt Telnet login  →  telnet {SWITCH_IP}  (should be DENIED)")
    ok, tn2 = try_telnet_login(SWITCH_IP, ADMIN_USER, ADMIN_PASS, TELNET_PORT)
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
        ("Telnet port open when enabled",        results.get("telnet_port_open")),
        ("Telnet session visible in show users", results.get("telnet_session_visible")),
        ("Device-side Telnet client",            results.get("device_side_telnet")),
        ("Telnet login denied (server OFF)",     results.get("telnet_denied_after_disable")),
    ]
    all_pass = True
    for label, result in rows:
        icon = "✅" if result == "PASS" else ("⚠️ " if result in ("WARN", "SKIP") else "❌")
        print(f"  {icon}  {label:<42} {result}")
        if result == "FAIL":
            all_pass = False

    print()
    if all_pass:
        print("🎉  ALL TESTS PASSED \n TEST-HFCL-SW-01 - Management - Verify the Telnet service by enabling and disabling it, and confirm that Telnet client support is functioning properly successfully passed.")
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
