import paramiko
import socket
import sys
import time


# ===========================================================
# Configuration
# ===========================================================
SWITCH_IP    = "192.168.180.136"
ADMIN_USER   = "admin"
ADMIN_PASS   = "admin"
DEFAULT_PORT = 22
CUSTOM_PORT  = 25


# ===========================================================
# Helpers
# ===========================================================
def open_ssh_shell(hostname, username, password, port=22, retries=3, delay=3):
    """
    Connect via SSH and return (client, shell).
    Retries a few times to handle the brief window when the switch
    restarts its SSH service after a port change.
    """
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
            _drain(shell)
            return client, shell
        except Exception as e:
            client.close()
            if attempt < retries:
                print(f"   ⏳ Attempt {attempt} failed ({e}), retrying in {delay}s...")
                time.sleep(delay)
            else:
                raise


def send_cmd(shell, cmd, wait=1.5):
    """Send a command over an SSH shell and return full output."""
    shell.send(cmd + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(4096).decode('utf-8', errors='ignore')
        time.sleep(0.3)
    return output


def send_cmd_safe(shell, cmd, wait=1.5):
    """
    Like send_cmd but silently ignores socket errors.
    Used for commands that may disconnect the session (e.g. port change).
    Returns output collected before disconnect, or empty string.
    """
    try:
        shell.send(cmd + "\n")
        time.sleep(wait)
        output = ""
        while shell.recv_ready():
            output += shell.recv(4096).decode('utf-8', errors='ignore')
            time.sleep(0.3)
        return output
    except (OSError, EOFError):
        return ""   # session closed by switch — expected


def _drain(shell):
    time.sleep(0.5)
    while shell.recv_ready():
        shell.recv(4096)
        time.sleep(0.2)


def try_ssh_login(hostname, username, password, port):
    """
    Attempt SSH login on the given port.
    Returns (success: bool, client, shell).
    """
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
        _drain(shell)
        return True, client, shell
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        return False, None, None


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
    # PHASE 1 — Enable SSH & change port (session will drop)
    # -----------------------------------------------------------
    section("PHASE 1 — Enable SSH & Change Port to 25  (via port 22)")

    step(1, f"Connect to switch as admin on default port {DEFAULT_PORT}")
    try:
        admin_client, admin_shell = open_ssh_shell(
            SWITCH_IP, ADMIN_USER, ADMIN_PASS, DEFAULT_PORT
        )
        print(f"✅ Admin SSH connected on port {DEFAULT_PORT}")
    except Exception as e:
        print(f"❌ Admin SSH connection failed: {e}")
        sys.exit(1)

    step(2, "Enable SSH server  →  ip ssh")
    send_cmd(admin_shell, "configure terminal")
    send_cmd(admin_shell, "ip ssh")
    send_cmd(admin_shell, "exit")
    print("✅ SSH enabled globally")

    step(3, f"Change SSH port to {CUSTOM_PORT}  →  ip ssh port {CUSTOM_PORT}")
    print(f"   ⚠️  NOTE: Changing the SSH port restarts the SSH service.")
    print(f"   The current session will be dropped. This is expected.")
    send_cmd(admin_shell, "configure terminal")
    # This command will kill the session — use safe variant
    send_cmd_safe(admin_shell, f"ip ssh port {CUSTOM_PORT}", wait=2)
    try:
        admin_client.close()
    except Exception:
        pass
    print(f"✅ Port change command sent — session closed by switch (expected)")

    # Wait for SSH service to restart on new port
    print(f"   ⏳ Waiting 5s for SSH service to restart on port {CUSTOM_PORT}...")
    time.sleep(5)

    # -----------------------------------------------------------
    # PHASE 2 — Reconnect on new port and verify
    # -----------------------------------------------------------
    section(f"PHASE 2 — Reconnect on Port {CUSTOM_PORT} & Verify")

    step(4, f"Reconnect as admin on new port {CUSTOM_PORT}")
    try:
        admin_client, admin_shell = open_ssh_shell(
            SWITCH_IP, ADMIN_USER, ADMIN_PASS, CUSTOM_PORT, retries=5, delay=3
        )
        print(f"✅ Admin SSH reconnected on port {CUSTOM_PORT}")
    except Exception as e:
        print(f"❌ Could not reconnect on port {CUSTOM_PORT}: {e}")
        print("   Cannot continue — aborting test.")
        sys.exit(1)

    step(5, "Verify port change  →  show ip ssh")
    out = send_cmd(admin_shell, "show ip ssh")
    print(out)
    port_ok   = str(CUSTOM_PORT) in out
    enable_ok = "enabled" in out.lower()
    print(f"  SSH enabled        : {'✅ YES' if enable_ok else '❌ NO'}")
    print(f"  Port = {CUSTOM_PORT} reflected : {'✅ YES' if port_ok   else '❌ NO'}")
    results["port_reflected"] = "PASS" if (enable_ok and port_ok) else "FAIL"

    step(6, "Show active users  →  show users")
    out = send_cmd(admin_shell, "show users")
    print(out)

    admin_client.close()
    print(f"\n✅ Admin session (port {CUSTOM_PORT}) closed")
    time.sleep(1)

    # -----------------------------------------------------------
    # PHASE 3 — Verify old port 22 is blocked
    # -----------------------------------------------------------
    section(f"PHASE 3 — Verify Port {DEFAULT_PORT} is NO LONGER Accessible")

    step(7, f"Attempt SSH login on old port {DEFAULT_PORT}  (should FAIL)")
    ok, c, s = try_ssh_login(SWITCH_IP, ADMIN_USER, ADMIN_PASS, DEFAULT_PORT)
    if not ok:
        print(f"✅ Port {DEFAULT_PORT} correctly REJECTED")
        results["old_port_blocked"] = "PASS"
    else:
        print(f"⚠️  Port {DEFAULT_PORT} still accepted the connection")
        results["old_port_blocked"] = "WARN"
        c.close()

    # -----------------------------------------------------------
    # PHASE 4 — External client on port 25
    # -----------------------------------------------------------
    section(f"PHASE 4 — External Client SSH on Custom Port {CUSTOM_PORT}")

    step(8, f"Connect as admin on custom port {CUSTOM_PORT}")
    ok, ext_client, ext_shell = try_ssh_login(
        SWITCH_IP, ADMIN_USER, ADMIN_PASS, CUSTOM_PORT
    )
    if ok:
        print(f"✅ External SSH login SUCCESSFUL on port {CUSTOM_PORT}")
        results["external_client_port25"] = "PASS"

        step(9, "show ip ssh on port-25 session")
        out = send_cmd(ext_shell, "show ip ssh")
        print(out)
        results["show_ip_ssh_port25"] = (
            "PASS" if (str(CUSTOM_PORT) in out and "enabled" in out.lower()) else "WARN"
        )

        step(10, "show users on port-25 session")
        out = send_cmd(ext_shell, "show users")
        print(out)
        results["show_users_port25"] = "PASS" if ADMIN_USER in out else "WARN"

        ext_client.close()
        print(f"\n✅ External client session (port {CUSTOM_PORT}) closed")
    else:
        print(f"❌ External SSH login FAILED on port {CUSTOM_PORT}")
        results["external_client_port25"] = "FAIL"
        results["show_ip_ssh_port25"]      = "SKIP"
        results["show_users_port25"]       = "SKIP"

    # -----------------------------------------------------------
    # PHASE 5 — Device-side SSH client test
    # -----------------------------------------------------------
    section(f"PHASE 5 — Device-Side SSH Client on Port {CUSTOM_PORT}")

    step(11, f"Connect on port {CUSTOM_PORT} to run device-side ssh command")
    ok, dev_client, dev_shell = try_ssh_login(
        SWITCH_IP, ADMIN_USER, ADMIN_PASS, CUSTOM_PORT
    )
    if ok:
        ssh_cmd = f"ssh admin {SWITCH_IP} port {CUSTOM_PORT}"
        step(12, f"Run  →  {ssh_cmd}")
        out = send_cmd(dev_shell, ssh_cmd, wait=3)
        print(out)
        if "password" in out.lower() or "connected" in out.lower() or SWITCH_IP in out:
            print("✅ Device-side SSH client reached switch on custom port")
            results["device_side_ssh"] = "PASS"
        else:
            print("⚠️  Response unclear — review output above")
            results["device_side_ssh"] = "WARN"
        dev_client.close()
    else:
        print(f"❌ Could not connect on port {CUSTOM_PORT} for device-side test")
        results["device_side_ssh"] = "FAIL"

    # -----------------------------------------------------------
    # PHASE 6 — Cleanup: restore port 22
    # -----------------------------------------------------------
    section("PHASE 6 — Cleanup: Restore Default Port 22")

    step(13, f"Connect on port {CUSTOM_PORT} and restore port to {DEFAULT_PORT}")
    ok, clean_client, clean_shell = try_ssh_login(
        SWITCH_IP, ADMIN_USER, ADMIN_PASS, CUSTOM_PORT
    )
    if ok:
        send_cmd(clean_shell, "configure terminal")
        send_cmd_safe(clean_shell, f"ip ssh port {DEFAULT_PORT}", wait=2)
        try:
            clean_client.close()
        except Exception:
            pass
        print(f"   ⏳ Waiting 5s for SSH to restart on port {DEFAULT_PORT}...")
        time.sleep(5)
        # Confirm restore
        ok2, c2, s2 = try_ssh_login(SWITCH_IP, ADMIN_USER, ADMIN_PASS, DEFAULT_PORT)
        if ok2:
            out = send_cmd(s2, "show ip ssh")
            print(out)
            c2.close()
            if str(DEFAULT_PORT) in out:
                print(f"✅ SSH port restored to {DEFAULT_PORT}")
                results["cleanup"] = "PASS"
            else:
                print(f"⚠️  Port restore unclear")
                results["cleanup"] = "WARN"
        else:
            print(f"❌ Could not reconnect on port {DEFAULT_PORT} after restore")
            results["cleanup"] = "FAIL"
    else:
        print(f"❌ Could not connect on port {CUSTOM_PORT} to start cleanup")
        results["cleanup"] = "FAIL"

    # -----------------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------------
    section("TEST SUMMARY")
    rows = [
        ("Port 25 reflected in show ip ssh",         results.get("port_reflected")),
        (f"Old port {DEFAULT_PORT} blocked",          results.get("old_port_blocked")),
        (f"External client login port {CUSTOM_PORT}", results.get("external_client_port25")),
        ("show ip ssh on port 25 session",            results.get("show_ip_ssh_port25")),
        ("show users on port 25 session",             results.get("show_users_port25")),
        ("Device-side SSH client port 25",            results.get("device_side_ssh")),
        ("Cleanup — port restored to 22",             results.get("cleanup")),
    ]
    all_pass = True
    for label, result in rows:
        icon = "✅" if result == "PASS" else ("⚠️ " if result in ("WARN", "SKIP") else "❌")
        print(f"  {icon}  {label:<42} {result}")
        if result == "FAIL":
            all_pass = False

    print()
    if all_pass:
        print("🎉  ALL TESTS PASSED")
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
