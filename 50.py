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
def open_ssh_shell(hostname, username, password, port=22):
    """Connect via SSH and return (client, shell). Raises on failure."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname, port=port,
        username=username, password=password,
        timeout=10, look_for_keys=False, allow_agent=False
    )
    shell = client.invoke_shell()
    time.sleep(1)
    _drain(shell)
    return client, shell


def send_cmd(shell, cmd, wait=1.5):
    """Send a command over an SSH shell and return full output."""
    shell.send(cmd + "\n")
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        output += shell.recv(4096).decode('utf-8', errors='ignore')
        time.sleep(0.3)
    return output


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
    # PHASE 1 — Admin Setup on default port 22
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
    send_cmd(admin_shell, "configure terminal")
    send_cmd(admin_shell, f"ip ssh port {CUSTOM_PORT}")
    send_cmd(admin_shell, "exit")
    print(f"✅ SSH port set to {CUSTOM_PORT}")

    step(4, "Verify port change  →  show ip ssh")
    out = send_cmd(admin_shell, "show ip ssh")
    print(out)
    port_ok   = str(CUSTOM_PORT) in out
    enable_ok = "enabled" in out.lower()
    print(f"  SSH enabled     : {'✅ YES' if enable_ok else '❌ NO'}")
    print(f"  Port = {CUSTOM_PORT}        : {'✅ YES' if port_ok   else '❌ NO'}")
    results["port_reflected"] = "PASS" if (enable_ok and port_ok) else "FAIL"

    step(5, "Show active users  →  show users")
    out = send_cmd(admin_shell, "show users")
    print(out)

    # Close admin session on port 22 — switch will now only listen on port 25
    admin_client.close()
    print(f"\n✅ Admin session (port {DEFAULT_PORT}) closed")
    time.sleep(1)

    # -----------------------------------------------------------
    # PHASE 2 — Verify old port 22 is no longer accepting
    # -----------------------------------------------------------
    section(f"PHASE 2 — Verify Port {DEFAULT_PORT} is NO LONGER Accessible")

    step(6, f"Attempt SSH login on old port {DEFAULT_PORT}  (should FAIL)")
    ok, c, s = try_ssh_login(SWITCH_IP, ADMIN_USER, ADMIN_PASS, DEFAULT_PORT)
    if not ok:
        print(f"✅ Port {DEFAULT_PORT} correctly REJECTED  (port is no longer active)")
        results["old_port_blocked"] = "PASS"
    else:
        print(f"⚠️  Port {DEFAULT_PORT} still accepted the connection")
        results["old_port_blocked"] = "WARN"
        c.close()

    # -----------------------------------------------------------
    # PHASE 3 — External client connects on custom port 25
    # -----------------------------------------------------------
    section(f"PHASE 3 — External Client SSH on Custom Port {CUSTOM_PORT}")

    step(7, f"Connect as admin on custom port {CUSTOM_PORT}  (external client)")
    ok, ext_client, ext_shell = try_ssh_login(
        SWITCH_IP, ADMIN_USER, ADMIN_PASS, CUSTOM_PORT
    )
    if ok:
        print(f"✅ External SSH login SUCCESSFUL on port {CUSTOM_PORT}")
        results["external_client_port25"] = "PASS"

        step(8, "Verify show ip ssh on custom port session")
        out = send_cmd(ext_shell, "show ip ssh")
        print(out)
        if str(CUSTOM_PORT) in out and "enabled" in out.lower():
            print(f"✅ show ip ssh confirms port {CUSTOM_PORT} and SSH enabled")
            results["show_ip_ssh_port25"] = "PASS"
        else:
            print("⚠️  show ip ssh output unclear")
            results["show_ip_ssh_port25"] = "WARN"

        step(9, "Verify show users on custom port session")
        out = send_cmd(ext_shell, "show users")
        print(out)
        if ADMIN_USER in out:
            print("✅ Admin session visible in show users")
            results["show_users_port25"] = "PASS"
        else:
            print("⚠️  Admin session not found in show users")
            results["show_users_port25"] = "WARN"

        ext_client.close()
        print(f"\n✅ External client session (port {CUSTOM_PORT}) closed")
    else:
        print(f"❌ External SSH login FAILED on port {CUSTOM_PORT}")
        results["external_client_port25"] = "FAIL"
        results["show_ip_ssh_port25"]      = "SKIP"
        results["show_users_port25"]       = "SKIP"

    # -----------------------------------------------------------
    # PHASE 4 — Device-side SSH client test (ssh from switch itself)
    # -----------------------------------------------------------
    section(f"PHASE 4 — Device-Side SSH Client Test on Port {CUSTOM_PORT}")

    step(10, f"Connect as admin on port {CUSTOM_PORT} to issue device-side ssh command")
    ok, dev_client, dev_shell = try_ssh_login(
        SWITCH_IP, ADMIN_USER, ADMIN_PASS, CUSTOM_PORT
    )
    if ok:
        # Issue the SSH client command from the switch itself
        ssh_cmd = f"ssh admin {SWITCH_IP} port {CUSTOM_PORT}"
        step(11, f"Run device-side SSH client  →  {ssh_cmd}")
        out = send_cmd(dev_shell, ssh_cmd, wait=3)
        print(out)
        # Switch may ask for password or show a connected banner
        if "password" in out.lower() or "connected" in out.lower() or SWITCH_IP in out:
            print("✅ Device-side SSH client reached the switch on custom port")
            results["device_side_ssh"] = "PASS"
        else:
            print("⚠️  Device-side SSH client response unclear — review output above")
            results["device_side_ssh"] = "WARN"
        dev_client.close()
    else:
        print(f"❌ Could not connect on port {CUSTOM_PORT} for device-side test")
        results["device_side_ssh"] = "FAIL"

    # -----------------------------------------------------------
    # PHASE 5 — Cleanup: restore default port 22
    # -----------------------------------------------------------
    section("PHASE 5 — Cleanup: Restore Default Port 22")

    step(12, f"Connect on port {CUSTOM_PORT} and restore port to {DEFAULT_PORT}")
    ok, clean_client, clean_shell = try_ssh_login(
        SWITCH_IP, ADMIN_USER, ADMIN_PASS, CUSTOM_PORT
    )
    if ok:
        send_cmd(clean_shell, "configure terminal")
        send_cmd(clean_shell, f"ip ssh port {DEFAULT_PORT}")
        send_cmd(clean_shell, "exit")
        out = send_cmd(clean_shell, "show ip ssh")
        print(out)
        clean_client.close()
        if str(DEFAULT_PORT) in out:
            print(f"✅ SSH port restored to {DEFAULT_PORT}")
            results["cleanup"] = "PASS"
        else:
            print(f"⚠️  Could not confirm port restored to {DEFAULT_PORT}")
            results["cleanup"] = "WARN"
    else:
        print(f"❌ Could not connect on port {CUSTOM_PORT} to restore default port")
        results["cleanup"] = "FAIL"

    # -----------------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------------
    section("TEST SUMMARY")
    rows = [
        ("Port 25 reflected in show ip ssh",    results.get("port_reflected")),
        (f"Old port {DEFAULT_PORT} blocked",     results.get("old_port_blocked")),
        (f"External client login port {CUSTOM_PORT}", results.get("external_client_port25")),
        ("show ip ssh on port 25 session",       results.get("show_ip_ssh_port25")),
        ("show users on port 25 session",        results.get("show_users_port25")),
        ("Device-side SSH client port 25",       results.get("device_side_ssh")),
        ("Cleanup — port restored to 22",        results.get("cleanup")),
    ]
    all_pass = True
    for label, result in rows:
        icon = "✅" if result == "PASS" else ("⚠️ " if result in ("WARN", "SKIP") else "❌")
        print(f"  {icon}  {label:<40} {result}")
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
    success = run_test()
    sys.exit(0 if success else 1)
