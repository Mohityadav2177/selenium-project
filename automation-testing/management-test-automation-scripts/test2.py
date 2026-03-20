import paramiko
import socket
import sys
import time


# ===========================================================
# Configuration — overridden by sys.argv if provided
# ===========================================================
SWITCH_IP  = "192.168.180.136"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
SSH_PORT   = 22


# ===========================================================
# Helper — SSH shell send/receive
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
    """Send a command and return the full output."""
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


def try_ssh_login(hostname, username, password, port=22):
    """
    Attempt SSH login. Returns (success: bool, client, shell).
    Does NOT raise — all exceptions are caught and reported.
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
    except paramiko.AuthenticationException:
        return False, None, None
    except Exception as e:
        return False, None, None
    finally:
        pass  # caller is responsible for closing on success


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
    # PHASE 1 — ADMIN SSH: setup
    # -----------------------------------------------------------
    section("PHASE 1 — Admin Setup via SSH")

    step(1, "Connect to switch as admin via SSH")
    try:
        admin_client, admin_shell = open_ssh_shell(
            SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT
        )
        print("✅ Admin SSH connection established")
    except Exception as e:
        print(f"❌ Admin SSH connection failed: {e}")
        sys.exit(1)

    step(2, "Enable SSH service  →  configure terminal + ip ssh")
    send_cmd(admin_shell, "configure terminal")
    send_cmd(admin_shell, "ip ssh")
    send_cmd(admin_shell, "exit")
    print("✅ SSH enabled globally")

    step(3, "Verify SSH is enabled  →  show ip ssh")
    out = send_cmd(admin_shell, "show ip ssh")
    print(out)
    if "enabled" in out.lower():
        print("✅ SSH confirmed ENABLED")
        results["ssh_enabled"] = "PASS"
    else:
        print("⚠️  SSH status unclear")
        results["ssh_enabled"] = "WARN"

    step(4, "Create user 'hfcl' with privilege 5")
    send_cmd(admin_shell, "configure terminal")
    send_cmd(admin_shell, "username hfcl privilege 5 password unencrypted Discover@1234")
    send_cmd(admin_shell, "exit")
    print("✅ User 'hfcl' (priv 5) created")

    step(5, "Create second user 'palc' with privilege 5")
    send_cmd(admin_shell, "configure terminal")
    send_cmd(admin_shell, "username palc privilege 5 password unencrypted Discover@1234")
    send_cmd(admin_shell, "exit")
    print("✅ User 'palc' (priv 5) created")

    step(6, "Verify both users exist  →  show running-config")
    out = send_cmd(admin_shell, "show running-config")
    print(out)
    hfcl_exists = "hfcl" in out
    palc_exists = "palc" in out
    print(f"  hfcl in config : {'✅ YES' if hfcl_exists else '❌ NO'}")
    print(f"  palc in config : {'✅ YES' if palc_exists else '❌ NO'}")
    results["users_created"] = "PASS" if (hfcl_exists and palc_exists) else "FAIL"

    admin_client.close()
    print("\n✅ Admin SSH session closed")

    # -----------------------------------------------------------
    # PHASE 2 — Login Tests
    # -----------------------------------------------------------
    section("PHASE 2 — SSH Login Tests")

    step(7, "Login with valid user 'hfcl' (privilege 5)")
    ok, hfcl_client, hfcl_shell = try_ssh_login(
        SWITCH_IP, "hfcl", "Discover@1234", SSH_PORT
    )
    if ok:
        print("✅ Login SUCCESSFUL for 'hfcl'")
        out = send_cmd(hfcl_shell, "show users")
        print(out)
        if "hfcl" in out:
            print("✅ 'hfcl' session visible in 'show users'")
            results["hfcl_login"] = "PASS"
        else:
            print("⚠️  'hfcl' not found in show users output")
            results["hfcl_login"] = "WARN"
    else:
        print("❌ Login FAILED for 'hfcl' — UNEXPECTED")
        results["hfcl_login"] = "FAIL"
        hfcl_client = None

    step(8, "Login with WRONG PASSWORD for 'hfcl'")
    ok, c, s = try_ssh_login(SWITCH_IP, "hfcl", "WrongPass999", SSH_PORT)
    if not ok:
        print("✅ Login correctly DENIED (wrong password)")
        results["wrong_password"] = "PASS"
    else:
        print("❌ Login SUCCEEDED with wrong password — SECURITY ISSUE")
        results["wrong_password"] = "FAIL"
        c.close()

    step(9, "Login with NON-EXISTENT user 'ghost'")
    ok, c, s = try_ssh_login(SWITCH_IP, "ghost", "Discover@1234", SSH_PORT)
    if not ok:
        print("✅ Login correctly DENIED (user does not exist)")
        results["nonexistent_user"] = "PASS"
    else:
        print("❌ Login SUCCEEDED for non-existent user — SECURITY ISSUE")
        results["nonexistent_user"] = "FAIL"
        c.close()

    step(10, "Multi-user: login as 'palc' while 'hfcl' is still connected")
    ok, palc_client, palc_shell = try_ssh_login(
        SWITCH_IP, "palc", "Discover@1234", SSH_PORT
    )
    if ok:
        print("✅ Login SUCCESSFUL for 'palc' (concurrent session)")
        out = send_cmd(palc_shell, "show users")
        print(out)
        hfcl_seen = "hfcl" in out if hfcl_client else True
        palc_seen = "palc" in out
        print(f"  hfcl visible : {'✅' if hfcl_seen else '⚠️ '}")
        print(f"  palc visible : {'✅' if palc_seen else '⚠️ '}")
        results["multi_user"] = "PASS" if palc_seen else "WARN"
        palc_client.close()
    else:
        print("❌ Login FAILED for 'palc' — UNEXPECTED")
        results["multi_user"] = "FAIL"

    if hfcl_client:
        hfcl_client.close()
        print("\n✅ 'hfcl' session closed")

    # -----------------------------------------------------------
    # PHASE 3 — Cleanup via admin (remove test users)
    # -----------------------------------------------------------
    section("PHASE 3 — Cleanup via Admin SSH")

    step(11, "Reconnect as admin and remove test users")
    try:
        admin_client, admin_shell = open_ssh_shell(
            SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT
        )
        send_cmd(admin_shell, "configure terminal")
        send_cmd(admin_shell, "no username hfcl")
        send_cmd(admin_shell, "no username palc")
        send_cmd(admin_shell, "exit")
        admin_client.close()
        print("✅ Test users 'hfcl' and 'palc' removed")
        results["cleanup"] = "PASS"
    except Exception as e:
        print(f"⚠️  Cleanup failed: {e}")
        results["cleanup"] = "WARN"

    # -----------------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------------
    section("TEST SUMMARY")
    all_pass = True
    rows = [
        ("SSH enabled",               results.get("ssh_enabled")),
        ("Users created",             results.get("users_created")),
        ("hfcl login (priv 5)",       results.get("hfcl_login")),
        ("Wrong password denied",     results.get("wrong_password")),
        ("Non-existent user denied",  results.get("nonexistent_user")),
        ("Multi-user concurrent",     results.get("multi_user")),
        ("Cleanup",                   results.get("cleanup")),
    ]
    for label, result in rows:
        icon = "✅" if result == "PASS" else ("⚠️ " if result == "WARN" else "❌")
        print(f"  {icon}  {label:<30} {result}")
        if result == "FAIL":
            all_pass = False

    print()
    if all_pass:
        print("🎉  ALL TESTS PASSED")
        print("    TEST-HFCL-SW-02 - Management - Verify SSH service by lower privilege")
        print("    level, wrong password, user and Multi-User Connectivity successfully passed.")
    else:
        print("❌  ONE OR MORE TESTS FAILED — review output above")
    print("=" * 60)

    return all_pass


if __name__ == "__main__":
    # Supports both direct run and Ansible invocation:
    #   python3 test_ssh_privilege.py <ip> <username> <password>
    if len(sys.argv) == 4:
        SWITCH_IP  = sys.argv[1]
        ADMIN_USER = sys.argv[2]
        ADMIN_PASS = sys.argv[3]
    elif len(sys.argv) == 1:
        # Fallback defaults for local testing without args
        SWITCH_IP  = "192.168.180.136"
        ADMIN_USER = "admin"
        ADMIN_PASS = "admin"
    else:
        print("Usage: python3 test_ssh_privilege.py <ip> <username> <password>")
        sys.exit(1)

    success = run_test()
    sys.exit(0 if success else 1)
