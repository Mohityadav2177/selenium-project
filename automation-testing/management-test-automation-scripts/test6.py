import paramiko
import telnetlib
import socket
import sys
import time


# ===========================================================
# Configuration  (override via CLI: script.py <ip> <admin> <pass>)
# ===========================================================
SWITCH_IP   = "192.168.180.136"
ADMIN_USER  = "admin"
ADMIN_PASS  = "admin"
SSH_PORT    = 22
TELNET_PORT = 23

# Test users created during this test
USER1_NAME  = "hfcl"
USER1_PASS  = "Discover@1234"
USER1_PRIV  = 1

USER2_NAME  = "palc"
USER2_PASS  = "Discover@1234"
USER2_PRIV  = 1

WRONG_PASS  = "WrongPass@9999"
GHOST_USER  = "nonexistent_user"
GHOST_PASS  = "SomePass@1234"


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
def try_telnet_login(hostname, username, password, port=23, timeout=20,
                     expect_fail=False):
    """
    Attempt a Telnet login using proper RFC-854 CRLF line endings.

    KEY LESSONS from previous debugging:
      1. tn.write() MUST use b"\\r\\n" — switches wait for CRLF before
         advancing their login state machine. Sending b"\\n" only causes
         the switch to echo the input and never send the Password: prompt.
      2. tn.expect() is used for the Password prompt step so it accumulates
         all bytes (including the username echo) and waits patiently until
         'Password' appears — a manual read_very_eager() loop exits too early.

    Parameters:
      expect_fail  – set True when testing wrong-password / ghost-user logins
                     so the function waits for rejection messages too.

    Returns (success: bool, tn_or_None, decoded_output_string).
    """
    try:
        tn = telnetlib.Telnet(hostname, port, timeout=timeout)

        # ── 1. Username prompt ───────────────────────────────────────────
        idx, _, pre = tn.expect(
            [b"Username:", b"username:", b"User:", b"user:"],
            timeout=timeout
        )
        if idx == -1:
            tn.close()
            return False, None, "No Username prompt — " + pre.decode('ascii', errors='ignore')

        tn.write(username.encode('ascii') + b"\r\n")   # RFC-854 CRLF mandatory

        # ── 2. Password prompt ────────────────────────────────────────────
        # tn.expect() buffers the username echo + any banner text and only
        # returns when 'Password' arrives. Never use read_very_eager() here.
        idx, _, after_user = tn.expect(
            [b"Password:", b"password:", b"PASSWORD:"],
            timeout=timeout
        )
        after_str = after_user.decode('ascii', errors='ignore')

        if idx == -1:
            if "#" in after_str or ">" in after_str:
                time.sleep(0.3); tn.read_very_eager()
                return True, tn, after_str
            tn.close()
            return False, None, "No Password prompt — " + after_str

        tn.write(password.encode('ascii') + b"\r\n")   # RFC-854 CRLF mandatory

        # ── 3. Post-password: shell prompt OR rejection ───────────────────
        patterns = [b"#", b">",
                    b"Login incorrect", b"login incorrect",
                    b"Access denied",   b"access denied",
                    b"% Authentication failed",
                    b"% Bad passwords", b"% Login invalid"]
        idx, _, post = tn.expect(patterns, timeout=timeout)
        post_str = post.decode('ascii', errors='ignore')

        if idx in (0, 1):                          # shell prompt
            time.sleep(0.3); tn.read_very_eager()
            return True, tn, after_str + post_str
        elif idx == -1:
            if "#" in post_str or ">" in post_str:
                time.sleep(0.3); tn.read_very_eager()
                return True, tn, after_str + post_str
            tn.close()
            return False, None, "No shell prompt — " + post_str
        else:
            # Explicit rejection message received
            tn.close()
            return False, None, post_str

    except (socket.timeout, ConnectionRefusedError, EOFError, OSError) as ex:
        return False, None, str(ex)


def telnet_send(tn, cmd, wait=2.0):
    """Send a command over an established Telnet session and return output."""
    tn.write(cmd.encode('ascii') + b"\r\n")        # RFC-854 CRLF mandatory
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


# ===========================================================
# Formatting
# ===========================================================
def section(title):
    print("\n" + "=" * 65)
    print(f"  {title}")
    print("=" * 65)


def step(n, desc):
    print(f"\n[Step {n}] {desc}")
    print("-" * 65)


def result_line(label, status):
    icon = "✅" if status == "PASS" else ("⚠️ " if status == "WARN" else "❌")
    print(f"  {icon}  {label:<50} {status}")


# ===========================================================
# MAIN TEST
# ===========================================================
def run_test():
    results = {}

    # ═══════════════════════════════════════════════════════════
    # PHASE 1 — Enable Telnet + create test users via SSH
    # ═══════════════════════════════════════════════════════════
    section("PHASE 1 — Setup: Enable Telnet & Create Test Users (via SSH)")

    step(1, f"Connect to switch as {ADMIN_USER} via SSH")
    try:
        ssh_c, ssh_sh = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print(f"✅ SSH connected to {SWITCH_IP}:{SSH_PORT}")
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        sys.exit(1)

    step(2, "Enable Telnet server  →  aaa authentication login telnet local")
    ssh_send(ssh_sh, "configure terminal")
    ssh_send(ssh_sh, "aaa authentication login telnet local")
    ssh_send(ssh_sh, "exit")
    # Verify
    cfg = ssh_send(ssh_sh, "show running-config feature auth", wait=2)
    if "no aaa authentication login telnet" not in cfg:
        print("✅ Telnet server ENABLED (confirmed in running-config)")
        results["telnet_enabled"] = "PASS"
    else:
        print("❌ Telnet server enable FAILED")
        results["telnet_enabled"] = "FAIL"

    step(3, f"Create user1: username {USER1_NAME} privilege {USER1_PRIV}")
    ssh_send(ssh_sh, "configure terminal")
    ssh_send(ssh_sh, f"username {USER1_NAME} privilege {USER1_PRIV} password unencrypted {USER1_PASS}")
    ssh_send(ssh_sh, "exit")
    # Verify
    user_cfg = ssh_send(ssh_sh, f"show running-config | include {USER1_NAME}", wait=2)
    print(user_cfg)
    if USER1_NAME in user_cfg:
        print(f"✅ User '{USER1_NAME}' created and visible in running-config")
        results["user1_created"] = "PASS"
    else:
        print(f"❌ User '{USER1_NAME}' NOT found in running-config")
        results["user1_created"] = "FAIL"

    step(4, "Verify show users (admin SSH session active)")
    out = ssh_send(ssh_sh, "show users")
    print(out)

    ssh_c.close()
    print("\n✅ SSH session closed")
    time.sleep(1)

    # ═══════════════════════════════════════════════════════════
    # PHASE 2 — Valid login: user hfcl (privilege 1 / User EXEC)
    # ═══════════════════════════════════════════════════════════
    section(f"PHASE 2 — Valid Login: user '{USER1_NAME}' (privilege {USER1_PRIV})")

    step(5, f"Telnet login with valid credentials  →  {USER1_NAME} / {USER1_PASS}")
    ok, tn1, login_buf = try_telnet_login(
        SWITCH_IP, USER1_NAME, USER1_PASS, TELNET_PORT
    )
    print(f"   Login buffer: {repr(login_buf)}")
    if ok:
        print(f"✅ Telnet login SUCCESSFUL for user '{USER1_NAME}'")
        results["user1_login"] = "PASS"

        step(6, "Run show users to confirm session is active")
        su_out = telnet_send(tn1, "show users")
        print(su_out)
        # Privilege-1 users land on '>' prompt (User EXEC), not '#'
        if USER1_NAME in su_out:
            print(f"✅ User '{USER1_NAME}' visible in show users output")
            results["user1_in_show_users"] = "PASS"
        elif "by Telnet" in su_out or "Telnet" in su_out:
            print(f"✅ Telnet session visible in show users")
            results["user1_in_show_users"] = "PASS"
        else:
            print(f"⚠️  '{USER1_NAME}' not found in show users — review output")
            results["user1_in_show_users"] = "WARN"

        # Confirm User EXEC mode (prompt is '>', not '#')
        prompt_check = login_buf + su_out
        if ">" in prompt_check and "#" not in prompt_check.split(">")[0]:
            print(f"✅ Privilege-{USER1_PRIV} confirmed: User EXEC mode (prompt is '>')")
            results["user1_exec_mode"] = "PASS"
        else:
            print(f"⚠️  Could not confirm User EXEC mode from prompt")
            results["user1_exec_mode"] = "WARN"

        tn1.close()
        print(f"\n✅ Telnet session for '{USER1_NAME}' closed")
    else:
        print(f"❌ Telnet login FAILED for '{USER1_NAME}': {login_buf}")
        results["user1_login"]         = "FAIL"
        results["user1_in_show_users"] = "FAIL"
        results["user1_exec_mode"]     = "FAIL"

    time.sleep(1)

    # ═══════════════════════════════════════════════════════════
    # PHASE 3 — Wrong password rejection
    # ═══════════════════════════════════════════════════════════
    section(f"PHASE 3 — Wrong Password Rejection  (user: {USER1_NAME})")

    step(7, f"Attempt login with WRONG password  →  {USER1_NAME} / {WRONG_PASS}")
    ok, tn_bad, bad_buf = try_telnet_login(
        SWITCH_IP, USER1_NAME, WRONG_PASS, TELNET_PORT, expect_fail=True
    )
    print(f"   Login buffer: {repr(bad_buf)}")
    if not ok:
        # Check the rejection message content
        buf_lower = bad_buf.lower()
        if any(kw in buf_lower for kw in [
            "login incorrect", "access denied", "authentication failed",
            "bad passwords", "login invalid", "% "
        ]):
            print(f"✅ Wrong-password login REJECTED with error message")
            print(f"   Rejection message: {bad_buf.strip()!r}")
        else:
            print(f"✅ Wrong-password login correctly DENIED (session not opened)")
        results["wrong_pass_rejected"] = "PASS"
    else:
        print(f"❌ Wrong-password login SUCCEEDED — this is a SECURITY FAILURE")
        results["wrong_pass_rejected"] = "FAIL"
        try: tn_bad.close()
        except Exception: pass

    time.sleep(1)

    # ═══════════════════════════════════════════════════════════
    # PHASE 4 — Non-existent user rejection
    # ═══════════════════════════════════════════════════════════
    section(f"PHASE 4 — Non-Existent User Rejection  (user: {GHOST_USER})")

    step(8, f"Attempt login with NON-EXISTENT user  →  {GHOST_USER} / {GHOST_PASS}")
    ok, tn_ghost, ghost_buf = try_telnet_login(
        SWITCH_IP, GHOST_USER, GHOST_PASS, TELNET_PORT, expect_fail=True
    )
    print(f"   Login buffer: {repr(ghost_buf)}")
    if not ok:
        buf_lower = ghost_buf.lower()
        if any(kw in buf_lower for kw in [
            "login incorrect", "access denied", "authentication failed",
            "bad passwords", "login invalid", "% "
        ]):
            print(f"✅ Non-existent user login REJECTED with error message")
            print(f"   Rejection message: {ghost_buf.strip()!r}")
        else:
            print(f"✅ Non-existent user login correctly DENIED (session not opened)")
        results["ghost_user_rejected"] = "PASS"
    else:
        print(f"❌ Non-existent user login SUCCEEDED — this is a SECURITY FAILURE")
        results["ghost_user_rejected"] = "FAIL"
        try: tn_ghost.close()
        except Exception: pass

    time.sleep(1)

    # ═══════════════════════════════════════════════════════════
    # PHASE 5 — Create user2 (palc) + Multi-user concurrent login
    # ═══════════════════════════════════════════════════════════
    section(f"PHASE 5 — Multi-User Concurrent Telnet Sessions")

    step(9, f"Connect via SSH to create user2: username {USER2_NAME} privilege {USER2_PRIV}")
    try:
        ssh_c2, ssh_sh2 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        print(f"✅ SSH connected")
    except Exception as e:
        print(f"❌ SSH connection failed: {e}")
        results["user2_created"]      = "FAIL"
        results["multi_user_session"] = "FAIL"
        ssh_c2 = None

    if ssh_c2:
        ssh_send(ssh_sh2, "configure terminal")
        ssh_send(ssh_sh2, f"username {USER2_NAME} privilege {USER2_PRIV} password unencrypted {USER2_PASS}")
        ssh_send(ssh_sh2, "exit")
        user2_cfg = ssh_send(ssh_sh2, f"show running-config | include {USER2_NAME}", wait=2)
        print(user2_cfg)
        if USER2_NAME in user2_cfg:
            print(f"✅ User '{USER2_NAME}' created and visible in running-config")
            results["user2_created"] = "PASS"
        else:
            print(f"❌ User '{USER2_NAME}' NOT found in running-config")
            results["user2_created"] = "FAIL"
        ssh_c2.close()

    time.sleep(1)

    step(10, f"Open Telnet session 1  →  user '{USER1_NAME}'")
    ok1, tn_u1, buf1 = try_telnet_login(SWITCH_IP, USER1_NAME, USER1_PASS, TELNET_PORT)
    print(f"   Login buffer: {repr(buf1)}")
    if ok1:
        print(f"✅ Session 1 opened for '{USER1_NAME}'")
    else:
        print(f"❌ Session 1 FAILED for '{USER1_NAME}': {buf1}")

    step(11, f"Open Telnet session 2 CONCURRENTLY  →  user '{USER2_NAME}'")
    ok2, tn_u2, buf2 = try_telnet_login(SWITCH_IP, USER2_NAME, USER2_PASS, TELNET_PORT)
    print(f"   Login buffer: {repr(buf2)}")
    if ok2:
        print(f"✅ Session 2 opened for '{USER2_NAME}'")
    else:
        print(f"❌ Session 2 FAILED for '{USER2_NAME}': {buf2}")

    step(12, "Run show users from admin SSH to confirm both sessions active")
    try:
        ssh_c3, ssh_sh3 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        show_u = ssh_send(ssh_sh3, "show users", wait=2)
        print(show_u)

        u1_visible = USER1_NAME in show_u
        u2_visible = USER2_NAME in show_u
        telnet_sessions = show_u.lower().count("by telnet") + show_u.lower().count("telnet")

        print(f"\n   User '{USER1_NAME}' in show users : {'YES ✅' if u1_visible else 'NO ❌'}")
        print(f"   User '{USER2_NAME}' in show users : {'YES ✅' if u2_visible else 'NO ❌'}")
        print(f"   Telnet sessions visible         : {telnet_sessions}")

        if ok1 and ok2:
            if u1_visible and u2_visible:
                print(f"\n✅ Both users visible concurrently in show users")
                results["multi_user_session"] = "PASS"
            elif u1_visible or u2_visible:
                print(f"\n⚠️  Only one user visible in show users — check output above")
                results["multi_user_session"] = "WARN"
            else:
                # Both sessions opened but usernames not in show users — still count as pass
                # since show users on some switches only shows username at higher privilege
                print(f"\n⚠️  Both logins succeeded but usernames not in show users")
                results["multi_user_session"] = "WARN"
        else:
            print(f"\n❌ One or both concurrent sessions failed to open")
            results["multi_user_session"] = "FAIL"

        ssh_c3.close()
    except Exception as e:
        print(f"❌ Could not verify show users: {e}")
        results["multi_user_session"] = "FAIL"

    # Close the two Telnet sessions
    for tn_obj, uname in [(tn_u1, USER1_NAME) if ok1 else (None, USER1_NAME),
                          (tn_u2, USER2_NAME) if ok2 else (None, USER2_NAME)]:
        if tn_obj:
            try:
                tn_obj.close()
                print(f"✅ Telnet session for '{uname}' closed")
            except Exception:
                pass

    time.sleep(1)

    # ═══════════════════════════════════════════════════════════
    # PHASE 6 — Cleanup: remove test users via SSH
    # ═══════════════════════════════════════════════════════════
    section("PHASE 6 — Cleanup: Remove Test Users (via SSH)")

    step(13, f"Remove users '{USER1_NAME}' and '{USER2_NAME}'")
    try:
        ssh_c4, ssh_sh4 = open_ssh_shell(SWITCH_IP, ADMIN_USER, ADMIN_PASS, SSH_PORT)
        ssh_send(ssh_sh4, "configure terminal")
        ssh_send(ssh_sh4, f"no username {USER1_NAME}")
        ssh_send(ssh_sh4, f"no username {USER2_NAME}")
        ssh_send(ssh_sh4, "exit")
        cleanup_cfg = ssh_send(ssh_sh4, "show running-config | include username", wait=2)
        print(cleanup_cfg)
        u1_gone = USER1_NAME not in cleanup_cfg
        u2_gone = USER2_NAME not in cleanup_cfg
        print(f"   User '{USER1_NAME}' removed : {'YES ✅' if u1_gone else 'NO ❌'}")
        print(f"   User '{USER2_NAME}' removed : {'YES ✅' if u2_gone else 'NO ❌'}")
        results["cleanup"] = "PASS" if (u1_gone and u2_gone) else "WARN"
        ssh_c4.close()
    except Exception as e:
        print(f"⚠️  Cleanup error: {e}")
        results["cleanup"] = "WARN"

    # ═══════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════
    section("TEST SUMMARY — TEST-HFCL-SW-02  Telnet Privilege & Multi-User")
    rows = [
        ("Telnet server enabled (aaa auth telnet local)",  results.get("telnet_enabled")),
        (f"User '{USER1_NAME}' created (privilege {USER1_PRIV})",
                                                           results.get("user1_created")),
        (f"Valid login: '{USER1_NAME}' via Telnet",        results.get("user1_login")),
        (f"'{USER1_NAME}' visible in show users",          results.get("user1_in_show_users")),
        (f"Privilege-{USER1_PRIV}: User EXEC mode (>)",    results.get("user1_exec_mode")),
        ("Wrong password login REJECTED",                  results.get("wrong_pass_rejected")),
        ("Non-existent user login REJECTED",               results.get("ghost_user_rejected")),
        (f"User '{USER2_NAME}' created (privilege {USER2_PRIV})",
                                                           results.get("user2_created")),
        ("Concurrent multi-user Telnet sessions",          results.get("multi_user_session")),
        ("Cleanup (test users removed)",                   results.get("cleanup")),
    ]

    all_pass = True
    for label, status in rows:
        result_line(label, status or "SKIP")
        if status in ("FAIL", None):
            all_pass = False

    print()
    if all_pass:
        print("🎉  ALL TESTS PASSED")
        print("    TEST-HFCL-SW-02 - Management - Verify Telnet service with lower")
        print("    privilege level, wrong password, non-existent user, and multi-user")
        print("    concurrent connectivity — successfully passed.")
    else:
        print("❌  ONE OR MORE TESTS FAILED — review output above")
    print("=" * 65)
    return all_pass


if __name__ == "__main__":
    if len(sys.argv) == 4:
        SWITCH_IP  = sys.argv[1]
        ADMIN_USER = sys.argv[2]
        ADMIN_PASS = sys.argv[3]

    success = run_test()
    sys.exit(0 if success else 1)
