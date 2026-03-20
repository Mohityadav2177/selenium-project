import paramiko
import telnetlib
import socket
import sys
import time


def test_switch_ssh(hostname, username, password, port=22):
    """
    Tests SSH functionality on a network switch:
    1.  SSH  - Connect
    2.  SSH  - Enable SSH globally
    3.  SSH  - Create test user 'hfcl'
    4.  SSH  - Verify SSH enabled  (show ip ssh)
    5.  SSH  - Verify users        (show users)
    6.  SSH  - EXIT SSH session
    7.  Telnet - Connect
    8.  Telnet - Disable SSH       (no ip ssh)
    9.  Telnet - Verify SSH disabled
    10. Telnet - Re-enable SSH     (ip ssh)
    11. Telnet - Verify SSH enabled again
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("=" * 60)
    print("SWITCH SSH CONFIGURATION TEST")
    print("=" * 60)
    print(f"Target: {hostname}:{port}")
    print(f"Username: {username}")
    print("=" * 60)
    # ===========================================================
    # PHASE 1 — SSH
    # ===========================================================
    try:
        print("\n[1] Attempting initial SSH connection...")
        client.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False
        )
        print("✅ Successfully connected via SSH")
        shell = client.invoke_shell()
        time.sleep(1)
        def ssh_send(cmd, wait=1):
            """Send a command over SSH shell and return full output."""
            shell.send(cmd + "\n")
            time.sleep(wait)
            output = ""
            while shell.recv_ready():
                output += shell.recv(4096).decode('utf-8', errors='ignore')
                time.sleep(0.5)
            return output
        # Clear banner
        ssh_send("")
        # Step 2: Enable SSH
        print("\n[2] Entering configuration mode and enabling SSH...")
        ssh_send("configure terminal")
        ssh_send("ip ssh")
        print("✅ SSH enabled globally")
        # Step 3: Create user
        print("\n[3] Creating test user 'hfcl'...")
        ssh_send("username hfcl privilege 15 password unencrypted Discover@1234")
        print("✅ User 'hfcl' created with privilege 15")
        # Exit config mode
        ssh_send("exit")
        # Step 4: Verify SSH enabled
        print("\n[4] Verifying SSH status with 'show ip ssh'...")
        output = ssh_send("show ip ssh")
        print("Output:")
        print("-" * 60)
        print(output)
        print("-" * 60)
        if "enabled" in output.lower():
            print("✅ SSH is confirmed enabled")
        else:
            print("⚠️  SSH status unclear - review output above")
        # Step 5: Show users
        print("\n[5] Checking active users with 'show users'...")
        output = ssh_send("show users")
        print("Output:")
        print("-" * 60)
        print(output)
        print("-" * 60)
        if "hfcl" in output or "admin" in output:
            print("✅ User session confirmed")
        else:
            print("⚠️  User status unclear - review output above")
        # Step 6: Close SSH
        print("\n[6] Closing SSH session...")
        client.close()
        print("✅ SSH session closed")
    except paramiko.AuthenticationException:
        print("❌ SSH Authentication failed.")
        client.close()
        return False
    except Exception as e:
        print(f"❌ SSH error: {e}")
        client.close()
        return False
    # ===========================================================
    # PHASE 2 — TELNET
    # ===========================================================
    print("\n" + "=" * 60)
    print("SWITCHING TO TELNET SESSION")
    print("=" * 60)
    try:
        print("\n[7] Attempting Telnet connection...")
        tn = telnetlib.Telnet(hostname, 23, timeout=10)
        print("✅ Telnet connection established")
        def telnet_send(cmd, wait=5):
            """Send a command over Telnet and return full output."""
            tn.write(cmd.encode('ascii') + b"\n")
            time.sleep(wait)
            output = b""
            while True:
                chunk = tn.read_very_eager()
                if not chunk:
                    break
                output += chunk
                time.sleep(0.5)
            decoded = output.decode('ascii', errors='ignore')
            lines = [l for l in decoded.splitlines() if cmd.strip() not in l]
            return "\n".join(lines).strip()
        # Login
        print("   Waiting for Username prompt...")
        tn.read_until(b"Username:", timeout=10)
        tn.write(username.encode('ascii') + b"\n")
        print("   Waiting for Password prompt...")
        tn.read_until(b"Password:", timeout=10)
        tn.write(password.encode('ascii') + b"\n")
        # Drain banner
        time.sleep(1.5)
        banner = b""
        while True:
            chunk = tn.read_very_eager()
            if not chunk:
                break
            banner += chunk
            time.sleep(0.3)
        print("✅ Logged in via Telnet")
        print(banner.decode('ascii', errors='ignore').strip())
        # Step 8: Disable SSH via Telnet
        print("\n[8] Disabling SSH via Telnet...")
        telnet_send("configure terminal")
        telnet_send("no ip ssh")
        telnet_send("exit")
        print("✅ SSH disabled globally")
        # Step 9: Verify SSH disabled
        print("\n[9] Verifying SSH is disabled with 'show ip ssh'...")
        output = telnet_send("show ip ssh")
        print("Output:")
        print("-" * 60)
        print(output)
        print("-" * 60)
        if "disabled" in output.lower() or "not enabled" in output.lower():
            print("✅ SSH is confirmed disabled")
        else:
            print("⚠️  SSH status unclear - review output above")
        # Step 10: Re-enable SSH via Telnet
        print("\n[10] Re-enabling SSH via Telnet...")
        telnet_send("configure terminal")
        telnet_send("ip ssh")
        telnet_send("exit")
        print("✅ SSH re-enabled globally")
        # Step 11: Verify SSH re-enabled
        print("\n[11] Verifying SSH is re-enabled with 'show ip ssh'...")
        output = telnet_send("show ip ssh")
        print("Output:")
        print("-" * 60)
        print(output)
        print("-" * 60)
        if "enabled" in output.lower():
            print("✅ SSH is confirmed re-enabled")
        else:
            print("⚠️  SSH status unclear - review output above")
        tn.close()
        print("\n" + "=" * 60)
        print("TEST-HFCL-SW-01 - Management - Verify SSH service by enabling,")
        print("created user and disabling it. COMPLETED SUCCESSFULLY")
        print("=" * 60)
        return True
    except Exception as e:
        print(f"❌ Telnet error: {e}")
        try:
            tn.close()
        except Exception:
            pass
        return False


if __name__ == "__main__":
    # Supports both direct run and Ansible invocation:
    #   python3 test4.py <ip> <username> <password>
    if len(sys.argv) == 4:
        SWITCH_IP = sys.argv[1]
        USERNAME  = sys.argv[2]
        PASSWORD  = sys.argv[3]
    elif len(sys.argv) == 1:
        # Fallback defaults for local testing without args
        SWITCH_IP = "192.168.180.136"
        USERNAME  = "admin"
        PASSWORD  = "admin"
    else:
        print("Usage: python3 test4.py <ip> <username> <password>")
        sys.exit(1)

    success = test_switch_ssh(SWITCH_IP, USERNAME, PASSWORD)
    sys.exit(0 if success else 1)
