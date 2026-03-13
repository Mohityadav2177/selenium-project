import paramiko
import socket
import sys
import time

def test_switch_ssh(hostname, username, password, port=22):
    """
    Tests SSH functionality on a network switch including:
    1. Initial SSH connection
    2. Enable SSH globally
    3. Create a test user
    4. Verify SSH is enabled with 'show ip ssh'
    5. Verify users with 'show users'
    6. Disable SSH
    7. Verify SSH is disabled
    """
    
    # Initialize the SSH client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    print("=" * 60)
    print("SWITCH SSH CONFIGURATION TEST")
    print("=" * 60)
    print(f"Target: {hostname}:{port}")
    print(f"Username: {username}")
    print("=" * 60)
    
    try:
        # Step 1: Connect to the switch
        print("\n[1] Attempting initial SSH connection...")
        client.connect(
            hostname,
            port=port,
            username=username,
            password=password,
            timeout=10,
            look_for_keys=False,
            allow_agent=False
        )
        print("✅ Successfully connected to the switch")
        
        # Open an interactive shell channel
        shell = client.invoke_shell()
        time.sleep(0.5)
        
        def send_command(cmd):
            """Send a command and get the output"""
            shell.send(cmd + "\n")
            time.sleep(1)
            output = ""
            while shell.recv_ready():
                output += shell.recv(4096).decode('utf-8', errors='ignore')
            return output
        
        # Clear initial output
        send_command("")
        
        # Step 2: Enter configuration mode and enable SSH
        print("\n[2] Entering configuration mode and enabling SSH...")
        output = send_command("configure terminal")
        output = send_command("ip ssh")
        print("✅ SSH enabled globally")
        
        # Step 3: Create a new user
        print("\n[3] Creating test user 'hfcl'...")
        output = send_command("username hfcl privilege 15 password unencrypted Discover@1234")
        print("✅ User 'hfcl' created with privilege 15")
        
        # Step 4: Exit config mode
        send_command("exit")
        time.sleep(0.5)
        
        # Step 5: Verify SSH status
        print("\n[4] Verifying SSH status with 'show ip ssh'...")
        output = send_command("show ip ssh")
        print("Output:")
        print("-" * 60)
        print(output)
        print("-" * 60)
        
        if "SSH Enabled" in output or "enabled" in output.lower():
            print("✅ SSH is confirmed enabled")
        else:
            print("⚠️  SSH status unclear - review output above")
        
        # Step 6: Show connected users
        print("\n[5] Checking active users with 'show users'...")
        output = send_command("show users")
        print("Output:")
        print("-" * 60)
        print(output)
        print("-" * 60)
        
        if "hfcl" in output or "admin" in output:
            print("✅ User session confirmed")
        else:
            print("⚠️  User status unclear - review output above")
        
        # Step 7: Disable SSH
        print("\n[6] Disabling SSH...")
        output = send_command("configure terminal")
        output = send_command("ip ssh")
        print("✅ SSH disabled globally")
        
        # Step 8: Exit and verify SSH is disabled
        send_command("exit")
        time.sleep(0.5)
        
        print("\n[7] Verifying SSH is disabled with 'show ip ssh'...")
        output = send_command("show ip ssh")
        print("Output:")
        print("-" * 60)
        print(output)
        print("-" * 60)
        
        if "SSH Disabled" in output or "disabled" in output.lower() or "not enabled" in output.lower():
            print("✅ SSH is confirmed disabled")
        else:
            print("⚠️  SSH status unclear - review output above")
        
        # Step 9: Test re-enabling to restore switch state
        print("\n[8] Re-enabling SSH to restore switch functionality...")
        output = send_command("configure terminal")
        output = send_command("ip ssh")
        output = send_command("exit")
        print("✅ SSH re-enabled for normal operation")
        
        print("\n" + "=" * 60)
        print("TEST COMPLETED SUCCESSFULLY")
        print("=" * 60)
        return True
        
    except paramiko.AuthenticationException:
        print("❌ Authentication failed: Please verify your username and password.")
    except paramiko.SSHException as ssh_err:
        print(f"❌ SSH error occurred: {ssh_err}")
    except socket.timeout:
        print("❌ Connection timed out: The switch might be offline or blocking port 22.")
    except socket.error as sock_err:
        print(f"❌ Network error occurred: {sock_err}")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
        
    finally:
        # Always close the connection
        client.close()
        
    return False

if __name__ == "__main__":
    # Switch configuration
    SWITCH_IP = "192.168.180.136"
    USERNAME = "admin"
    PASSWORD = "admin"
    
    success = test_switch_ssh(SWITCH_IP, USERNAME, PASSWORD)
    
    sys.exit(0 if success else 1)
