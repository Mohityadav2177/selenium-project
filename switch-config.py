import netmiko
import paramiko
import time
import sys

if len(sys.argv) != 4:
    print("Usage: python3 switch_config.py <ip> <username> <password>")
    sys.exit(1)


# Device details
#ip = "192.168.180.136"
#username = "admin"
#password = "admin"  # Put the real password here

ip = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

# Error patterns returned by switch CLI
ERROR_PATTERNS = [
    "% Invalid",
    "% Incomplete",
    "% Error",
    "% Ambiguous",
    "% Unknown",
    "% Failed"
]

# Create SSH client
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Connect to device
client.connect(ip, username=username, password=password,
               look_for_keys=False, allow_agent=False)

# Start interactive shell
shell = client.invoke_shell()

time.sleep(1)
shell.recv(65535)

# Disable paging
shell.send("terminal length 0\n")
time.sleep(1)
shell.recv(65535)

line_number = 0


def send_cmd(command, wait=2):
    global line_number
    line_number += 1

    print(f"\n[LINE {line_number}] Executing: {command}")

    shell.send(command + "\n")
    time.sleep(wait)

    output = shell.recv(65535).decode("utf-8", errors="ignore")
    print(output)

    # Check for CLI errors
    for line in output.splitlines():
        if line.strip().startswith("%"):
            error_reason = line.strip()

            print(f"\n❌ ERROR at LINE {line_number}")
            print(f"Command: {command}")
            print(f"Reason: {error_reason}")
            print("Stopping execution...\n")

            client.close()
            sys.exit(1)

    return output


# Start configuration
send_cmd("configure terminal")

# VLAN configuration
send_cmd("vlan 100")
send_cmd("exit")

# Management interface configuration
send_cmd("interface vlan 100")
send_cmd("ip address 20.20.20.20 255.255.255.0")
send_cmd("exit")

# Access port configuration
send_cmd("interface GigabitEthernet 1/6")
send_cmd("switchport mode access")
send_cmd("switchport access vlan 100")
send_cmd("exit")

# Trunk port configuration
send_cmd("interface GigabitEthernet 1/7")
send_cmd("switchport mode trunk")
send_cmd("switchport trunk allowed vlan 100")
send_cmd("end")

# Save config
#send_cmd("copy running-config startup-config")

# Verify config
send_cmd("show running-config")

# Exit
send_cmd("exit")

client.close()

print("\n✅ Script completed successfully")
