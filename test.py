import paramiko
import time

# Device details
ip = "192.168.180.136"
username = "admin"
password = "admin"  # Put the real password here

# Create an SSH client
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Connect to device
client.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)

# Start interactive shell session
shell = client.invoke_shell()

def send_cmd(command, wait=1):
    """Send command to device and wait for response"""
    shell.send(command + "\n")
    time.sleep(wait)
    output = shell.recv(65535).decode("utf-8", errors="ignore")
    print(output)
    return output

# Start configuration
send_cmd("configure terminal")

# VLAN configuration
send_cmd("vlan 100")
send_cmd("exit")

# Management interface configuration
send_cmd("interface vlan 100")
send_cmd("ip address 10.10.10.10 255.255.255.0")
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
send_cmd("copy running-config startup-config")

# To check the config
send_cmd("show running-config")

send_cmd("                ")
# Exit
send_cmd("exit")

# Close SSH connection
client.close()
