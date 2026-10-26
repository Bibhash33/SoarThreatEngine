import sys
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def block_ip_linux(ip_address: str) -> bool:
    """Blocks malicious IP using Linux iptables."""
    try:
        command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        subprocess.run(command, check=True)
        logging.info(f"SUCCESS: Blocked IP {ip_address} using iptables.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"ERROR: Failed to block IP {ip_address} using iptables: {e}")
        return False

def block_ip_windows(ip_address: str) -> bool:
    """Blocks malicious IP using Windows Netsh Firewall safely."""
    rule_name = f"SOAR_Block_{ip_address}"
    try:
        # Step 1: Delete rule if it already exists (prevents duplicate rule error)
        delete_command = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
        subprocess.run(delete_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Step 2: Add the firewall block rule
        add_command = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip_address}"
        subprocess.run(add_command, check=True, shell=True)
        
        logging.info(f"SUCCESS: Blocked IP {ip_address} using Windows Firewall rule {rule_name}.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"ERROR: Failed to Block IP: {ip_address} using Windows Firewall: {e}")
        return False

def trigger_containment(ip_address: str) -> bool:
    """Detects host OS and routes to appropriate firewall block function."""
    if sys.platform.startswith("win"):
        return block_ip_windows(ip_address)
    else:
        return block_ip_linux(ip_address)