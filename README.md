# **SBEXEC - Active Directory Penetration Testing Tool**  

## **Overview**  
`sbexec.py` automates the process of Active Directory reconnaissance and penetration testing. It performs:  
- **Network scanning** to identify active hosts  
- **Service enumeration** (SSH, SMB, WinRM, RDP, MSSQL, LDAP)  
- **Domain Controller detection**  
- **Brute-force attacks** with usernames, passwords, and NTLM hashes  
- **Pass-the-Hash (PtH) attacks**  
- **BloodHound integration** for AD data collection  
- **Automatic logging and alerts**  
✅ Ideal for OSCP & PNPT candidates: SBEXEC helps automate real-world AD attack techniques, including brute-force, Pass-the-Hash, and BloodHound enumeration, making it a valuable tool for exam preparation.
---

## **Features**  
✔️ **Network Discovery:** Identifies active hosts and saves results to `IP_list.txt`.  
✔️ **Service Enumeration:** Scans for SSH, SMB, WinRM, RDP, MSSQL, and LDAP ports.  
✔️ **Domain Controller Detection:** Identifies DCs and logs them.  
✔️ **Brute-force Attacks:** Uses `netexec` for password spraying and brute-force attacks.  
✔️ **Pass-the-Hash (PtH) Attacks:** Checks both local and domain users with NTLM hashes.  
✔️ **BloodHound Integration:** Automatically collects AD information.  
✔️ **Warning Messages:** Displays `"b3 c4r3fu1!"` if critical ports are found.  

---

## **Installation**  
### **1️⃣ Clone the Repository**  
```bash
git clone https://github.com/yourusername/sbexec.git
cd sbexec
```

### **2️⃣ Install Required Dependencies**  
This tool requires `nmap`, `netexec`, and `BloodHound-python`. Install them using:  
```bash
sudo apt update && sudo apt install -y nmap bloodhound-python
pip install git+https://github.com/SnaffCon/NetExec.git
```

---

## **Usage**  
### **1️⃣ Run SBEXEC**  
```bash
python3 sbexec.py -u users.txt -p passwords.txt -H hashes.txt -d target.local
```

### **2️⃣ Command Breakdown**  
- `-u users.txt` → List of usernames  
- `-p passwords.txt` → List of passwords for brute-force  
- `-H hashes.txt` → List of NTLM hashes for Pass-the-Hash attacks  
- `-d target.local` → Target domain  

---

## **How SBEXEC Works (Step-by-Step)**  
### **🔍 Step 1: Network Discovery**  
- Runs an **Nmap sweep** to identify active IPs in the subnet.  
- Saves the results to `IP_list.txt`.  

### **🔎 Step 2: Service Enumeration**  
- Scans each IP for **SSH, SMB, WinRM, RDP, MSSQL, LDAP** ports.  
- If a port is open, it prints `"b3 c4r3fu1!"`.  

### **⚠️ Step 3: Domain Controller Detection**  
- Identifies **DC IP addresses** and logs them.  
- Runs `BloodHound-python` to collect AD data.  

### **🔑 Step 4: Brute-Force & Pass-the-Hash Attacks**  
- Runs **brute-force attacks** against detected services using `netexec`.  
- Uses **Pass-the-Hash (PtH)** if hashes are provided.  
- Checks if users are **local or domain accounts** and tests both.  

---

## **Example Output**  
```
[+] Active Hosts: 192.168.1.10, 192.168.1.15
[!] DC Detected: 192.168.1.10 (Logged)
[+] Found SMB on 192.168.1.15 → b3 c4r3fu1!
[+] Attempting brute-force attack on SMB...
[+] Found valid credentials: admin:SuperSecure123
```

---

## **Disclaimer**  
This tool is for **educational purposes only**. Do not use it on unauthorized systems.  

---


