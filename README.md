# Suricata-IDS-Home-Lab

## Overview

This repository guides you through building a practical Suricata Intrusion Detection System (IDS) home laboratory environment. The goal is to provide hands-on experience with network security monitoring, threat detection, and IDS configuration. Suricata is a powerful open-source network security engine capable of real-time intrusion detection, inline intrusion prevention, and network security monitoring. By setting up this lab, you'll gain practical skills in deploying, configuring, and managing an IDS to protect network infrastructure.

## Requirements

### Hardware Specifications
- Host machine with minimum 16GB RAM
- Dual-core or better processor (quad-core recommended)
- At least 50GB available disk space
- Virtualization support enabled in BIOS

### Software Requirements
- Virtualization platform (VirtualBox or VMware)
- **Ubuntu Server 22.04** (for Suricata IDS server)
- **Kali Linux** (attacker machine)
- **Windows Machine** (victim system)
- **Metasploitable 2** (vulnerable target)
- **DVWA** (Damn Vulnerable Web Application)

## Lab Diagram

The lab consists of the following components:

```
[Attacker Machine - Kali Linux] ──┐
                                  │
                                  ├─── [Suricata IDS Server]
                                  │
[Victim Machines] ────────────────┘
├─ Ubuntu + DVWA
├─ Metasploitable 2
└─ Windows Target
```

All systems should be configured on the same internal network to allow traffic monitoring by Suricata.

## Setting up the Suricata Home-Lab

### Step 1: Deploy the Suricata IDS Server

1. **Create Ubuntu Server VM**
   - Download Ubuntu Server 22.04 ISO
   - Create a new VM with 4GB RAM and 2 CPU cores
   - Install Ubuntu Server with default settings
   - Update system packages: `sudo apt update && sudo apt upgrade -y`

2. **Install Suricata**
   ```bash
   sudo apt install software-properties-common -y
   sudo add-apt-repository ppa:oisf/suricata-stable
   sudo apt update
   sudo apt install suricata -y
   ```

3. **Configure Suricata**
   - Edit the main configuration file: `sudo nano /etc/suricata/suricata.yaml`
   - Set the correct network interface for monitoring
   - Configure HOME_NET to match your lab network range
   - Update rule files: `sudo suricata-update`

4. **Start Suricata Service**
   ```bash
   sudo systemctl start suricata
   sudo systemctl enable suricata
   sudo systemctl status suricata
   ```

### Step 2: Configure Victim Server 1 (DVWA)

1. Deploy Ubuntu Server 22.04 in a new VM
2. Install Apache, MySQL, and PHP
3. Download and configure DVWA:
   ```bash
   cd /var/www/html
   sudo git clone https://github.com/digininja/DVWA.git
   sudo chmod -R 777 DVWA
   ```
4. Configure database settings and complete DVWA setup through web interface

### Step 3: Deploy Victim Server 2 (Metasploitable 2)

1. Download Metasploitable 2 VM image
2. Import the OVA/VMDK file into your virtualization platform
3. Configure network adapter to connect to the lab network
4. Boot the system (default credentials: msfadmin/msfadmin)

### Step 4: Set up Attacker Machine (Kali Linux)

1. Download Kali Linux VM image
2. Import into virtualization platform
3. Configure network settings to access the lab network
4. Update Kali tools: `sudo apt update && sudo apt upgrade -y`

## Exercises—Network-based attacks

These exercises demonstrate how to create Suricata rules for detecting common network-based attack patterns.

### Exercise 1: Nmap Stealth Scan Detection
**Objective:** Detect TCP SYN scans across multiple ports

**Sample Rule:**
```
alert tcp any any -> $HOME_NET any (msg:"Potential Nmap SYN Scan Detected"; flags:S,12; threshold: type threshold, track by_src, count 10, seconds 5; sid:1000001; rev:1;)
```

### Exercise 2: Nmap OS Fingerprinting Detection
**Objective:** Identify OS detection attempts via ICMP traffic patterns

**Sample Rules:**
```
alert icmp any any -> $HOME_NET any (msg:"Possible OS Fingerprinting - ICMP Echo"; itype:8; ttl:64; sid:1000002; rev:1;)

alert icmp any any -> $HOME_NET any (msg:"Possible OS Fingerprinting - ICMP Reply"; itype:0; ttl:128; sid:1000003; rev:1;)
```

### Exercise 3: Service Version Detection
**Objective:** Detect Nmap service enumeration probes

**Sample Rules:**
```
alert tcp any any -> $HOME_NET any (msg:"Service Version Scan Attempt"; flow:to_server; flags:S; detection_filter: track by_src, count 20, seconds 30; sid:1000004; rev:1;)

alert http any any -> $HOME_NET any (msg:"HTTP Version Detection Probe"; http.method; content:"GET"; sid:1000005; rev:1;)
```

### Exercise 4: Metasploit Exploit Payload Detection
**Objective:** Identify Metasploit framework exploitation attempts

**Sample Rule:**
```
alert tcp any any -> $HOME_NET any (msg:"Metasploit Exploit Pattern Detected"; content:"|90 90 90 90|"; fast_pattern; sid:1000006; rev:1;)
```

### Exercise 5: Reverse Shell Connection Detection
**Objective:** Monitor for outbound connections to suspicious IPs

**Sample Rule:**
```
alert tcp $HOME_NET any -> $EXTERNAL_NET [4444,4445,31337] (msg:"Suspicious Outbound Connection - Possible Reverse Shell"; flow:to_server,established; sid:1000007; rev:1;)
```

### Exercise 6: Meterpreter Communication Detection
**Objective:** Detect Meterpreter callback traffic

**Sample Rule:**
```
alert tcp any any -> $HOME_NET any (msg:"Meterpreter Traffic Pattern"; flow:established; content:"|00 00 00|"; depth:3; sid:1000008; rev:1;)
```

### Exercise 7: Credential Harvesting Detection
**Objective:** Identify LDAP/SMB credential theft attempts

**Sample Rule:**
```
alert tcp any any -> $HOME_NET [389,636,445] (msg:"Potential Credential Harvesting Activity"; flow:to_server; threshold: type both, track by_src, count 5, seconds 60; sid:1000009; rev:1;)
```

## Exercises—Web-based attacks

These exercises focus on detecting web application attacks and exploitation attempts.

### Exercise 1: Web Server Enumeration
**Objective:** Detect excessive directory/file enumeration

**Sample Rule:**
```
alert http any any -> $HOME_NET any (msg:"Web Directory Enumeration Detected"; flow:to_server; threshold: type threshold, track by_src, count 30, seconds 60; sid:1000010; rev:1;)
```

### Exercise 2: Web Vulnerability Scanning
**Objective:** Identify automated vulnerability scanner activity

**Sample Rules:**
```
alert http any any -> $HOME_NET any (msg:"SQL Injection Probe Detected"; flow:to_server; content:"SELECT"; nocase; http_uri; sid:1000011; rev:1;)

alert http any any -> $HOME_NET any (msg:"XSS Attack Pattern"; flow:to_server; content:"<script"; nocase; http_uri; sid:1000012; rev:1;)
```

### Exercise 3: Metasploit Web Exploitation
**Objective:** Detect web-based exploit delivery

**Sample Rule:**
```
alert http any any -> $HOME_NET any (msg:"Metasploit Web Exploit Attempt"; flow:to_server; content:"exploit"; nocase; http_uri; sid:1000013; rev:1;)
```

### Exercise 4: Command Injection Detection
**Objective:** Identify OS command injection attempts

**Sample Rule:**
```
alert http any any -> $HOME_NET any (msg:"Command Injection Attempt"; flow:to_server; content:";"; http_uri; pcre:"/;(cat|ls|wget|curl|echo)/i"; sid:1000014; rev:1;)
```

### Exercise 5: Directory Traversal Detection
**Objective:** Detect path traversal attacks

**Sample Rule:**
```
alert http any any -> $HOME_NET any (msg:"Directory Traversal Attack"; flow:to_server; content:"../"; http_uri; threshold: type limit, track by_src, count 1, seconds 60; sid:1000015; rev:1;)
```

### Exercise 6: Cross-Site Scripting (XSS)
**Objective:** Detect XSS payload delivery

**Sample Rule:**
```
alert http any any -> $HOME_NET any (msg:"XSS Attack Vector Detected"; flow:to_server; content:"<script>"; nocase; fast_pattern; sid:1000016; rev:1;)
```

### Exercise 7: SQL Injection Detection
**Objective:** Identify SQL injection attempts and error messages

**Sample Rules:**
```
alert http any any -> $HOME_NET any (msg:"SQL Injection - UNION Attack"; flow:to_server; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; sid:1000017; rev:1;)

alert http $HOME_NET any -> any any (msg:"SQL Error Message in Response"; flow:to_client; content:"SQL syntax"; nocase; sid:1000018; rev:1;)
```

### Exercise 8: File Inclusion Attacks
**Objective:** Detect Local/Remote File Inclusion attempts

**Sample Rule:**
```
alert http any any -> $HOME_NET any (msg:"File Inclusion Attack Pattern"; flow:to_server; content:".."; http_uri; content:"/etc/passwd"; distance:0; nocase; sid:1000019; rev:1;)
```

### Exercise 9: CSRF Detection
**Objective:** Monitor for suspicious cross-origin requests

**Sample Rule:**
```
alert http any any -> $HOME_NET any (msg:"Potential CSRF Attack"; flow:to_server; content:"POST"; http_method; content:!"csrf"; nocase; sid:1000020; rev:1;)
```

### Exercise 10: Authentication Bypass
**Objective:** Detect authentication bypass techniques

**Sample Rule:**
```
alert http any any -> $HOME_NET any (msg:"Authentication Bypass Attempt"; flow:to_server; content:"admin=true"; nocase; http_uri; sid:1000021; rev:1;)
```

## Additional Resources

- [Official Suricata Documentation](https://suricata.readthedocs.io/)
- [Suricata Rule Writing Guide](https://suricata.readthedocs.io/en/latest/rules/)
- [Emerging Threats Ruleset](https://rules.emergingthreats.net/)

## Credits

This repository was inspired by and adapted from the excellent work at [0xrajneesh/Suricata-IDS-Home-Lab](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab). All content has been rewritten and restructured with original instructions and additional details.

## License

This project is available for educational and research purposes. Feel free to modify and adapt for your learning needs.

## Contributing

Contributions, suggestions, and improvements are welcome! Please feel free to submit issues or pull requests.
