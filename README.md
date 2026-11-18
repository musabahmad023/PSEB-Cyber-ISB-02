# Digital Forensics & Cyber Security Bootcamp

**Cohort:** PSEB-Cyber-ISB-02  
**Student Name:** Musab Ahmad  
**Student ID:** PSEB-2026-017582  
**Programme:** Digital Forensics & Cyber Security (Atomcamp & PSEB)  

---

## Repository Structure & Assignments

| Session / Directory | Topic | Key Deliverables | Status |
|---|---|---|---|
| [`s01-foundations/`](./s01-foundations/) | **Day 1:** Foundations, Linux, Networks | Malware taxonomy table, `chmod` permissions (symbolic, octal, set), public IP lookup, traceroute analysis | Completed |
| [`s06-scanning/`](./s06-scanning/) | **Day 2:** Nmap Scanning & Vulnerability Assessment | 3 complete findings (vsftpd 2.3.4, Anonymous FTP, SMB Null Session), host discovery comparison (Nmap, Netdiscover, Nmap -PR), CWE classification & remediation by class | Completed |
| [`s07-report/`](./s07-report/) | **Day 3:** Vulnerability Scanning to Reporting | Full VA/PT report (`.md` & `.pdf`), Greenbone/OpenVAS (GVM 23.11.0) 35-min scan (70 findings), Nmap NSE exploits (vsftpd root, distcc daemon), default credentials audit | Completed |
| [`s08-client-side/`](./s08-client-side/) | **Day 4:** Client-Side Attacks, Payloads & Career Paths | 9-family malware taxonomy, client-side payload delivery, Meterpreter session handling, UAC token restriction analysis, `fodhelper` UAC bypass to `NT AUTHORITY\SYSTEM`, PECA 2016 legal statement, Web Pentesting career roadmap | Completed |
| [`s05-web-recon/`](./s05-web-recon/) | **Day 5:** Web App Pentesting & Recon | Google Dorking exposures, GHDB & Exploit-DB (Apache case study), Shodan IoT exposure in Pakistan, 4-tool subdomain footprinting & reconciliation | Completed |
| [`s09-recon-and-upload/`](./s09-recon-and-upload/) | **Day 6:** Recon Workflow & DVWA File Upload | Custom 10-step recon methodology, DVWA File Upload exploitation across 4 security levels (Low, Medium, High, Impossible), management remediation brief | Completed |

---

### Verification and Lab Environment
- **Operating System:** Kali Linux (VMware Workstation) / Windows 11
- **Practice Targets:** Local Metasploitable 2 VM (`192.168.23.139`), Local Docker container (`vulnerables/web-dvwa`), `vulnweb.com` (Acunetix training site)
- **Tools Utilized:** Greenbone Vulnerability Management (GVM / OpenVAS), Nmap (NSE Vuln Engine, Host Discovery, Service/Version Detection), Netdiscover, Smbclient, Burp Suite Community Edition, OWASP ZAP, Subfinder, amass, assetfinder, theHarvester, Shodan, Exploit-DB / searchsploit, Gobuster, Ffuf, Katana.
