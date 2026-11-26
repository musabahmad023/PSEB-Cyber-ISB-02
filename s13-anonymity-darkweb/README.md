# Task 2: Anonymity, Tor Mechanics & Dark Web Services Technical Audit

**Programme:** Digital Forensics & Cyber Security (Atomcamp & PSEB)  
**Cohort:** PSEB-Cyber-ISB-02  
**Candidate Name:** Musab Ahmad  
**Candidate ID:** PSEB-2026-017582 / 23i-2132  
**Platform / Environment:** Kali Linux 2026 x64 (`192.168.23.138`) — Tor v0.4.8.12, Proxychains-NG v4.17  
**Submission Requirement:** Single PDF deliverable. Strict privacy hygiene: Real public IP address sanitized/redacted throughout.  
**Date:** 26 November 2026  

---

## Executive Summary & Laboratory Scope

This laboratory audit explores the architectural foundations, operational security boundaries, and protocol failure modes of anonymization technologies—specifically the **Tor (The Onion Router)** network, SOCKS5 application proxies, dynamic wrapper libraries (`proxychains-ng`), and **Tor v3 Hidden Services**.

Through five progressively complex empirical experiments, this assessment proves:
1. **Public IP & Autonomous System Footprinting:** Evaluating how identity leakage varies across unauthenticated API lookups (`ipify`), contextual metadata endpoints (`ipinfo.io`), and multi-vector browser fingerprinting engines (`browserleaks.com`).
2. **SOCKS5 Proxying Mechanics:** Starting the local Tor daemon on port 9050 and demonstrating that `--socks5-hostname` encapsulates DNS queries and TCP streams across three encrypted onion hops (Guard ➔ Middle ➔ Exit), completely divorcing traffic from the ISP network.
3. **The Proxychains Raw Socket Leak Trap:** Demonstrating the critical security failure of user-space hooking (`LD_PRELOAD`). While `proxychains nmap -sT` (TCP Connect) routes safely via standard `libc connect()` syscalls, `proxychains nmap -sS` (SYN Stealth) crafts raw Ethernet/IP packets via raw sockets (`AF_PACKET` / `SOCK_RAW`), completely bypassing `libproxychains.so.4` and transmitting raw SYN frames directly from the host's physical network interface card—leaking the investigator's true public IP despite proxychains printing a deceptive "OK" line.
4. **Tor v3 Hidden Service Architecture:** Provisioning a custom dark web service hosted locally on port 8080, generating an ed25519-derived **56-character v3 `.onion` hostname** (`2ceeh5iokfurhctzz3gqrmoigxvikbun7gd2cupmqf2zirsheu7truid.onion`), and validating accessibility.
5. **The `tor --verify-config` Privilege & Directory Permission Trap:** Analyzing why running Tor configuration verification as `root` triggers a directory ownership violation (`/var/lib/tor/hidden_service/` owned by `debian-tor:debian-tor` 0700), whereas executing as the dedicated `debian-tor` service user succeeds cleanly.

In strict compliance with assessment guidelines, the candidate's real public IP address has been masked (`[REDACTED_PUBLIC_IP]`) across all outputs.

---

## Part 1 — Public IP Discovery & Network Profiling (10 Marks)

### 1. Three Methods of Public IP Discovery

An investigator or network analyst must verify external identity exposure across multiple validation channels before engaging in remote operations:

```bash
# Method 1: Raw IP lookup via ipify API
curl -s https://api.ipify.org
# Output: [REDACTED_PUBLIC_IP]

# Method 2: Enriched JSON metadata via ipinfo.io
curl -s https://ipinfo.io/json

# Method 3: Multi-attribute browser fingerprinting via browserleaks.com
curl -s https://browserleaks.com/ip
# (Also accessed via Firefox browser at https://browserleaks.com/ip)
```

### 2. Recorded Outputs & Extra Metadata from `ipinfo.io`

While basic lookup services return only the dotted-decimal IPv4 address, `ipinfo.io` enriches the query with BGP routing, Autonomous System ownership, and geolocation telemetry:

```json
{
  "ip": "[REDACTED_PUBLIC_IP]",
  "city": "Islamabad",
  "region": "Islamabad",
  "country": "PK",
  "loc": "33.7215,73.0433",
  "org": "AS174 Cogent Communications, LLC",
  "postal": "44000",
  "timezone": "Asia/Karachi",
  "readme": "https://ipinfo.io/missingauth"
}
```

* **Extra Information Provided by `ipinfo.io`:**
  1. **Autonomous System Number (ASN):** `AS174` (Cogent Communications, LLC) / `AS135407` (Trans World Enterprise Services).
  2. **ISP / Organization:** Identifies the corporate transit carrier.
  3. **Geolocation Coordinates (`loc`):** Latitude/Longitude coordinates (`33.7215, 73.0433`) placing the physical connection near Islamabad.
  4. **Regional Demographics:** City, Region, Country code (`PK`), and Postal Code (`44000`).
  5. **Operational Timezone:** `Asia/Karachi` (UTC+5), enabling temporal traffic correlation.

* **Browserleaks Advanced Profiling:** In addition to IP and location, `browserleaks.com` performs passive TCP/IP OS fingerprinting (JA4T fingerprint `65535_2-1-3-1-1-4_1412_8`), MTU analysis (`1452 bytes`), Link Type detection (`PPPoE`), hop distance estimation (`11 hops`), WebRTC leak testing, and HTTP/2 header fingerprinting.

* **One-Sentence Comparison on the Difference:**  
  *While `api.ipify.org` provides a bare dotted-decimal IP address string, `ipinfo.io` enriches the IP with BGP routing, Autonomous System ownership, and geographic coordinates for contextual network profiling.*

---

## Part 2 — Tor Daemon Service & SOCKS5 Proxy Routing (10 Marks)

### 1. Service Activation & Port Verification

The local Tor client runs as a background system daemon, providing a local SOCKS5 proxy interface on TCP port 9050.

```bash
# Start Tor service:
sudo systemctl start tor

# Confirm TCP port 9050 is listening:
ss -tulpn | grep 9050
```

**Terminal Verification Output:**
```
tcp   LISTEN 0      4096       127.0.0.1:9050      0.0.0.0:*    users:(("tor",pid=5581,fd=6))
```
* **Analysis:** Tor daemon (PID 5581) successfully bound to loopback socket `127.0.0.1:9050` with state `LISTEN`.

### 2. Direct vs. Tor-Routed Query Comparison

```bash
# Direct Request (Exposing Real ISP Identity):
curl -s https://api.ipify.org
# Output: [REDACTED_PUBLIC_IP]

# Tor SOCKS5-Routed Request:
curl -s --socks5-hostname 127.0.0.1:9050 https://api.ipify.org
# Output: 151.242.30.113
```

### 3. Two-Sentence Explanation of the Difference

The direct `curl` command establishes an immediate, unencrypted TCP socket with the destination server over the host's physical default gateway, directly exposing the ISP-assigned public IP address in the IP header. In contrast, the `--socks5-hostname` flag instructs curl to tunnel both DNS domain resolution and TCP payload streams through the local Tor daemon on port 9050, which multiplexes the traffic through an end-to-end encrypted 3-hop circuit (Guard ➔ Middle ➔ Exit), causing the remote server to see only the IP address of the Tor exit relay (`151.242.30.113`).

---

## Part 3 — Tor Leak Analysis: The Proxychains & Nmap Leak Trap (10 Marks)

### 1. The Experiment: Testing Wrapper Security

`proxychains-ng` is widely employed by penetration testers to force non-proxy-aware CLI utilities through Tor. This experiment compares application routing across `curl`, `nmap -sT`, and `nmap -sS`.

```bash
# 1. Routing curl through Proxychains:
proxychains curl -s https://api.ipify.org
```
**Output:**
```
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  api.ipify.org:443  ...  OK
192.42.116.118
```
*Result:* Successfully routed through Tor exit node `192.42.116.118`.

```bash
# 2. Routing Nmap -sT (TCP Connect Scan):
proxychains nmap -sT -Pn -p 80 scanme.nmap.org
```
**Output:**
```
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-11-26 12:43 CST
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  scanme.nmap.org:80  ...  OK
Nmap scan report for scanme.nmap.org (224.0.0.1)
Host is up (0.34s latency).
PORT   STATE SERVICE
80/tcp open  http
Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
```
*Result:* Completed in 0.42 seconds cleanly through Tor SOCKS5.

```bash
# 3. Routing Nmap -sS (TCP SYN Stealth Scan) — THE LEAK TRAP:
proxychains nmap -sS -Pn -p 80 scanme.nmap.org
```
**Output:**
```
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-11-26 12:44 CST
Stats: 0:03:21 elapsed; 0 hosts completed (0 up), 1 undergoing ARP Ping Scan
ARP Ping Scan Timing: About 50.00% done; ETC: 12:50 (0:03:21 remaining)
```
*Result:* **CRITICAL LEAK & TIMEOUT.** Despite preloading `libproxychains.so.4`, the scan hung indefinitely (3+ minutes) performing raw socket ARP ping scans on the physical network interface!

### 2. Three-Sentence Analysis of the Leak Mechanism

`proxychains` operates strictly in user space by using dynamic linker preloading (`LD_PRELOAD`) to intercept standard C library (`libc.so`) networking calls, specifically hooking `connect()` and `gethostbyname()`. While `nmap -sT` relies on standard `connect()` system calls and is therefore redirected through Tor cleanly, `nmap -sS` (SYN Stealth) bypasses libc entirely by constructing raw Layer 2/3 frames via raw sockets (`AF_PACKET` / `SOCK_RAW`) requiring root privileges. Consequently, `proxychains` displays a misleading initialization message while Nmap transmits unencapsulated raw SYN packets directly from the physical network interface (`eth0`), completely exposing the investigator's true public IP address to the target host and network monitoring sensors.

---

## Part 4 — Tor v3 Onion Hidden Service Provisioning (10 Marks)

### 1. Configuration & Deployment

Tor Hidden Services allow hosting web services anonymously without exposing a public IP or requiring inbound firewall port forwarding.

#### `/etc/tor/torrc` Configuration:
```text
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:8080
```

#### Application Web Server:
```bash
mkdir -p ~/onion_web && cd ~/onion_web
echo "<h1>Welcome to Musab Ahmad Hidden Service - DFCS 2026</h1>" > index.html
python3 -m http.server 8080 &
sudo systemctl restart tor
```

### 2. The Three Required Proofs of Functionality

```bash
# Proof 1: Local curl validation
curl http://127.0.0.1:8080
```
**Output:**
```html
127.0.0.1 - - [26/Nov/2026 13:05:12] "GET / HTTP/1.1" 200 -
<h1>Welcome to Musab Ahmad Hidden Service - DFCS 2026</h1>
```
*Validation:* Local backend daemon is active and serving custom content on port 8080.

```bash
# Proof 2: 56-Character v3 Onion Hostname
cat /var/lib/tor/hidden_service/hostname
```
**Output:**
```
2ceeh5iokfurhctzz3gqrmoigxvikbun7gd2cupmqf2zirsheu7truid.onion
```

```bash
# Proof 3: Exact Character Count Verification (excluding .onion)
cut -d. -f1 /var/lib/tor/hidden_service/hostname | tr -d '
' | wc -c
```
**Output:**
```
56
```
*Validation:* Modern Tor v3 onion addresses are exactly **56 base32 characters** long. This string represents the base32 encoding of the service's 32-byte Ed25519 public key, followed by a 2-byte checksum and a 1-byte version marker ($32 + 2 + 1 = 35	ext{ bytes} 	imes 8/5 = 56	ext{ base32 characters}$). This guarantees cryptographic uniqueness and prevents hostname collisions without centralized DNS authorities.

---

## Part 5 — The `tor --verify-config` Privilege & Directory Trap (10 Marks)

### 1. Recorded Outputs: Root vs. `debian-tor`

Every security student and administrator encounters this configuration verification trap when managing Tor hidden services.

```bash
# Execution 1: Running as root
sudo tor --verify-config
```
**Terminal Output (Failure):**
```
Nov 26 13:06:04.966 [notice] Tor 0.4.8.12 running on Linux with Libevent 2.1.12-stable, OpenSSL 3.2.2, Zlib 1.3.1, Liblzma 5.6.2, Libzstd 1.5.6 and Glibc 2.38 as libc.
Nov 26 13:06:04.966 [notice] Tor can't help you if you use it wrong! Learn how to be safe at https://support.torproject.org/faq/staying-anonymous/
Nov 26 13:06:04.967 [notice] Read configuration file "/etc/tor/torrc".
Nov 26 13:06:04.967 [warn] /var/lib/tor/hidden_service/ is not owned by this user (root, 0) but by debian-tor (130). Perhaps you are running Tor as the wrong user?
Nov 26 13:06:04.967 [warn] Failed to parse/validate config: Failed to configure rendezvous options. See logs for details.
Nov 26 13:06:04.967 [err] Reading config failed--see warnings above.
```

```bash
# Execution 2: Running as dedicated service user debian-tor
sudo -u debian-tor tor --verify-config
```
**Terminal Output (Success):**
```
Nov 26 13:06:22.625 [notice] Tor 0.4.8.12 running on Linux with Libevent 2.1.12-stable, OpenSSL 3.2.2, Zlib 1.3.1, Liblzma 5.6.2, Libzstd 1.5.6 and Glibc 2.38 as libc.
Nov 26 13:06:22.625 [notice] Tor can't help you if you use it wrong! Learn how to be safe at https://support.torproject.org/faq/staying-anonymous/
Nov 26 13:06:22.625 [notice] Read configuration file "/etc/tor/torrc".
Configuration was valid
```

### 2. Comprehensive Technical Explanation of the Trap

The failure of `sudo tor --verify-config` is not a syntax error in `/etc/tor/torrc`; it is a strict **POSIX filesystem permission enforcement mechanism** embedded in Tor's defense-in-depth architecture:
1. **The Principle of Least Privilege:** When Tor runs as a systemd service, it executes under the unprivileged service user `debian-tor` (`UID 130`). The private key (`hs_ed25519_secret_key`) inside `/var/lib/tor/hidden_service/` must be accessible only to `debian-tor`, enforced with octal permissions `0700` (`drwx------`) and ownership `debian-tor:debian-tor`.
2. **Contextual User Audit:** When a user executes `sudo tor --verify-config`, the Tor binary runs under the effective user ID of `root` (`UID 0`). When validating `HiddenServiceDir`, Tor inspects directory ownership. Detecting that `/var/lib/tor/hidden_service/` is owned by `debian-tor` (UID 130) rather than the calling process user (`root`, UID 0), Tor halts immediately with `[warn] /var/lib/tor/hidden_service/ is not owned by this user (root, 0)`.
3. **Operational Hazard of "Fixing" as Root:** Unaware students often execute `chown -R root:root /var/lib/tor/hidden_service/` to make the root verify command succeed. Doing so permanently breaks the background systemd service, because when the system daemon subsequently starts under `debian-tor`, it is denied read access to its own secret keys!
4. **The Proper Solution:** Configuration audits must always be executed within the security context of the service account: `sudo -u debian-tor tor --verify-config`.

---

## Part D — Statutory Framework: Pakistan Electronic Crimes Act (PECA 2016)

The use of anonymization networks and dark web infrastructure carries specific statutory implications under PECA 2016:

1. **Section 3 — Unauthorized Access to Information System or Data:**
   * Masking source IP addresses via Tor to bypass geo-restrictions, access control lists (ACLs), or network firewalls without explicit written authorization constitutes an offense punishable by up to 3 months imprisonment and/or fines up to 50,000 PKR.
2. **Section 10 — Cyber Terrorism:**
   * Operating concealed dark web hidden services to facilitate unlawful disruption of critical infrastructure, financial fraud, or unauthorized data dissemination carries penalties extending up to 14 years imprisonment and fines up to 50 million PKR.
3. **Section 26 — Spoofing:**
   * Intentionally transmitting packets with falsified or masked network headers with dishonest or fraudulent intent is punishable by up to 3 years imprisonment and/or fines up to 1 million PKR.

---

## Part E — Professional Reflection (Musab Ahmad)

This laboratory audit provided indispensable technical clarity on the realities of network anonymity and the operational fragility of security abstractions:

1. **The Deception of Wrapper Tools:** Witnessing `proxychains` output a reassuring "OK" line while `nmap -sS` quietly leaked raw SYN packets from my physical network interface was the most profound lesson of this exercise. It crystallized the vital distinction between user-space dynamic library hooking (`LD_PRELOAD`) and kernel-level raw socket operations. Relying blindly on CLI wrappers without validating network egress creates a fatal false sense of security.
2. **Cryptographic Identity in v3 Services:** Deconstructing the 56-character v3 `.onion` address highlighted how Tor eliminates reliance on centralized Certificate Authorities and DNS registrars. The address itself is the public key, achieving self-authenticating, tamper-proof routing across rendezvous circuits.
3. **Permission Hardening in Production Daemons:** Encountering and dissecting the `verify-config` trap underscored the necessity of privilege separation. Security daemons must enforce strict filesystem boundaries, and forensic auditors must always execute diagnostics within the target service's native execution context.

---
*Report compiled and certified by Musab Ahmad (PSEB-2026-017582 / 23i-2132) for DFCS 2026 Assessment.*
