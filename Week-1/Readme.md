# 🔐 Vulnerability Analysis — IKB21004 & IKB21403
> **Task: File Analysis – Scanning Result**  
> Universiti Kuala Lumpur (UniKL)

---

## Question 1 - Analyse packet1.pcap and find the flag.

### Steps

**1. Open the file in Wireshark**

Launch Wireshark and open `packet1.pcap` via `File → Open`.

**2. Identify the protocol**

All 41 packets use **ICMP** (Internet Control Message Protocol) - ping request (type 8) and ping reply (type 0) between two hosts.

| Field | Value |
|---|---|
| Source | `10.66.66.1` |
| Destination | `10.66.66.2` |
| Protocol | ICMP (Echo Request / Echo Reply) |
| Total Packets | 41 |

**3. Filter ICMP traffic and inspect payloads**

Apply an `icmp` display filter, then inspect the **Data** section of each packet. Most packets carry a standard repeating ping payload.

![ICMP](assets/Question-1/Filter-ICMP.png)

**4. Spot the anomalous packet - Packet 37**

Packet 37 **ICMP** Echo Reply, `type 0` stands out. Its payload contains a readable ASCII string instead of normal ping padding:

![Packet37]
<img width="827" height="1181" alt="Akid_Passport" src="https://github.com/user-attachments/assets/af3aa726-50a5-4476-84f7-3c9a966815a0" />


* **ASCII string**

    ```bash
    U1VDVEYyMDIze2FpX2lzX2Nvb2x9
    ```

**5. Decode the payload (Base64)**

Decode using [CyberChef](https://gchq.github.io/CyberChef/) with the **From Base64** operation.

![Decode](assets/Question-1/Decode-the-payload-Base64.png)

* **Flag:**

    ```bash
    SUCTF2023{ai_is_cool}
    ```

---

## Question 2 - Analyse packet2.pcap and find the flag.

### Traffic Found

| # | Traffic Type | Details |
|---|---|---|
| 1 | ICMP (668 packets) | Standard ping traffic `172.24.20.31 → 171.64.20.62`. No flag hidden here. |
| 2 | TCP Chat (Port 4444) | WarGames movie reference conversation. |
| 3 | FTP Session (Port 21) | Client downloaded `global_thermonuclear_war.gamerules.txt` via PASV mode. |
| 4 | Tic-Tac-Toe Dialogue (Ports 8888–10112) | Another WarGames reference. |

### Key Finding - FTP File Content

![FTP](assets/Question-2/Key-Finding-FTP-File-Content.png)

* The file `global_thermonuclear_war.gamerules.txt` transferred via FTP contained:

    ```
    https://tinyurl.com/yr5zprz4
    ```

### Decoding the Flag

![Website](assets/Question-2/website.png)

* The URL leads to a **Google Doc "Club Tux"** containing images of **Pigpen cipher** symbols - a substitution cipher that uses tic-tac-toe grid fragments as letters.

Decode using the Tic-Tac-Toe cipher at [dCode](https://www.dcode.fr/tic-tac-toe-cipher).

![Decode](assets/Question-2/Decoding-the-Flag.png)

* **Flag:**

    ```bash
    SUCTF2023{EXMACHINAAVA}
    ```

---

## Question 3 - Interpret an Nmap Output

### Scanned Ports

| Port | State | Service | Version |
|---|---|---|---|
| 21/tcp | open | FTP | vsftpd 2.3.4 |
| 22/tcp | open | SSH | OpenSSH 5.3p1 |
| 80/tcp | open | HTTP | Apache 2.2.8 |
| 139/tcp | open | NetBIOS-SSN | — |
| 445/tcp | open | SMB | Windows 7 Professional 7601 SP1 |

### 1. What can an attacker do with each port?

| Port | Service | Potential Attack |
|---|---|---|
| 21/tcp | FTP (vsftpd 2.3.4) | Anonymous login, file upload/download, backdoor shell, brute-force |
| 22/tcp | SSH (OpenSSH 5.3p1) | Brute-force, exploit old SSH vulnerabilities, gain remote shell |
| 80/tcp | HTTP (Apache 2.2.8) | SQLi, XSS, directory traversal, exploit outdated Apache bugs |
| 139/tcp | NetBIOS-SSN | Share/user enumeration, relay attacks, capture NTLM hashes |
| 445/tcp | SMB (Windows 7 SP1) | EternalBlue exploit, pass-the-hash, ransomware, lateral movement |

### 2. What vulnerabilities are likely present based on the version?

| Port | Version | CVE / Vulnerability |
|---|---|---|
| 21 | vsftpd 2.3.4 | **CVE-2011-2523** - Backdoor opens a root shell on port 6200 when `:)` is sent as username. CVSS 10.0 |
| 22 | OpenSSH 5.3p1 | **CVE-2010-4478** (J-PAKE bypass), memory corruption bugs, brute-force susceptibility |
| 80 | Apache 2.2.8 | **CVE-2017-7679** (mod_mime buffer overflow), **CVE-2007-6750** (DoS), directory traversal |
| 139/445 | Windows 7 SP1 7601 | **CVE-2017-0144 (EternalBlue / MS17-010)** — SMB remote code execution. CVSS 9.3 |

### 3. Which one is the highest risk and why?

**Port 445 (SMB / MS17-010 EternalBlue)** - closely followed by **Port 21 (vsftpd backdoor)**

**Reasoning:**
- MS17-010 allows **unauthenticated RCE as SYSTEM** - no credentials required.
- Weaponised in **WannaCry** and **NotPetya** ransomware; automated exploit tools exist freely.
- Windows 7 SP1 is **end-of-life** (no patches since January 2020).
- vsftpd 2.3.4 carries a **CVSS of 10.0** and yields direct root access on Linux.

### 4. What attack path can be built from this?

- **Path 1 (Quick Win):** Use Metasploit to exploit the vsftpd 2.3.4 backdoor for an initial root shell.
- **Path 2 (SMB):** Run `nmap --script smb-vuln-ms17-010` against port 445 to confirm EternalBlue, then exploit for a SYSTEM-level reverse shell.

### 5. What should be the remediation?

| Area | Action |
|---|---|
| Patch Management | Upgrade vsftpd, Apache, and OpenSSH to their latest stable versions |
| OS Upgrade | Migrate from Windows 7 EOL to Windows 10/11; apply MS17-010 patch if immediate upgrade isn't possible |
| Firewall Rules | Restrict ports 21 and 22 to trusted IP addresses only |

---

## Question 4 - Iden fy the OS (OS Fingerprin ng) - TTL

Image 1

![Image 1](assets/Question-4/Image-1.png)

* `ttl=64`: **Linux/Unix-based OS**

Image 2

![Image 2](assets/Question-4/image-2.png)

* `Time to live`: 255: **Cisco router/switch or Solaris Unix**

Image 3

![Image 3](assets/Question-4/image-3.png)

* `ttl=128`: **Windows OS**

Operating systems can be identified by the **Time To Live (TTL)** value in ICMP ping replies.

| TTL Value | Operating System |
|---|---|
| **64** | Linux / Unix-based systems |
| **128** | Windows operating systems |
| **255** | Network devices (Cisco routers/switches) or Solaris Unix |

---

## Question 5 - Analyse the Nessus file

**File:** `Network_Scan.nessus` 

**Vulnerability:** **Ghostcat (CVE-2020-1938)**

### 1. What is the affected Port number

| Port | Service |
|---|---|
| **8009/tcp** | Apache JServ Protocol (AJP) connector on Apache Tomcat |

### 2. What is the Affected protocol 

**AJP13 over TCP** - the protocol Tomcat uses to accept requests from a web server front-end.

### 3. What is the CVSS Score of vulnerability found

| Metric | Score |
|---|---|
| CVSSv3 Base Score | **9.8 (Critical)** |
| CVSSv3 Temporal Score | 8.8 |
| CVSSv3 Vector | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| CVSSv2 Base Score | 7.5 (High) |
| VPR Score | 9.6 |

### 4. Can you find any exploit related to this vulnerability?

| Source | Details |
|---|---|
| ExploitDB EDB-ID 48143 | Python-based public PoC for file read primitive |
| Metasploit | `auxiliary/admin/http/tomcat_ghostcat` - automated exploitation module |
| GitHub PoCs | Target LFI and, if file upload is enabled, RCE |
| CNVD-2020-10487 | Original Chinese NVD disclosure accompanying the public PoC |

### 5. Find CVE for this vulnerability

**CVE-2020-1938**

- Published: **20 February 2020**
- Affects Apache Tomcat versions prior to `9.0.31`, `8.5.51`, and `7.0.100`
- **Fix:** Update Tomcat to a patched version, or disable the AJP connector entirely

---
