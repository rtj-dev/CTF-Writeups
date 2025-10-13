# Phantom CTF Example Writeup

## Non-Technical Summary

### Overview

The "Phantom" CTF, simulates a Windows Active Directory network, typical of corporate environments. 

### Key Findingss

### Impact

These issues could allow an attacker to:
- Encrypt and/or steal all on-premises data
- Disrupt critical systems, causing indefinite downtime.
- Gain complete domain control, compromising all systems, establishing powerful persistence.


### Recommendations



## Technical Writeup

### Introduction

"Phantom" is a medium-difficulty Windows Active Directory machine on **Hack the Box**. As usual, the objective was to achieve both **user** and **Root/Administrator** flags. 

### Initial Enumeration

* **Tools**: `nmap`, `NetExec`
- Scanned the target with `nmap -sC -sV 10.129.234.63 -oA Outputs/nmap/initial`.
  - **Output HTML:** https://html-preview.github.io/?url=https://github.com/rtj-dev/CTF-Writeups/blob/main/Active-Directory/Phantom/Outputs/nmap/initial_syn_scan.html
  - **Output**:
    ```
    # Nmap 7.93 scan initiated Mon Oct 13 18:20:06 2025 as: nmap -sC -sV -oA Outputs/nmap/initial 10.129.234.63
    Nmap scan report for 10.129.234.63
    Host is up (0.043s latency).
    Not shown: 988 filtered tcp ports (no-response)
    PORT     STATE SERVICE       VERSION
    53/tcp   open  domain        Simple DNS Plus
    88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-13 17:20:28Z)
    135/tcp  open  msrpc         Microsoft Windows RPC
    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: phantom.vl0., Site: Default-First-Site-Name)
    445/tcp  open  microsoft-ds?
    464/tcp  open  kpasswd5?
    593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp  open  tcpwrapped
    3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: phantom.vl0., Site: Default-First-Site-Name)
    3269/tcp open  tcpwrapped
    3389/tcp open  ms-wbt-server Microsoft Terminal Services
    | ssl-cert: Subject: commonName=DC.phantom.vl
    | Not valid before: 2025-10-12T16:34:25
    |_Not valid after:  2026-04-13T16:34:25
    |_ssl-date: 2025-10-13T17:21:12+00:00; -2s from scanner time.
    | rdp-ntlm-info:
    |   Target_Name: PHANTOM
    |   NetBIOS_Domain_Name: PHANTOM
    |   NetBIOS_Computer_Name: DC
    |   DNS_Domain_Name: phantom.vl
    |   DNS_Computer_Name: DC.phantom.vl
    |   DNS_Tree_Name: phantom.vl
    |   Product_Version: 10.0.20348
    |_  System_Time: 2025-10-13T17:20:29+00:00
    Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    |_clock-skew: mean: -2s, deviation: 0s, median: -2s
    | smb2-time:
    |   date: 2025-10-13T17:20:31
    |_  start_date: N/A
    | smb2-security-mode:
    |   311:
    |_    Message signing enabled and required
      
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Mon Oct 13 18:21:16 2025 -- 1 IP address (1 host up) scanned in 70.01 seconds
    ```
     * Immedidate findings give us information that this is a typical Domain Controller, relevant records like phantom.v1, DC.phantom.v1 help with DNS
     * SMB signing is enabled and required
  - Enumerating SMB 
    - With no initial access given, null and guest access is attemped
    - `nxc smb 10.129.234.63 -u 'a' -p '' --log guest_scan.txt`
      - **Output:**
          ```
          SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False) (Null Auth:True)
          SMB         10.129.234.63   445    DC               [+] phantom.vl\a: (Guest)
          ```
      * With both guest and null bindings working, further enumeration is done with a guest account as they are typically more permissive.
    * Using NetExec, we find we can list shares. `nxc smb 10.129.234.63 -u 'a' -p '' --shares --log guest_shares.txt`
       
      
    

### Exploitation Steps

1. 
2. 
3. 

### Privilege Escalation



### Post-Exploitation


### Tools Used


### Mitigations



### Lessons Learned



