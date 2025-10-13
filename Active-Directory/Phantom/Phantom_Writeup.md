# Phantom CTF Writeup

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

### Initial Enumeration and Reconnaissance

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
      
      ```
      SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False) (Null Auth:True)
      SMB         10.129.234.63   445    DC               [+] phantom.vl\a: (Guest)
      ```
      With both guest and null bindings working, further enumeration is done with a guest account as they are typically more permissive.
    * Using NetExec, we can also attempt to list shares and users. `nxc smb 10.129.234.63 -u 'a' -p '' --shares --log guest_shares.txt`
      - Shares - Interesting list, "Public" with read access is an immediate thing to note for further enumeration.
         ```
          SMB         10.129.234.63   445    DC               [*] Enumerated shares
          SMB         10.129.234.63   445    DC               Share           Permissions     Remark
          SMB         10.129.234.63   445    DC               -----           -----------     ------
          SMB         10.129.234.63   445    DC               ADMIN$                          Remote Admin
          SMB         10.129.234.63   445    DC               C$                              Default share
          SMB         10.129.234.63   445    DC               Departments Share
          SMB         10.129.234.63   445    DC               IPC$            READ            Remote IPC
          SMB         10.129.234.63   445    DC               NETLOGON                        Logon server share
          SMB         10.129.234.63   445    DC               Public          READ
          SMB         10.129.234.63   445    DC               SYSVOL                          Logon server share
         ```
      - Users - Nothing here, our guest access is likely limited
         ```
          SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False) (Null Auth:True)
          SMB         10.129.234.63   445    DC               [+] phantom.vl\a: (Guest)
         ```
      - We can attempt a RID bruteforce and get a rough list of users or groups
        `nxc smb 10.129.234.63 -u 'a' -p '' --rid-brute --log rid_scan.txt`
          ```
          <SNIP>
          SMB         10.129.234.63   445    DC               1000: PHANTOM\DC$ (SidTypeUser)
          SMB         10.129.234.63   445    DC               1101: PHANTOM\DnsAdmins (SidTypeAlias)
          SMB         10.129.234.63   445    DC               1102: PHANTOM\DnsUpdateProxy (SidTypeGroup)
          SMB         10.129.234.63   445    DC               1103: PHANTOM\svc_sspr (SidTypeUser)
          SMB         10.129.234.63   445    DC               1104: PHANTOM\TechSupports (SidTypeGroup)
          SMB         10.129.234.63   445    DC               1105: PHANTOM\Server Admins (SidTypeGroup)
          SMB         10.129.234.63   445    DC               1106: PHANTOM\ICT Security (SidTypeGroup)
          SMB         10.129.234.63   445    DC               1107: PHANTOM\DevOps (SidTypeGroup)
          SMB         10.129.234.63   445    DC               1108: PHANTOM\Accountants (SidTypeGroup)
          SMB         10.129.234.63   445    DC               1109: PHANTOM\FinManagers (SidTypeGroup)
          SMB         10.129.234.63   445    DC               1110: PHANTOM\EmployeeRelations (SidTypeGroup)
          SMB         10.129.234.63   445    DC               1111: PHANTOM\HRManagers (SidTypeGroup)
          SMB         10.129.234.63   445    DC               1112: PHANTOM\rnichols (SidTypeUser)
          SMB         10.129.234.63   445    DC               1113: PHANTOM\pharrison (SidTypeUser)
          SMB         10.129.234.63   445    DC               1114: PHANTOM\wsilva (SidTypeUser)
          SMB         10.129.234.63   445    DC               1115: PHANTOM\elynch (SidTypeUser)
          SMB         10.129.234.63   445    DC               1116: PHANTOM\nhamilton (SidTypeUser)
          SMB         10.129.234.63   445    DC               1117: PHANTOM\lstanley (SidTypeUser)
          SMB         10.129.234.63   445    DC               1118: PHANTOM\bbarnes (SidTypeUser)
          SMB         10.129.234.63   445    DC               1119: PHANTOM\cjones (SidTypeUser)
          SMB         10.129.234.63   445    DC               1120: PHANTOM\agarcia (SidTypeUser)
          SMB         10.129.234.63   445    DC               1121: PHANTOM\ppayne (SidTypeUser)
          SMB         10.129.234.63   445    DC               1122: PHANTOM\ibryant (SidTypeUser)
          SMB         10.129.234.63   445    DC               1123: PHANTOM\ssteward (SidTypeUser)
          SMB         10.129.234.63   445    DC               1124: PHANTOM\wstewart (SidTypeUser)
          SMB         10.129.234.63   445    DC               1125: PHANTOM\vhoward (SidTypeUser)
          SMB         10.129.234.63   445    DC               1126: PHANTOM\crose (SidTypeUser)
          SMB         10.129.234.63   445    DC               1127: PHANTOM\twright (SidTypeUser)
          SMB         10.129.234.63   445    DC               1128: PHANTOM\fhanson (SidTypeUser)
          SMB         10.129.234.63   445    DC               1129: PHANTOM\cferguson (SidTypeUser)
          SMB         10.129.234.63   445    DC               1130: PHANTOM\alucas (SidTypeUser)
          </SNIP>
          ```
        </details>
### Exploitation Steps

1. 
2. 
3. 

### Privilege Escalation



### Post-Exploitation


### Tools Used


### Mitigations



### Lessons Learned



