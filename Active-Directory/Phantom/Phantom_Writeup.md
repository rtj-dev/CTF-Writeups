
# Phantom CTF Writeup

## Non-Technical Summary

### Overview

The "Phantom" CTF simulates a Windows Active Directory network, typical of corporate environments. This writeup details the steps taken to gain unauthorized access and compromise the domain controller.

### Key Findings

During the CTF, several vulnerabilities were identified, including:
*   Weak SMB permissions allowing guest access to sensitive shares.
*   The presence 
*   Specific Active Directory misconfigurations that facilitated privilege escalation like RBCD.

### Impact

These identified issues could allow an attacker to:
*   Encrypt and/or steal all on-premises data.
*   Disrupt critical systems, causing indefinite downtime.
*   Gain complete domain control, compromising all systems and establishing powerful persistence.

### Recommendations

To mitigate the discovered vulnerabilities, it is recommended to:
*   Review and restrict SMB share permissions, especially for guest accounts.
*   Implement 
*   Regularly 

---

## Technical Writeup

### Introduction

"Phantom" is a medium-difficulty Windows Active Directory machine on **Hack the Box**. As usual, the objective was to achieve both **user** and **Root/Administrator** flags. This writeup will detail the methodology and tools used to compromise the target.

### Initial Enumeration and Reconnaissance

*   **Tools**: `nmap`, `NetExec`
  
My initial reconnaissance phase focused on gathering as much information as possible about the target system, `10.129.234.63`.

#### Nmap Scan
*   **Command**: `nmap -sC -sV 10.129.234.63 -oA Outputs/nmap/initial`

An `nmap` scan revealed a standard Windows Domain Controller setup, with several key services open:
*   **Port 53 (DNS)**: `Simple DNS Plus`
*   **Port 88 (Kerberos)**: `Microsoft Windows Kerberos`
*   **Port 135 (MSRPC)**: `Microsoft Windows RPC`
*   **Port 139 (NetBIOS-SSN)**: `Microsoft Windows netbios-ssn`
*   **Port 389 (LDAP)**: `Microsoft Windows Active Directory LDAP (Domain: phantom.vl)`
*   **Port 445 (SMB)**: `Microsoft Windows` (SMB signing enabled and required)
*   **Port 3389 (RDP)**: `Microsoft Terminal Services`

The `nmap` output immediately provided crucial domain information: `phantom.vl` and `DC.phantom.vl`.

For a full breakdown of the Nmap scan, see the [HTML output](https://html-preview.github.io/?url=https://github.com/rtj-dev/CTF-Writeups/blob/main/Active-Directory/Phantom/Outputs/nmap/initial_syn_scan.html).



#### SMB Enumeration with NetExec

With SMB port 445 open, I proceeded to enumerate shares and users using `NetExec`.

**1. Null/Guest Access Check:**

Initially, I attempted to authenticate with null and guest credentials.
*   **Command**: `nxc smb 10.129.234.63 -u 'a' -p '' --log Outputs/nxc/guest_scan.txt`

```
SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.234.63   445    DC               [+] phantom.vl\a: (Guest)
```
The output confirmed that both guest and null bindings were working, indicating potential for further enumeration with guest privileges.

**2. Listing Shares:**

Leveraging the guest access, we can list available SMB shares.
*   **Command**: `nxc smb 10.129.234.63 -u 'a' -p '' --shares --log Outputs/nxc/guest_shares.txt`

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
Note the `Public` share, with `READ` permissions, something to note for further enumeration

**3. Listing Users via RID Bruteforce:**

Although direct user listing wasn't successful with guest access, a RID bruteforce attack is a noisy but often fruitful option.
*   **Command**: `nxc smb 10.129.234.63 -u 'a' -p '' --rid-brute --log Outputs/nxc/rid_scan.txt`
  
```
<SNIP>
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
<SNIP>
```
The scan has given a good picture of how the domain is strucutred, groups for IT Staff, HR, Finance (etc.) and a good list of users to leverage for further enumeration and testing.
An interesting finding is `svc_sspr` (RID 1103), which often indicates a service account used for Self-Service Password Reset. For the complete RID scan output, refer to [rid_scan.txt](Outputs/nxc/rid_scan.txt).

**4. Exploring Shares:**

Spidering available shares is a convenient way to list and/or download all acessible files for which we have access.
*  **Command:** `nxc smb 10.129.234.63 -u 'a' -p '' -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=./spider --log spider_shares.txt`
```
SPIDER_PLUS 10.129.234.63   445    DC               [+] Saved share-file metadata to "./spider/10.129.234.63.json".
SPIDER_PLUS 10.129.234.63   445    DC               [*] SMB Shares:           7 (ADMIN$, C$, Departments Share, IPC$, NETLOGON, Public, SYSVOL)
SPIDER_PLUS 10.129.234.63   445    DC               [*] SMB Readable Shares:  2 (IPC$, Public)
SPIDER_PLUS 10.129.234.63   445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.234.63   445    DC               [*] Total folders found:  0
SPIDER_PLUS 10.129.234.63   445    DC               [*] Total files found:    1
SPIDER_PLUS 10.129.234.63   445    DC               [*] File size average:    14.22 KB
SPIDER_PLUS 10.129.234.63   445    DC               [*] File size min:        14.22 KB
SPIDER_PLUS 10.129.234.63   445    DC               [*] File size max:        14.22 KB
SPIDER_PLUS 10.129.234.63   445    DC               [*] File unique exts:     1 (eml)
SPIDER_PLUS 10.129.234.63   445    DC               [*] Downloads successful: 1
SPIDER_PLUS 10.129.234.63   445    DC               [+] All files processed successfully.
```
Exploring the metadata report has given a single file to investiage.

```
{
    "Public": {
        "tech_support_email.eml": {
            "atime_epoch": "2024-07-06 17:08:50",
            "ctime_epoch": "2024-07-06 17:08:50",
            "mtime_epoch": "2024-07-06 17:09:28",
            "size": "14.22 KB"
        }
    }
}
```




### Exploitation Steps

1.  **Enumerate Public Share**: Access the `Public` share identified during reconnaissance and look for any sensitive files or documents.
2.  **Investigate `svc_sspr`**: Focus on the `svc_sspr` account
3.  **Identify Misconfiguration**: Leverage any found credentials or misconfigurations to gain initial access.

### Privilege Escalation

*   **Initial Access**: (Details to be filled in after exploitation)
*   **Lateral Movement**: (Details to be filled in)
*   **Domain Admin**: (Details to be filled in)

### Post-Exploitation

*   **Persistence**: Establish persistent access within the network.
*   **Data Exfiltration**: Identify and exfiltrate sensitive data.
*   **Cleanup**: Remove traces of intrusion.

### Tools Used

*   `nmap`: Network scanning and service enumeration.
*   `NetExec`: SMB enumeration, user listing, and password spraying.
*   (Add more tools as they are used in the CTF)

### Mitigations

*   **Strong Password Policies**: Enforce complex and unique passwords for all accounts, especially service accounts.
*   **Least Privilege**: Restrict permissions for shares and user accounts to only what is necessary.
*   **Regular Audits**: Conduct frequent audits of Active Directory and SMB configurations.
*   **Monitor Guest Accounts**: Disable or strictly monitor guest accounts and null sessions.

### Lessons Learned

*   Thorough initial enumeration is crucial.
*   Service accounts (`svc_`) are often a weak link.
*   SMB misconfigurations can expose significant attack surfaces.
