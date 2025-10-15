## Non-Technical Summary (DRAFT IDEAS)

### Overview

The "Phantom" CTF simulates a Windows Active Directory network, typical of corporate environments. This writeup details the steps taken to gain unauthorized access and compromise the domain controller with a hybrid aspect of typical pentesting professional-esque reporting. 

As such, not all typical extensive enumeration steps that were performed are documented.

### Key Findings

During the CTF, several vulnerabilities were identified, including:
*   Weak SMB permissions allowing guest access to sensitive shares.
*   The presence 
*   Specific Active Directory misconfigurations that facilitated privilege escalation

### Impact

These identified issues could allow an attacker to:
*   Encrypt and/or steal all on-premises data.
*   Disrupt critical systems, causing indefinite downtime.
*   Gain complete domain control, compromising all systems and establishing powerful persistence.

### Recommendations

To mitigate the discovered vulnerabilities, it is recommended to:
*   Review and restrict null and/or guest access to the domain.
*   Do not publicly share onboarding credentials
*   Regularly 

---
