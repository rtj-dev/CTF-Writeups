## Non-Technical Summary (DRAFT IDEAS)


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
