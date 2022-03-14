# Recon

# Unauthenticated enumeration

# First foothold
### Username == password
Using crackmapexec to test for password equal to username on domain contoso.com

```
for word in $(cat users.txt); do crackmapexec smb 10.10.0.10 -u $word -p $word -d contoso.com; done
```

# Authenticated enumeration

### Expanding BloodHound
- https://github.com/hausec/Bloodhound-Custom-Queries
- https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
- https://www.trustedsec.com/blog/expanding-the-hound-introducing-plaintext-field-to-compromised-accounts/
- https://neo4j.com/docs/api/python-driver/current/


# Exploitation

# Active Directory exploitation

# Persistence

# Post-Exploitation

## Data-Exfiltration
Data exfiltration and DLP (Data Loss Prevention) bypass.

# Reporting / Collaborative
