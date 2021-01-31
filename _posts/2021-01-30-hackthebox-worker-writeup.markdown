---
title: "HackTheBox: Worker Writeup"
date: 2021-01-31 21:05:00 +0000
categories:
  - blog
tags:
  - CTF
  - HTB
  - English
---

![Worker Info](https://jackhack.se/assets/images/worker/worker_infocard.png)
{: .full}

Time for another writeup! This time it's the box Worker from HackTheBox. Worker is a windows box rated at medium difficulty. 

Too root this box, we will have to use Subversion(SVN) to clone a repository and find some old configuration files, from there on we will abuse extensive permissions within Azure DevOps to be able to upload a web-shell which we will use to get shell access to the box. Then perform basic enumeration and dig through more configuration files until we can escalate into a more privileged user. 

The path to root is also via Azure DevOps but this time abusing the Pipelines-function to get root shell access.


# Recon

~~~
# Nmap 7.91 scan initiated Sun Jan 24 17:47:21 2021 as: nmap -sC -sV -oA initial -T5 10.10.10.203
Nmap scan report for 10.10.10.203
Host is up (0.036s latency).
Scanned at 2021-01-24 17:47:22 EST for 11s
Not shown: 998 filtered ports
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3690/tcp open  svnserve Subversion
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 24 17:47:33 2021 -- 1 IP address (1 host up) scanned in 12.19 seconds
~~~
{: .language-bash}


Same old nmap scan, not much open ports laying around on this box. A webserver and a SVN-server running, i will start by trying to clone the SVN repository to my local machine. 

SVN is a versioning and revision control system, basically the same thing as git.

I can use *svn list* to show what files are in the repository, and then *svn export* with the argument **--force** to download the repository.

~~~
┌──(kali@kali)-[~/boxes/worker]
└─$ svn list svn://worker.htb                                      
dimension.worker.htb/
moved.txt

┌──(kali@kali)-[~/boxes/worker]
└─$ svn export svn://worker.htb --force 
~~~
{: .language-bash}

Im intrested in looking at the moved.txt before diving in to the directory.

~~~
┌──(kali@kali)-[~/boxes/worker]
└─$ cat moved.txt   
This repository has been migrated and will no longer be maintaned here.
You can find the latest version at: http://devops.worker.htb

// The Worker team :)
~~~
{: .language-bash}

So here I will add devops.worker.htb to my /etc/hosts file and check it out later

Taking a peek into the directory i find nothing that really sticks out, remembering that svn works like git and is a version control system i know there would be a way to list recent commits. 
Found out using the command *svn checkout -r* specifing arguments  **revision_number** and **server** was what i was looking for, this command pretty much imitates *git log*

Started checking out revisions from 1 and up, at revision 2 a file called **deploy.ps1** appeared, 

~~~
┌──(kali@kali)-[~/boxes/worker]                                     
└─$ svn checkout -r 2 svn://worker.htb                                                                         
A    deploy.ps1                                                                                                      
Checked out revision 2.                                                                                              
                                                          
┌──(kali@kali)-[~/boxes/worker]                                     
└─$ cat deploy.ps1                                                                                                   
$user = "nathen"                                                                                                     
$plain = "wendel98"                                                                                                  
$pwd = ($plain | ConvertTo-SecureString)                                                                             
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"                                   
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
~~~

The file contains credentials for the user **nathen**, now i just have to find out where to use them, and i think i have a great idea due to the url mentioned in the text file earlier. 


# User

![Authentication page](https://jackhack.se/assets/images/worker/access_denied.png)
{: .full}

Browsing to *devops.worker.htb* i am met with a basic authentication popup. So i enter the credentials **nathen** and password **wendel98**, which gives me access to Azure Devops. 

The landning page shows this project SmartHotel360, checking out the repos we can tell there is a lot of subdomains/side-projects inside this project.

![Repositorys](https://jackhack.se/assets/images/worker/repos.png)
{: .full}

Each one of these repositorys seems to include some *index.html* files and this makes me think all these are different sites. I add one of the repositories to my /etc/hosts file. I use the format *repository*.worker.htb so in this case i add **spectral.worker.htb** to my hosts file

![Spectral subdomain](https://jackhack.se/assets/images/worker/spectral.png)
{: .full}
The page is browseable and by checking the available pipelines in Azure DevOps i can make an educated guess that if i manage to push content into the master branch of the spectral repo, the site should be automatically deployed including my changes.

![Spectral pipeline](https://jackhack.se/assets/images/worker/spectral-pipeline.png)
{: .full}

This can be verified by checking the triggers of the pipeline

![Spectral triggers](https://jackhack.se/assets/images/worker/spectral-triggers.png)
{: .full}

This following part took a good while since im not very experienced within Azure Devops, before i had just used this platform to submit tickets to developers while working in a support/operations type of role - but finally i was able to upload a webshell to the page. 

According to the nmap scan performed in the recon-phase the webserver running is Microsofts **IIS** and i can't see the page running any php-code or similar, so i will use an aspx-shell since i know Windows IIS will be able to run it.

~~~
┌──(kali@kali)-[~/boxes/worker]
└─$ locate *.aspx
/usr/share/davtest/backdoors/aspx_cmd.aspx
/usr/share/laudanum/aspx/shell.aspx
/usr/share/webshells/aspx/cmdasp.aspx
┌──(kali@kali)-[~/boxes/worker]
└─$ cp /usr/share/webshells/aspx/cmdasp.aspx .
~~~
{: .language-bash}

Trying to upload the shell into the "spectral" repository i quickly found out i was not allowed to push content into the master branch, so my workaround turned out to be to make a own temporary branch, upload the shell and then merge the branches and finally approve the changes. 

After that procedure i could access my aspx shell and execute code on the victim machine, so i grabbed a quick powershell one-line reverse shell, edited it with my IP address and a random port and started a netcat listener on my Kali machine.

![Initial shell](https://jackhack.se/assets/images/worker/shell1.png)
{: .full}

At this point i only have access to an IIS account and it seems there is no user flag accessible for me, taking a quick look into the C:\Users\ directory to hunt potential users other than Administraor revealed there was another user called **robisl** and one called **restorer**.

~~~
    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/28/2020   2:59 PM                .NET v4.5
d-----        3/28/2020   2:59 PM                .NET v4.5 Classic
d-----        8/18/2020  12:33 AM                Administrator
d-r---        3/28/2020   2:01 PM                Public
d-----        7/22/2020   1:11 AM                restorer
d-----         7/8/2020   7:22 PM                robisl
~~~

Back at the triggers for the pipeline associated with the spectral-repository i saw a reference to a directory placed on a disk assigned the drive letter **W:**, browsing the drive it seems to contain various configuration files for Azure DevOps and SVN. 

~~~
    Directory: W:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/16/2020   6:59 PM                agents
d-----        3/28/2020   2:57 PM                AzureDevOpsData
d-----         4/3/2020  11:31 AM                sites
d-----        6/20/2020   4:04 PM                svnrepos

~~~

Inside the directory *svnrepos\www\conf\* i found a file called **passwd**. Using findstr to search for users i managed to retrieve a password for the user robisl, using it to connect to the machine via evil-winrm and grab the user flag. 

~~~
PS W:\svnrepos\www\conf> type passwd | findstr restorer
PS W:\svnrepos\www\conf> type passwd | findstr robisl
robisl = wolves11
~~~
![User flag](https://jackhack.se/assets/images/worker/user-flag.png)
{: .full}

# Root

So the privilege escalation begins. After looking through insane ammounts of files i realized i could test to authenticate as this robisl on the DevOps page, maybe that would grant me more permissions to create own pipelines or something like that?


Authenticating as robisl displayed a whole new project as landing page this time

![New landing page](https://jackhack.se/assets/images/worker/partsunlimited.png)
{: .full}

Inside this project, no pipelines were available but i had permissions to create new pipelines, i simply followed the wizard-style "Create new pipeline" button, selected "Starter Pipeline" as my type of pipeline and was presented with a pre defined YAML-file

![Standard pipeline](https://jackhack.se/assets/images/worker/standard-pipeline.png)
{: .full}

I removed the "Trigger" part and everything i saw as unnessecary and tried to execute a simple *net user* command to try to change the administrator password, clicked "Save and run" and selected "create a new branch for this commit and start a pull request.".

![Modified script](https://jackhack.se/assets/images/worker/script.png)
{: .full}

This seemed to work just fine, i was now able to access the administrator account through evil-winrm. I honestly don't fully understand why this worked, my guess is there must be assigned extensive permissions to the Azure service on the box or something like that. I will make sure to read up on it when the box retires and other hackers will publish write-ups.

![Root flag](https://jackhack.se/assets/images/worker/rootflag.png)
{: .full}

# Resources
Resources is where i will put links without context used while solving the boxes, these can be used to further understand parts of the writeup :)

* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell
* https://docs.microsoft.com/en-us/azure/devops/pipelines/get-started/pipelines-get-started?view=azure-devops
* https://www.perforce.com/blog/vcs/svn-commands-cheat-sheet
