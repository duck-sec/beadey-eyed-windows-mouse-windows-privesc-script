# Beady-eyed Windows Mouse - Windows Privilege Escalation Script

This script is designed to assist in the detection of possible misconfigurations that may lead to privilege escalation on a Windows system. 
I use this as a "first view" script to gather basic system config information and detect "easy win" vulnerabilities - it is not intended to replace more comprehensive tools, such as WinPEAS.
It provides a quick overview of system information, user and group details, file permissions, network configurations, running processes, scheduled tasks, and potential security issues.

The Beady-eyed Mouse is a cute little mouse found in Columbia and Ecuador - with those beady eyes, if a mouse was going to be good at privilege esealation, it would be this one :)

## Requirements
Powershell 3.0 or newer

## Usage

Run the script on a Windows system with the following command:

```powershell
powershell mouse.ps1
```
## Features

- System Informaion: Collects system information such as OS version, hotfixes, and system boot time.
- User Information: Retrieves user details, including current user, groups, privileges, and command history.
- Network: Gathers network information, DNS settings, ARP cache, and network connections.
- Firewall / AV: Checks firewall and antivirus status, app locker policies, and firewall configurations.
- Processes: Displays running processes, services, and registry items.
- Searches for interesting files, directories, and configurations.
- Checks for scheduled tasks, startup commands, and named pipes.
- Highlights potential privilege escalation routes and useful information for further investigation.


# Disclaimer
This script is meant for educational and authorised auditing purposes only (eg. HackTheBox)

# Example Output
An example from the Support HTB box

```

            .--,       .--,
           ( (  \.---./  ) )
            ".__/o   o\__."
               {=  ^  =}
                >  -  <
 ___________.""-------"".____________
/                                      \
\          Beadey Eye Mouse            /
/            Now Scanning!             \
\                                      /         __
/iucnredlist.org/species/21770/22366419\     _.-"  .
\______________ __________ ____________/ .-~^        ~--"
              ___)( )(___        -.___."
             (((__) (__)))
=====================================================







Beadey Eye (Windows) Mouse
Running as user: SUPPORT\support
Started at: 12/3/2023 3:30:28 AM

Items in Red Are potential privesc routes, check them out!
Items in Yellow Could be useful, have a look
Items in Green Are information which might help with other approaches

=============================
  ###-SYSTEM INFORMATION-###
=============================
    ()-().----.          .
     \"/ ___  ;________./
       ^^   ^^
=============================


=============================
  Basic System Information
=============================
powershell.exe : Program 'systeminfo.exe' failed to run: Access is deniedAt line:1 char:1
    + CategoryInfo          : NotSpecified: (Program 'system...t line:1 char:1:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
+ systeminfo+ ~~~~~~~~~~.At line:1 char:1+ systeminfo+ ~~~~~~~~~~    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException    + FullyQualifiedErrorId : NativeCommandFailed 

=============================
  Environment Variables
=============================

Key                     Value
---                     -----
ALLUSERSPROFILE         C:\ProgramData
APPDATA                 C:\Users\support\AppData\Roaming
CommonProgramFiles      C:\Program Files\Common Files
CommonProgramFiles(x86) C:\Program Files (x86)\Common Files
CommonProgramW6432      C:\Program Files\Common Files
COMPUTERNAME            DC
ComSpec                 C:\Windows\system32\cmd.exe
DriverData              C:\Windows\System32\Drivers\DriverData
LOCALAPPDATA            C:\Users\support\AppData\Local
NUMBER_OF_PROCESSORS    2
OS                      Windows_NT
Path                    C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\Syst...
PATHEXT                 .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE  AMD64
PROCESSOR_IDENTIFIER    Intel64 Family 6 Model 85 Stepping 7, GenuineIntel
PROCESSOR_LEVEL         6
PROCESSOR_REVISION      5507
ProgramData             C:\ProgramData
ProgramFiles            C:\Program Files
ProgramFiles(x86)       C:\Program Files (x86)
ProgramW6432            C:\Program Files
PSModulePath            C:\Users\support\Documents\WindowsPowerShell\Modules;C:\Program Files\W...
PUBLIC                  C:\Users\Public
SystemDrive             C:
SystemRoot              C:\Windows
TEMP                    C:\Users\support\AppData\Local\Temp
TMP                     C:\Users\support\AppData\Local\Temp
USERDNSDOMAIN           support.htb
USERDOMAIN              SUPPORT
USERNAME                support
USERPROFILE             C:\Users\support
windir                  C:\Windows




=============================
  ###-USER INFORMATION-###
=============================
    ()-().----.          .
     \"/ ___  ;________./
       ^^   ^^
=============================


=============================
  Current User
=============================
SUPPORT\support


=============================
  Current User Privileges
=============================

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


=============================
  Current User Groups
=============================

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
SUPPORT\Shared Support Accounts            Group            S-1-5-21-1677581083-3380853377-188903654-1103 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


=============================
  Current User Command History
=============================


=============================
  Local Users
=============================

Name              Enabled LastLogon
----              ------- ---------
Administrator        True 12/3/2023 3:29:17 AM
Guest                True
krbtgt              False
ldap                 True
support              True
smith.rosario        True
hernandez.stanley    True
wilson.shelby        True
anderson.damian      True
thomas.raphael       True
levine.leopoldo      True
raven.clifton        True
bardot.mary          True
cromwell.gerard      True
monroe.david         True
west.laura           True
langley.lucy         True
daughtler.mabel      True
stoll.rachelle       True
ford.victoria        True
DC$                  True 12/3/2023 3:29:18 AM




=============================
  Local Administrators
=============================
Get-LocalGroupMember : Group Administrators was not found.At line:1 char:1+ Get-LocalGroupMember Administrators | ft Name, PrincipalSource+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : ObjectNotFound: (Administrators:String) [Get-LocalGroupMember], Gro    upNotFoundException    + FullyQualifiedErrorId : GroupNotFound,Microsoft.PowerShell.Commands.GetLocalGroupMemberComm    and 

=============================
  Local Groups
=============================

Name
----
Cert Publishers
RAS and IAS Servers
Allowed RODC Password Replication Group
Denied RODC Password Replication Group




=============================
  Logged in Users
=============================
No session exists for *

=============================
  Recent RDP Sessions
=============================
get-winevent : Attempted to perform an unauthorized operation.At line:1 char:1+ get-winevent -logname "Microsoft-Windows-TerminalServices-LocalSessio ...+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : NotSpecified: (:) [Get-WinEvent], UnauthorizedAccessException    + FullyQualifiedErrorId : System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.Ge    tWinEventCommand 

=============================
  User Directories
=============================

Name
----
Administrator
ldap
Public
support




=============================
  Password policy
=============================
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        PRIMARY
The command completed successfully.



=============================
  Credential Manager
=============================

Currently stored credentials:

* NONE *


=============================
  User Autologon Registry Items
=============================

DefaultDomainName DefaultUserName
----------------- ---------------
SUPPORT




=============================
  ###-----NETWORK-----###
=============================
    ()-().----.          .
     \"/ ___  ;________./
       ^^   ^^
=============================


=============================
  Network Information
=============================
New-CimSession : Access denied At C:\Windows\system32\WindowsPowerShell\v1.0\Modules\NetTCPIP\NetIPConfiguration.psm1:46 char:27+             $CimSession = New-CimSession+                           ~~~~~~~~~~~~~~    + CategoryInfo          : PermissionDenied: (:) [New-CimSession], CimException    + FullyQualifiedErrorId : HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.N    ewCimSessionCommand Get-CimInstance : Access denied At C:\Windows\system32\WindowsPowerShell\v1.0\Modules\NetTCPIP\NetIPConfiguration.psm1:47 char:30+ ...           $ComputerName = (Get-CimInstance win32_ComputerSystem).name+                                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : PermissionDenied: (root\cimv2:win32_ComputerSystem:String) [Get-Cim    Instance], CimException    + FullyQualifiedErrorId : HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.G    etCimInstanceCommand Get-NetCompartment : Cannot validate argument on parameter 'CimSession'. The argument is null or empty. Provide an argument that is not null or empty, and then try the command again.At C:\Windows\system32\WindowsPowerShell\v1.0\Modules\NetTCPIP\NetIPConfiguration.psm1:72 char:60+ ...            $Compartments = Get-NetCompartment -CimSession $CimSession+                                                               ~~~~~~~~~~~    + CategoryInfo          : InvalidData: (:) [Get-NetCompartment], ParameterBindingValidationEx    ception    + FullyQualifiedErrorId : ParameterArgumentValidationError,Get-NetCompartment Get-NetAdapter : Cannot validate argument on parameter 'CimSession'. The argument is null or empty. Provide an argument that is not null or empty, and then try the command again.At C:\Windows\system32\WindowsPowerShell\v1.0\Modules\NetTCPIP\NetIPConfiguration.psm1:90 char:67+ ...     $Adapters = Get-NetAdapter -IncludeHidden -CimSession $CimSession+                                                               ~~~~~~~~~~~    + CategoryInfo          : InvalidData: (:) [Get-NetAdapter], ParameterBindingValidationExcept    ion    + FullyQualifiedErrorId : ParameterArgumentValidationError,Get-NetAdapter Get-NetIPInterface : Cannot validate argument on parameter 'CimSession'. The argument is null or empty. Provide an argument that is not null or empty, and then try the command again.At C:\Windows\system32\WindowsPowerShell\v1.0\Modules\NetTCPIP\NetIPConfiguration.psm1:91 char:126+ ... nts:$AllCompartments -PolicyStore ActiveStore -CimSession $CimSession+                                                               ~~~~~~~~~~~    + CategoryInfo          : InvalidData: (:) [Get-NetIPInterface], ParameterBindingValidationEx    ception    + FullyQualifiedErrorId : ParameterArgumentValidationError,Get-NetIPInterface 

=============================
  DNS Servers
=============================
Get-DnsClientServerAddress : Cannot connect to CIM server. Access denied At line:1 char:1+ Get-DnsClientServerAddress -AddressFamily IPv4 | ft+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : ResourceUnavailable: (MSFT_DNSClientServerAddress:String) [Get-DnsC    lientServerAddress], CimJobException    + FullyQualifiedErrorId : CimJob_BrokenCimSession,Get-DnsClientServerAddress 

=============================
  ARP cache
=============================
Get-NetNeighbor : Cannot connect to CIM server. Access denied At line:1 char:1+ Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerA ...+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : ResourceUnavailable: (MSFT_NetNeighbor:String) [Get-NetNeighbor], C    imJobException    + FullyQualifiedErrorId : CimJob_BrokenCimSession,Get-NetNeighbor 

=============================
  Routing Table
=============================
Get-NetRoute : Cannot connect to CIM server. Access denied At line:1 char:1+ Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,Route ...+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : ResourceUnavailable: (MSFT_NetRoute:String) [Get-NetRoute], CimJobE    xception    + FullyQualifiedErrorId : CimJob_BrokenCimSession,Get-NetRoute 

=============================
  Network Connections
=============================

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       644
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       956
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       644
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       644
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       956
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       644
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       644
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       644
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       1420
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       644
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       504
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       776
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1176
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       644
  TCP    0.0.0.0:49676          0.0.0.0:0              LISTENING       644
  TCP    0.0.0.0:49681          0.0.0.0:0              LISTENING       628
  TCP    0.0.0.0:49690          0.0.0.0:0              LISTENING       644
  TCP    0.0.0.0:49695          0.0.0.0:0              LISTENING       2064
  TCP    0.0.0.0:49707          0.0.0.0:0              LISTENING       2088
  TCP    10.129.50.188:53       0.0.0.0:0              LISTENING       2064
  TCP    10.129.50.188:139      0.0.0.0:0              LISTENING       4
  TCP    10.129.50.188:389      10.129.50.188:49689    ESTABLISHED     644
  TCP    10.129.50.188:389      10.129.50.188:49701    ESTABLISHED     644
  TCP    10.129.50.188:389      10.129.50.188:49740    ESTABLISHED     644
  TCP    10.129.50.188:5985     10.10.14.40:52436      TIME_WAIT       0
  TCP    10.129.50.188:5985     10.10.14.40:52444      ESTABLISHED     4
  TCP    10.129.50.188:49689    10.129.50.188:389      ESTABLISHED     2088
  TCP    10.129.50.188:49701    10.129.50.188:389      ESTABLISHED     2088
  TCP    10.129.50.188:49740    10.129.50.188:389      ESTABLISHED     2064
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2064
  TCP    127.0.0.1:389          127.0.0.1:49678        ESTABLISHED     644
  TCP    127.0.0.1:389          127.0.0.1:49680        ESTABLISHED     644
  TCP    127.0.0.1:389          127.0.0.1:49683        ESTABLISHED     644
  TCP    127.0.0.1:389          127.0.0.1:49694        ESTABLISHED     644
  TCP    127.0.0.1:3268         127.0.0.1:49705        ESTABLISHED     644
  TCP    127.0.0.1:49678        127.0.0.1:389          ESTABLISHED     2124
  TCP    127.0.0.1:49680        127.0.0.1:389          ESTABLISHED     2124
  TCP    127.0.0.1:49683        127.0.0.1:389          ESTABLISHED     1420
  TCP    127.0.0.1:49694        127.0.0.1:389          ESTABLISHED     2064
  TCP    127.0.0.1:49705        127.0.0.1:3268         ESTABLISHED     1420
  TCP    [::]:88                [::]:0                 LISTENING       644
  TCP    [::]:135               [::]:0                 LISTENING       956
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:464               [::]:0                 LISTENING       644
  TCP    [::]:593               [::]:0                 LISTENING       956
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:9389              [::]:0                 LISTENING       1420
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       644
  TCP    [::]:49665             [::]:0                 LISTENING       504
  TCP    [::]:49666             [::]:0                 LISTENING       776
  TCP    [::]:49667             [::]:0                 LISTENING       1176
  TCP    [::]:49668             [::]:0                 LISTENING       644
  TCP    [::]:49676             [::]:0                 LISTENING       644
  TCP    [::]:49681             [::]:0                 LISTENING       628
  TCP    [::]:49690             [::]:0                 LISTENING       644
  TCP    [::]:49695             [::]:0                 LISTENING       2064
  TCP    [::]:49707             [::]:0                 LISTENING       2088
  TCP    [::1]:53               [::]:0                 LISTENING       2064
  TCP    [::1]:49668            [::1]:49697            ESTABLISHED     644
  TCP    [::1]:49668            [::1]:58945            ESTABLISHED     644
  TCP    [::1]:49692            [::1]:49668            TIME_WAIT       0
  TCP    [::1]:49697            [::1]:49668            ESTABLISHED     2088
  TCP    [::1]:49733            [::1]:49668            TIME_WAIT       0
  TCP    [::1]:49741            [::1]:135              TIME_WAIT       0
  TCP    [::1]:58944            [::1]:135              TIME_WAIT       0
  TCP    [::1]:58945            [::1]:49668            ESTABLISHED     644
  UDP    0.0.0.0:123            *:*                                    764
  UDP    0.0.0.0:389            *:*                                    644
  UDP    0.0.0.0:500            *:*                                    2100
  UDP    0.0.0.0:4500           *:*                                    2100
  UDP    0.0.0.0:5353           *:*                                    1088
  UDP    10.129.50.188:88       *:*                                    644
  UDP    10.129.50.188:137      *:*                                    4
  UDP    10.129.50.188:138      *:*                                    4
  UDP    10.129.50.188:464      *:*                                    644
  UDP    127.0.0.1:53           *:*                                    2064
  UDP    127.0.0.1:51394        127.0.0.1:51394                        1680
  UDP    127.0.0.1:52347        127.0.0.1:52347                        2088
  UDP    127.0.0.1:54150        127.0.0.1:54150                        1496
  UDP    127.0.0.1:56058        127.0.0.1:56058                        2124
  UDP    127.0.0.1:58563        127.0.0.1:58563                        1420
  UDP    127.0.0.1:62792        127.0.0.1:62792                        2064
  UDP    127.0.0.1:65085        127.0.0.1:65085                        3780
  UDP    127.0.0.1:65086        127.0.0.1:65086                        952
  UDP    [::]:123               *:*                                    764
  UDP    [::]:500               *:*                                    2100
  UDP    [::]:4500              *:*                                    2100
  UDP    [::]:58797             *:*                                    1088
  UDP    [::]:64272             *:*                                    2064
  UDP    [::1]:53               *:*                                    2064
  UDP    [::1]:56059            *:*                                    2064


=============================
  Proxy Settings
=============================

Current WinHTTP proxy settings:

    Direct access (no proxy server).



=============================
  Connected Drives
=============================

Name           Used (GB)     Free (GB) Provider      Root                                CurrentLo
                                                                                            cation
----           ---------     --------- --------      ----                                ---------
C                                      FileSystem    C:\                                 ...uments




=============================
  PuTTY sessions
=============================
Get-ChildItem : Cannot find path 'HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions' because it does not exist.At line:1 char:1+ Get-ChildItem HKCU:\Software\SimonTatham\PuTTY\Sessions+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : ObjectNotFound: (HKEY_CURRENT_US...\PuTTY\Sessions:String) [Get-Chi    ldItem], ItemNotFoundException    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetChildItemCommand 

=============================
  Saved PuTTY SSH Keys
=============================
Get-Childitem : Cannot find path 'HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys\' because it does not exist.At line:1 char:1+ Get-Childitem HKCU:\Software\SimonTatham\PuTTY\SshHostKeys\+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : ObjectNotFound: (HKEY_CURRENT_US...TY\SshHostKeys\:String) [Get-Chi    ldItem], ItemNotFoundException    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetChildItemCommand 

=============================
  RDP Session log
=============================
Get-EventLog : Requested registry access is not allowed.At line:1 char:1+ Get-EventLog security -after (Get-date -hour 0 -minute 0 -second 0) | ...+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : NotSpecified: (:) [Get-EventLog], SecurityException    + FullyQualifiedErrorId : System.Security.SecurityException,Microsoft.PowerShell.Commands.Get    EventLogCommand 

=============================
  ###-FIREWALL / AV-###
=============================
    ()-().----.          .
     \"/ ___  ;________./
       ^^   ^^
=============================


=============================
  Defender status
=============================
Get-MpComputerStatus : Cannot connect to CIM server. Access denied At line:1 char:1+ Get-MpComputerStatus+ ~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : ResourceUnavailable: (MSFT_MpComputerStatus:String) [Get-MpComputer    Status], CimJobException    + FullyQualifiedErrorId : CimJob_BrokenCimSession,Get-MpComputerStatus 

=============================
  App Locker Policies
=============================


=============================
  Firewall Config
=============================

Domain profile configuration (current):
-------------------------------------------------------------------
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Disable

Service configuration for Domain profile:
Mode     Customized  Name
-------------------------------------------------------------------
Enable   No          File and Printer Sharing

Allowed programs configuration for Domain profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------

Port configuration for Domain profile:
Port   Protocol  Mode    Traffic direction     Name
-------------------------------------------------------------------

Standard profile configuration:
-------------------------------------------------------------------
Operational mode                  = Enable
Exception mode                    = Enable
Multicast/broadcast response mode = Enable
Notification mode                 = Disable

Service configuration for Standard profile:
Mode     Customized  Name
-------------------------------------------------------------------
Enable   No          File and Printer Sharing

Allowed programs configuration for Standard profile:
Mode     Traffic direction    Name / Program
-------------------------------------------------------------------

Port configuration for Standard profile:
Port   Protocol  Mode    Traffic direction     Name
-------------------------------------------------------------------

Log configuration:
-------------------------------------------------------------------
File location   = C:\Windows\system32\LogFiles\Firewall\pfirewall.log
Max file size   = 4096 KB
Dropped packets = Disable
Connections     = Disable

IMPORTANT: Command executed successfully.
However, "netsh firewall" is deprecated;
use "netsh advfirewall firewall" instead.
For more information on using "netsh advfirewall firewall" commands
instead of "netsh firewall", see KB article 947709
at https://go.microsoft.com/fwlink/?linkid=121488 .




=============================
  ###-PROCESS / PROGS-###
=============================
    ()-().----.          .
     \"/ ___  ;________./
       ^^   ^^
=============================


=============================
  Running Processes
=============================
gwmi : Access denied At line:1 char:1+ gwmi -Query "Select * from Win32_Process" | where {$_.Name -notlike " ...+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjec    tCommand 

=============================
  Running Services
=============================
ERROR: Access denied

=============================
  Checking registry for AlwaysInstallElevated
=============================
False


=============================
  Unquoted Service Paths
=============================
gwmi : Access denied At line:1 char:1+ gwmi -class Win32_Service -Property Name, DisplayName, PathName, Star ...+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjec    tCommand 

=============================
  Software in Registry
=============================

Name
----
HKEY_LOCAL_MACHINE\SOFTWARE\Classes
HKEY_LOCAL_MACHINE\SOFTWARE\Clients
HKEY_LOCAL_MACHINE\SOFTWARE\DefaultUserEnvironment
HKEY_LOCAL_MACHINE\SOFTWARE\Google
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft
HKEY_LOCAL_MACHINE\SOFTWARE\ODBC
HKEY_LOCAL_MACHINE\SOFTWARE\OpenSSH
HKEY_LOCAL_MACHINE\SOFTWARE\Policies
HKEY_LOCAL_MACHINE\SOFTWARE\RegisteredApplications
HKEY_LOCAL_MACHINE\SOFTWARE\Setup
HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node




=============================
  Searching for SAM backup files
=============================
False
False


=============================
  Installed Software Directories
=============================

Parent              Name                                        LastWriteTime
------              ----                                        -------------
Program Files       Common Files                                5/19/2022 2:28:33 AM
Program Files       Internet Explorer                           5/8/2021 1:15:05 AM
Program Files       ModifiableWindowsApps                       5/8/2021 1:15:05 AM
Program Files       VMware                                      7/21/2022 4:01:48 AM
Program Files       Windows Defender                            5/20/2022 7:08:35 PM
Program Files       Windows Defender Advanced Threat Protection 7/21/2022 6:03:23 AM
Program Files       Windows NT                                  5/8/2021 2:34:54 AM
Program Files       WindowsPowerShell                           5/8/2021 1:27:30 AM
Program Files (x86) Common Files                                5/8/2021 1:27:37 AM
Program Files (x86) Internet Explorer                           5/8/2021 1:15:05 AM
Program Files (x86) Microsoft.NET                               5/8/2021 1:27:30 AM
Program Files (x86) Windows NT                                  5/8/2021 2:34:54 AM
Program Files (x86) WindowsPowerShell                           5/8/2021 1:15:05 AM




=============================
  Folders with Everyone Permissions
=============================


=============================
  Folders with BUILTIN\User Permissions
=============================


=============================
  Scheduled Tasks
=============================
Get-ScheduledTask : Cannot connect to CIM server. Access denied At line:1 char:1+ Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft T ...+ ~~~~~~~~~~~~~~~~~    + CategoryInfo          : ResourceUnavailable: (MSFT_ScheduledTask:String) [Get-ScheduledTask    ], CimJobException    + FullyQualifiedErrorId : CimJob_BrokenCimSession,Get-ScheduledTask 

=============================
  Tasks Folder
=============================


=============================
  Startup Commands
=============================
Get-CimInstance : Access denied At line:1 char:1+ Get-CimInstance Win32_StartupCommand | select Name, command, Location ...+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~    + CategoryInfo          : PermissionDenied: (root\cimv2:Win32_StartupCommand:String) [Get-Cim    Instance], CimException    + FullyQualifiedErrorId : HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.G    etCimInstanceCommand 

=============================
  Searching for named pipes
=============================


    Directory: \\.\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              3 InitShutdown
------        12/31/1600   4:00 PM              7 lsass
------        12/31/1600   4:00 PM              3 ntsvcs
------        12/31/1600   4:00 PM              3 scerpc


    Directory: \\.\pipe\Winsock2


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-284-0
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-3bc-0


    Directory: \\.\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              3 epmapper


    Directory: \\.\pipe\Winsock2


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-1f8-0


    Directory: \\.\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              3 LSM_API_service


    Directory: \\.\pipe\Winsock2


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-3f4-0


    Directory: \\.\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              3 eventlog


    Directory: \\.\pipe\Winsock2


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-308-0


    Directory: \\.\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              4 wkssvc
------        12/31/1600   4:00 PM              3 atsvc


    Directory: \\.\pipe\Winsock2


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-498-0
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-284-1


    Directory: \\.\pipe\RpcProxy


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              3 RpcProxy\49676


    Directory: \\.\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              3 91eacadf25f90510


    Directory: \\.\pipe\RpcProxy


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              3 RpcProxy\593


    Directory: \\.\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              4 srvsvc
------        12/31/1600   4:00 PM              3 winreg
------        12/31/1600   4:00 PM              3 efsrpc
------        12/31/1600   4:00 PM              3 netdfs
------        12/31/1600   4:00 PM              1 vgauth-service


    Directory: \\.\pipe\Winsock2


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-274-0


    Directory: \\.\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              3 W32TIME_ALT


    Directory: \\.\pipe\Winsock2


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-810-0


    Directory: \\.\pipe\PIPE_EVENTROOT


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              1 PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER


    Directory: \\.\pipe\Winsock2


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-828-0


    Directory: \\.\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------        12/31/1600   4:00 PM              1 PSHost.133460764276545794.3780.DefaultAppDomain.
                                                  powershell
------        12/31/1600   4:00 PM              1 PSHost.133460765843678338.3744.DefaultAppDomain.
                                                  wsmprovhost
------        12/31/1600   4:00 PM              1 PSHost.133460766279800367.1812.DefaultAppDomain.
                                                  powershell




=============================
  Searching for Unattend and Sysprep files
=============================


    Directory: C:\Windows\System32


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:11 AM            614 WdsUnattendTemplate.xml


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-d..t-services-unattend_31bf3856ad364e35_1
    0.0.20348.1_none_528a574a6dbe9437


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:11 AM            614 WdsUnattendTemplate.xml




=============================
  Searching for web.config files
=============================


    Directory: C:\Windows\Microsoft.NET\Framework\v4.0.30319\ASP.NETWebAdminFiles


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:14 AM           1040 web.config


    Directory: C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:14 AM          43133 web.config


    Directory: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ASP.NETWebAdminFiles


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:14 AM           1040 web.config


    Directory: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:14 AM          43133 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-d..cehealthattestation_31bf3856ad364e35_1
    0.0.20348.1_none_0c2e78cd71412811


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:18 AM           2042 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-r..-licensing-external_31bf3856ad364e35_1
    0.0.20348.1_none_ad2db43ebff2b793


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:21 AM           1426 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-r..-web-administration_31bf3856ad364e35_1
    0.0.20348.1_none_4227238622f5bec1


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           1332 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-r..-web-groupexpansion_31bf3856ad364e35_1
    0.0.20348.1_none_519724206a6d1721


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           1501 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-r..certification-reach_31bf3856ad364e35_1
    0.0.20348.1_none_1410befbadd63a71


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           3532 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-r..es-web-decommission_31bf3856ad364e35_1
    0.0.20348.1_none_616d85097c9f9bd7


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           1531 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-r..s-web-certification_31bf3856ad364e35_1
    0.0.20348.1_none_6046c0d6a9f0fc73


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           1501 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-r..tification-external_31bf3856ad364e35_1
    0.0.20348.1_none_024d4594c3a6fba9


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:21 AM           1400 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-r..vices-web-licensing_31bf3856ad364e35_1
    0.0.20348.1_none_c1d8336d4539121f


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           1603 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft-windows-r..web-licensing-reach_31bf3856ad364e35_1
    0.0.20348.1_none_365dce5470382cbb


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:21 AM           1668 web.config


    Directory: C:\Windows\WinSxS\amd64_microsoft.windows.r..ation.server.nongac_31bf3856ad364e35_1
    0.0.20348.1_none_3a8a1b05aed34584


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           2173 Web.config


    Directory: C:\Windows\WinSxS\amd64_netfx4-aspnet_webadmin_b03f5f7f11d50a3a_4.0.15806.0_none_a7
    c19c2403ed1c0f


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           1040 web.config


    Directory:
    C:\Windows\WinSxS\amd64_netfx4-web_config_b03f5f7f11d50a3a_4.0.15806.0_none_cc8d87808387fbf1


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:25 AM           5706 web.config


    Directory: C:\Windows\WinSxS\amd64_updateservices-webservices-apiremoting_31bf3856ad364e35_10.
    0.20348.1_none_6982510e0716dd4e


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:23 AM           2142 Web.config


    Directory: C:\Windows\WinSxS\amd64_updateservices-webservices-client_31bf3856ad364e35_10.0.203
    48.1_none_87512a1fc4a5794a


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:23 AM           2620 Web.config


    Directory: C:\Windows\WinSxS\amd64_updateservices-webservices-dssauth_31bf3856ad364e35_10.0.20
    348.1_none_a303681c72c0f589


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:23 AM           2342 Web.config


    Directory: C:\Windows\WinSxS\amd64_updateservices-webservices-reporting_31bf3856ad364e35_10.0.
    20348.1_none_a5022b14c19e28c3


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:23 AM           2146 Web.config


    Directory: C:\Windows\WinSxS\amd64_updateservices-webservices-serversync_31bf3856ad364e35_10.0
    .20348.1_none_ed1a05375e9fbaf9


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           3726 Web.config


    Directory: C:\Windows\WinSxS\amd64_updateservices-webservices-simpleauth_31bf3856ad364e35_10.0
    .20348.1_none_c4ad25d5ce31b1a3


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:23 AM           2106 Web.config


    Directory: C:\Windows\WinSxS\msil_microsoft-windows-p..ccess-web.resources_31bf3856ad364e35_10
    .0.20348.1_en-us_c39ff644419377e9


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   2:33 AM           1262 Web.config


    Directory: C:\Windows\WinSxS\msil_microsoft-windows-p..rshellwebaccess-web_31bf3856ad364e35_10
    .0.20348.1_none_f00fde4e746775de


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           2808 Web.config


    Directory: C:\Windows\WinSxS\x86_netfx4-aspnet_webadmin_b03f5f7f11d50a3a_4.0.15806.0_none_ef6e
    d2fb18694515


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:12 AM           1040 web.config


    Directory:
    C:\Windows\WinSxS\x86_netfx4-web_config_b03f5f7f11d50a3a_4.0.15806.0_none_143abe57980424f7


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:25 AM           5706 web.config




=============================
  Searching for other interesting files
=============================


    Directory: C:\Windows\Help\en-US

<SNIP>



```
