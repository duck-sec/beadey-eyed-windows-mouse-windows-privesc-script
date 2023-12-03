#Windows enumeration script :) 
 
$lines="============================="
function printitem($item) {
    Write-Host
    Write-Host -ForegroundColor Green $lines
    Write-Host -ForegroundColor Red " "$item 
    Write-Host -ForegroundColor Green $lines
}


Write-host @"

            .--,       .--,
           ( (  \.---./  ) )
            ".__/o   o\__."
               {=  ^  =}
                >  -  <
 ___________.""`-------`"".____________
/                                      \
\          Beadey Eye Mouse            /
/            Now Scanning!             \
\                                      /         __
/iucnredlist.org/species/21770/22366419\     _.-"  `.
\______________ __________ ____________/ .-~^        `~--"
              ___)( )(___        `-.___."
             (((__) (__)))
=====================================================






"@

 Write-Host
 Write-Host -ForegroundColor Green "Beadey Eye (Windows) Mouse"
 Write-Host -Nonewline -ForegroundColor Green "Running as user: "
 Write-Host -ForegroundColor Red $env:UserDomain\$env:UserName
 Write-Host -Nonewline -ForegroundColor Green "Started at: "
 Write-Host -ForegroundColor Red $(Get-Date)
 Write-Host
 Write-Host -Nonewline "Items in "
 Write-Host -ForegroundColor Red -NoNewline "Red" 
 Write-Host -NoNewline " Are potential privesc routes, check them out!" 
 Write-Host
 Write-Host -Nonewline "Items in "
 Write-Host -ForegroundColor Yellow -NoNewline "Yellow" 
 Write-Host -NoNewline " Could be useful, have a look" 
 Write-Host
 Write-Host -Nonewline "Items in "
 Write-Host -ForegroundColor Green -NoNewline "Green" 
 Write-Host -NoNewline " Are information which might help with other approaches" 
 Write-Host


 

$commands = [ordered]@{


    '###-SYSTEM INFORMATION-###' = 'write-host @"
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
=============================
"@';
    'Basic System Information'                    = 'systeminfo';
    'Environment Variables'                       = 'Get-ChildItem Env: | ft Key,Value';


       '###-USER INFORMATION-###' = 'write-host @"
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
=============================
"@';

    'Current User'                                = 'Write-Host $env:UserDomain\$env:UserName';
    'Current User Privileges'                             = 'whoami /priv';
    'Current User Groups'                             = 'whoami /groups';
    'Current User Command History'                = 'Get-history';
    'Local Users'                                 = 'Get-LocalUser | ft Name,Enabled,LastLogon';
    'Local Administrators'                        = 'Get-LocalGroupMember Administrators | ft Name, PrincipalSource';
    'Local Groups'                                = 'Get-LocalGroup | ft Name';
    'Logged in Users'                             = 'qwinsta';
    'Recent RDP Sessions'                         = 'get-winevent -logname "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"';
    'User Directories'                            = 'Get-ChildItem C:\Users | ft Name';
    'Password policy'                             = 'net accounts'
    'Credential Manager'                          = 'cmdkey /list'
    'User Autologon Registry Items'               = 'Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*" | ft';
    
    
     '###-----NETWORK-----###' = 'write-host @"
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
=============================
"@'; 

    'Network Information'                         = 'Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address';
    'DNS Servers'                                 = 'Get-DnsClientServerAddress -AddressFamily IPv4 | ft';
    'ARP cache'                                   = 'Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State';
    'Routing Table'                               = 'Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex';
    'Network Connections'                         = 'netstat -ano';
    'Proxy Settings'                              = 'netsh winhttp show proxy'
    'Connected Drives'                            = 'Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft';
    'PuTTY sessions'                              = 'Get-ChildItem HKCU:\Software\SimonTatham\PuTTY\Sessions'
    'Saved PuTTY SSH Keys'                        = 'Get-Childitem HKCU:\Software\SimonTatham\PuTTY\SshHostKeys\'
    'RDP Session log'                             = 'Get-EventLog security -after (Get-date -hour 0 -minute 0 -second 0) | ?{$_.eventid -eq 4624 -and $_.Message -match "logon type:\s+(10)\s"} | Out-GridView'


       '###-FIREWALL / AV-###' = 'write-host @"
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
=============================
"@';

    'Defender status'                             = 'Get-MpComputerStatus';
    'App Locker Policies'                         = 'Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections';
    'Firewall Config'                             = 'netsh firewall show config';



   '###-PROCESS / PROGS-###' = 'write-host @"
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
=============================
"@';

     'Running Processes'                           = 'gwmi -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize';
     'Running Services'                            = 'tasklist /svc';
         'Checking registry for AlwaysInstallElevated' = 'Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer" | ft';
    'Unquoted Service Paths'                      = 'gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike ''"*''} | select PathName, DisplayName, Name | ft';
      'Software in Registry'  = 'Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name';
   
   
  
    'Searching for SAM backup files'              = 'Test-Path %SYSTEMROOT%\repair\SAM ; Test-Path %SYSTEMROOT%\system32\config\regback\SAM';
    'Installed Software Directories'              = 'Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | ft Parent,Name,LastWriteTime';
  

    'Folders with Everyone Permissions'           = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "Everyone"} } catch {}} | ft';
    'Folders with BUILTIN\User Permissions'       = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } catch {}} | ft';
    

    'Scheduled Tasks'                             = 'Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State';
    'Tasks Folder'                                = 'Get-ChildItem C:\Windows\Tasks | ft';
    'Startup Commands'                            = 'Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl';
    'Searching for named pipes'                   = 'gci \\.\pipe\'
    
    'Searching for Unattend and Sysprep files' = 'Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}';
    'Searching for web.config files'           = 'Get-Childitem –Path C:\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue';
    'Searching for other interesting files'    = 'Get-Childitem –Path C:\ -Include *password*,*cred*,*vnc* -File -Recurse -ErrorAction SilentlyContinue';
    'Searching for various config files'       = 'Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue'
    'Searching HKLM for passwords'             = 'reg query HKLM /f password /t REG_SZ /s';
    'Searching HKCU for passwords'             = 'reg query HKCU /f password /t REG_SZ /s ';
    'Searching for files with passwords'       = 'Get-ChildItem c:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSPath -notlike "*C:\temp*" -and $_.PSParentPath -notlike "*Reference Assemblies*" -and $_.PSParentPath -notlike "*Windows Kits*"}| Select-String -Pattern "password" ';
    
    
}

# Match interesting strings from output
function Format-Color([hashtable] $Colors = @{}, [switch] $SimpleMatch) {
    $lines = ($input | Out-String) -replace "`r", "" -split "`n"
    foreach($line in $lines) {
        $color = ''
        foreach($pattern in $Colors.Keys){
            if(!$SimpleMatch -and $line -match $pattern) { $color = $Colors[$pattern] }
            elseif ($SimpleMatch -and $line -like $pattern) { $color = $Colors[$pattern] }
        }
        if($color) {
            Write-Host -ForegroundColor $color $line
        } else {
            Write-Host $line
        }
    }
}

#interesting strings to highlight
$interesting = @{ 

#high value, take a look a this!
'Administrator' = 'Red'; 
'Admin' = 'Red';
'NT AUTHORITY\SYSTEM' = 'Red';
'OS Version' = 'Red';
'Hotfix(s)' = 'Red';
'NT AUTHORITY' = 'Red';
'Administrators' = 'Red';
'adm' = 'Red';
'Server Operators' = 'Red';
'Backup Operators' = 'Red';
'Print Operators' = 'Red';
'SeBackupPrivilege' = 'Red';
'SeTakeOwnershipPrivilege' = 'Red';
'SeDebugPrivilege' = 'Red';
'SeImpersonatePrivilege' = 'Red';
'SeRestorePrivilege' = 'Red';
'Pass' = 'Red';
'Password' = 'Red';
'SeLoadDriverPrivilege' = 'Red';

'svc' = 'Yellow';
'Account Operators' = 'Yellow';
'Remote Desktop Users' = 'Yellow';
'Remote Management Users' = 'Yellow';
'Event Log Viewers' = 'Yellow';
'DNS Admins' = 'Yellow';
'User' = 'Yellow';
'127.0.' = 'Yellow';


'System Boot Time' = 'Green';
'Lockout threshold' = 'Green';
'Lockout duration' = 'Green';
'Minimum password length' = 'Green';
'Domain' = 'Green';
'SeSecurityPrivilege' = 'Green';
'SeShutdownPrivilege' = 'Green';
'Disabled' = 'Green';
'Python' = 'Green';
'xampp' = 'Green';
'iis' = 'Green';


}

function RunCommands($commands) {
    ForEach ($command in $commands.GetEnumerator()) {
        printitem $command.Name
        Invoke-Expression $command.Value | Format-Color $interesting
    }
}


RunCommands($commands)






