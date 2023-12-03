# Beady-eyed Windows Mouse - Windows Privilege Escalation Script

This script is designed to assist in the detection of possible misconfigurations that may lead to privilege escalation on a Windows system. 
I use this as a "first view" script to gather basic system config information and detect "easy win" vulnerabilities - it is not intended to replace more comprehensive tools, such as WinPEAS.
It provides a quick overview of system information, user and group details, file permissions, network configurations, running processes, scheduled tasks, and potential security issues.

The Beady-eyed Mouse is a cute little mouse found in Columbia and Ecuador - with those beady eyes, if a mouse was going to be good at privilege esealation, it would be this one :)

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
