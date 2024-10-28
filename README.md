# Windows 11 configuration script
This script is designed to simplify installations and enable new user sessions to be pre-configured correctly for a professional environment.

# Prerequisites
Windows 11 installation and an administrator account are required for the script to work properly.

# Script functions
* Change volume name 'C' to 'System'
* Run Ninite.exe file (Please create your own : https://ninite.com/)
* Delete unused keyboard layouts
* Change start menu layout for new and current users
* Uninstall Windows bloatware packages
* Install .NET Framework 3.5 from the Internet
* Removal of desktop icons, except for the Recycle Bin
* Clock synchronization
* Registry keys modified to enable DisableConsumerAccountStateContent and DisableWindowsConsumerFeatures
* Registry key modified for DCOM error correction
* Registry key modification to enable file explorer opening on “This PC”.
* Registry key modification to change taskbar settings
* Registry key modification to disable IPv6
* Registry key modification to remove Microsoft store from taskbar
* Registry key modification to enable numpad at startup

# Using the script :
When running the script, do not create a user account.

Here's how to use the script in a powershell command prompt with administrator rights:
```
$ cd C:\temp\Win11_conf; Set-ExecutionPolicy Unrestricted; .\win11conf.ps1
```
