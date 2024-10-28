<#
.SYNOPSIS
  Windows 11 configuration script
.DESCRIPTION
  This script is designed to simplify installations and enable new user sessions to be pre-configured correctly for a professional environment.
.NOTES
  Version:        1.1
  Author:         Monnet
.LINK
  https://github.com/NMJLorsal/Win11_conf
#>

# Display of keyboard layout selection menu
Write-Host "Please select the keyboard layout :"
Write-Host "1. fr-CH"
Write-Host "2. de-CH"
Write-Host "3. en-US"
$choice = Read-Host "Enter the number corresponding to the chosen layout (1/2/3) :"

switch ($choice) {
    "1" { $lang = "fr-CH"; $executeLanguageRemoval = $true }
    "2" { $lang = "de-CH"; $executeLanguageRemoval = $true }
    "3" { $lang = "en-US"; $executeLanguageRemoval = $true }
    default { Write-Host "Invalid layout choice. Default use of en-US."; $lang = "en-US"; $executeLanguageRemoval = $true }
}

# Message display based on selected layout
Write-Host "Selected layout : $lang"

# Deleting layouts other than the selected one
if ($executeLanguageRemoval) {
    Write-Host "Removing layouts other than $lang"
    try {
        Set-WinUserLanguageList -LanguageList $lang -Force
        Write-Host "Layouts other than $lang have been successfully removed." -ForegroundColor Green
    } catch {
        Write-Host "An error occurred when deleting layouts: $_" -ForegroundColor Red
    }
}

# Change volume name 'C' to 'System
Write-Host "Change volume name 'C' to 'System"
try {
    $volume = Get-Volume -DriveLetter "C"
    $volume | Set-Volume -NewFileSystemLabel "System"
    Write-Host "Volume C has been successfully renamed." -ForegroundColor Green
} catch {
    Write-Host "An error occurred when renaming the volume : $_" -ForegroundColor Red
}

# Running Ninite.exe
$filePath = ".\Ninite.exe"
Write-Host "Running Ninite.exe..."
$process = Start-Process -FilePath $filePath -PassThru -Verb RunAs
# Check executable launch
if ($process -ne $null) {
    Write-Host "Ninite.exe has been executed successfully." -ForegroundColor Green
} else {
    Write-Host "Failed to execute Ninite.exe file." -ForegroundColor Red
}

# Modifying the start menu layout for the current user
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$username = (Get-ChildItem Env:\USERNAME).Value
$destinationPath = "C:\Users\$username\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
try {
    if (-not (Test-Path -Path $destinationPath)) {
        New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
    }

    Copy-Item -Path "$scriptPath\start2.bin" -Destination "$destinationPath\start2.bin" -Force

    if (Test-Path -Path "$destinationPath\start2.bin") {
        Write-Host "The file start2.bin has been successfully copied to $destinationPath." -ForegroundColor Green
    } else {
        Write-Host "An error occurred when copying the start2.bin file." -ForegroundColor Red
    }
} catch {
    Write-Host "An error occurred when modifying the Start menu layout: $_" -ForegroundColor Red
}
stop-process -name explorer –force

# Modifying the start menu layout for new users
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$destinationPath = "C:\Users\default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
try {
    if (-not (Test-Path -Path $destinationPath)) {
        New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
    }

    Copy-Item -Path "$scriptPath\start2.bin" -Destination "$destinationPath\start2.bin" -Force

    if (Test-Path -Path "$destinationPath\start2.bin") {
        Write-Host "The file start2.bin has been successfully copied to $destinationPath." -ForegroundColor Green
    } else {
        Write-Host "An error occurred when copying the start2.bin file." -ForegroundColor Red
    }
} catch {
    Write-Host "An error occurred when modifying the Start menu layout: $_" -ForegroundColor Red
}

# Uninstalling Windows bloatware packages
$appNames = @(
    "Microsoft.549981C3F5F10",
    "Clipchamp.Clipchamp",
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.GamingApp",
    "Microsoft.GetHelp",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "MicrosoftTeams",
    "BytedancePte.Ltd.TikTok",
    "SpotifyAB.SpotifyMusic",
    "Facebook.InstagramBeta",
    "5319275A.WhatsAppDesktop",
    "AmazonVideo.PrimeVideo",
    "22364Disney.ESPNBetaPWA"
)

# Uninstall each application for all users
foreach ($appName in $appNames) {
    $app = Get-AppxPackage -AllUsers -Name $appName
    if ($null -ne $app) {
        $app | Remove-AppxPackage -AllUsers
        if ($null -eq (Get-AppxPackage -AllUsers -Name $appName)) {
            Write-Host "$appName désinstallé avec succès." -ForegroundColor Green
        } else {
            Write-Host "Failed to uninstall $appName." -ForegroundColor Red
        }
    } else {
        Write-Host "$appName is not installed."
    }
}

# Installing .NET Framework 3.5 from the Internet
Write-Host "Installing .NET Framework 3.5..."
Add-WindowsCapability -Online -Name NetFx3~~~~ -Source C:\path\to\cabfile
Write-Host ".NET Framework 3.5 has been successfully installed." -ForegroundColor Green

# Delete all Desktop Public folder icons except the Recycle Bin
$desktopPath = [Environment]::GetFolderPath("Desktop")
$desktopItems = Get-ChildItem -Path $desktopPath | Where-Object { $_.Name -ne "Corbeille" }
foreach ($item in $desktopItems) {
    Write-Host "Deleting the icon $($item.Name)..." -ForegroundColor Green
    Remove-Item -Path $item.FullName -Force
}

# Delete all Desktop Public folder icons except the Recycle Bin
try {
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $desktopItems = Get-ChildItem -Path $desktopPath | Where-Object { $_.Name -ne "Corbeille" }
    foreach ($item in $desktopItems) {
        Write-Host "Delete icon $($item.Name)..." -ForegroundColor Green
        Remove-Item -Path $item.FullName -Force
    }

    # Suppression des icônes du dossier Desktop Public, excepté la Corbeille
    $publicDesktopPath = [Environment]::GetFolderPath("CommonDesktopDirectory")
    $publicDesktopItems = Get-ChildItem -Path $publicDesktopPath | Where-Object { $_.Name -ne "Corbeille" }
    foreach ($item in $publicDesktopItems) {
        Write-Host "Remove $($item.Name) icon from Desktop Public folder..." -ForegroundColor Green
        Remove-Item -Path $item.FullName -Force
    }
    Write-Host "Desktop and Desktop Public icons have been successfully removed." -ForegroundColor Green
} catch {
    Write-Host "An error occurred when deleting the desktop and Desktop Public icons: $_" -ForegroundColor Red
}

# Clock synchronization (broken 3/4 of the time)
Write-Host "Clock synchronization..."
try {
    w32tm /resync
    Write-Host "The clock has been successfully synchronized." -ForegroundColor Green
} catch {
    Write-Host "An error has occurred during clock synchronization: $_" -ForegroundColor Red
}

# Uninstalling OneDrive
# Thanks to : https://github.com/asheroto/UninstallOneDrive
function Uninstall-OneDrive {
    param (
        [string]$Path
    )
    if (Test-Path $Path) {
        Write-Output "Uninstalling OneDrive found in $Path"
        $proc = Start-Process $Path "/uninstall" -PassThru
        $proc.WaitForExit()
    } else {
        Write-Output "Path `"$Path`" not found, skipping..."
    }
}

function Get-UninstallString {
    param (
        [string]$Match
    )
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            $uninstallString = Get-ChildItem -Path $path | 
            Get-ItemProperty | 
            Where-Object { $_.DisplayName -like "*$Match*" } |
            Select-Object -ExpandProperty UninstallString -First 1
            if ($uninstallString) {
                return $uninstallString
            }
        }
    }
    return $null
}

try {
    $oneDrivePaths = @(
        "$ENV:SystemRoot\System32\OneDriveSetup.exe",
        "$ENV:SystemRoot\SysWOW64\OneDriveSetup.exe",
        "$ENV:ProgramFiles\Microsoft Office\root\Integration\Addons\OneDriveSetup.exe",
        "${ENV:ProgramFiles(x86)}\Microsoft Office\root\Integration\Addons\OneDriveSetup.exe"
    )

    Write-Output "Désinstallation de OneDrive"
    Stop-Process -Name OneDrive* -Force -ErrorAction SilentlyContinue

    # Uninstall from common locations
    foreach ($path in $oneDrivePaths) {
        Uninstall-OneDrive -Path $path
    }

    # Uninstall from Uninstall registry key UninstallString
    $uninstallString = Get-UninstallString -Match "OneDrive"
    if ($uninstallString) {
        Write-Output "Uninstalling OneDrive found in Uninstall registry key..."
        try {
            # Remove quotation marks from the uninstall string
            $uninstallString = $uninstallString.Replace('"', '')

            $exePath = $uninstallString.Substring(0, $uninstallString.IndexOf(".exe") + 4).Trim()
            $argz = $uninstallString.Substring($uninstallString.IndexOf(".exe") + 5).Trim().replace("  ", " ")

            # Write the path of the executable and the arguments to the console
            Write-Output "`t`"$exePath`""

            $proc = Start-Process -FilePath $exePath -Args $argz -PassThru
            $proc.WaitForExit()
        } catch {
            Write-Output "Uninstall failed with exception: $($_.Exception.Message)"
        }
    } else {
        Write-Output "No OneDrive uninstall string found in registry, skipping..."
    }

    # Remove OneDrive scheduled tasks
    Get-ScheduledTask -TaskName "OneDrive*" | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    # Output uninstall complete
    Write-Output "Uninstall complete!"
} catch {
    Write-Warning "Uninstall failed with exception: $($_.Exception.Message)"
    exit 1
}

# Regedit modification
# Function to display messages in color
function Write-ColorMessage {
    param (
        [string]$message,
        [string]$color = "Green"
    )
    Write-Host $message -ForegroundColor $color
}

# Error handling function
function Handle-Error {
    param (
        [string]$errorMessage
    )
    Write-ColorMessage "Erreur : $errorMessage" "Red"
}

# Function to update a registry key
function Update-RegistryKey {
    param (
        [string]$registryPath,
        [string]$valueName,
        [int]$newValue
    )
    try {
        if (-not (Test-Path $registryPath)) {
           New-Item -Path $registryPath -Force | Out-Null
        }
        $valueExists = Test-Path "$registryPath\$valueName"
        if (-not $valueExists) {
            New-ItemProperty -Path $registryPath -Name $valueName -Value $newValue -PropertyType DWORD -Force | Out-Null
        } else {
            Set-ItemProperty -Path $registryPath -Name $valueName -Value $newValue -Type DWORD -ErrorAction Stop
        }
        $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName
        if ($currentValue.$valueName -eq $newValue) {
            Write-ColorMessage "The $valueName value of the registry key has been successfully activated."
        } else {
            Handle-Error "The $valueName value of the registry key has not been activated."
        }
    } catch {
        Handle-Error $_.Exception.Message
    }
}

# Change registry keys to enable DisableConsumerAccountStateContent, DisableCloudOptimizedContent and DisableWindowsConsumerFeatures
# https://www.tenable.com/audits/items/CIS_MS_Windows_11_Enterprise_Level_1_Bitlocker_v1.0.0.audit:77238250114c3e75f5635582b1a58180
# https://www.tenable.com/audits/items/CIS_Microsoft_Windows_Server_2019_STIG_v1.0.1_L2_DC.audit:7b0f89b94e066df1285bedb8b6b8876e
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$registryValues = @(

    @{
        Name = "DisableConsumerAccountStateContent"
        Value = 1
    },
    @{
        Name = "DisableCloudOptimizedContent"
        Value = 1
    }
)
try {
    foreach ($value in $registryValues) {
        Update-RegistryKey -registryPath $registryPath -valueName $value.Name -newValue $value.Value
    }
} catch {
    Handle-Error $_.Exception.Message
}

# Modification of registry key for DCOM error correction, this key may not exist
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{1b562e86-b7aa-4131-badc-b6f3a001407e}"
$valueName = "Enabled"
$newValue = 0

Set-ItemProperty -Path $registryPath -Name $valueName -Value $newValue

# Registry key modified to enable file explorer to open on “This PC”.
$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$registryName = 'LaunchTo'
$newValue = 1

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "The registry key $registryPath\$registryName has been successfully modified."
    } else {
        Handle-Error "The value of the registry key $registryPath\$registryName has not been modified."
    }
} catch {
    Handle-Error $_.Exception.Message
}

# Changing registry keys to modify taskbar settings
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "TaskbarMn" /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarMode" /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarModeCache" /t REG_DWORD /d 1 /f

# Modification of the registry key to remove “Widgets'” from the taskbar
$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$registryName = 'TaskbarDa'
$newValue = 0

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "The registry key $registryPath\$registryName has been successfully modified."
    } else {
        Handle-Error "The value of the registry key $registryPath\$registryName has not been modified."
    }
} catch {
    Handle-Error $_.Exception.Message
}

# Registry key modification to disable IPv6
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$registryName = 'DisabledComponents'
$newValue = 255

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "The registry key $registryPath\$registryName has been successfully modified."
    } else {
        Handle-Error "The value of the registry key $registryPath\$registryName has not been modified."
    }
} catch {
    Handle-Error $_.Exception.Message
}

 # Modification de la clé de registre pour retirer le Microsoft store de la barre des tâches
 $GPOName = "NoPinningStoreToTaskbar"
 $GPOValue = 1

 $GPOPaths = @(
     "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
     "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
 )

 foreach ($path in $GPOPaths) {
     try {
         New-Item -Path $path -Force | Out-Null
         Set-ItemProperty -Path $path -Name $GPOName -Value $GPOValue -Type DWord -ErrorAction Stop
         Write-ColorMessage "The $path\$GPOName GPO has been successfully activated."
     } catch {
         Handle-Error $_.Exception.Message
     }
 }
# https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index
$registryPath = "HKCU:\Keyboard Layout\Preload"

try {
    Remove-ItemProperty -Path $registryPath -Name "2" -ErrorAction Stop
    Write-Host "The Keyboard $registryPath key has been removed" -ForegroundColor Green
} catch {
    Write-Host "The Keyboard $registryPath key did not exist" -ForegroundColor Yellow
}

 # Modify registry key to enable numpad at startup
$registryPath = "Registry::HKU\.DEFAULT\Control Panel\Keyboard"
$registryName = "InitialKeyboardIndicators"
$newValue = 2

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "The registry key $registryPath\$registryName has been successfully modified."
    } else {
        Handle-Error "The value of the registry key $registryPath\$registryName has not been modified."
    }
} catch {
    Handle-Error $_.Exception.Message
}

# Allows you to modify the registry used by new users
# If a session is created during modification, it will be corrupted
# HKU drive definition:
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

$ntuserPath = "C:\Users\Default\NTUSER.DAT"

# Chargement du fichier de registre utilisé par défaut 
$regHivePath = "HKU:\TempHive"
$regHive = Get-Item -Path $regHivePath -ErrorAction SilentlyContinue
if ($null -eq $regHive) {
    Invoke-Command -ScriptBlock { param($ntuserPath) reg.exe load HKU\TempHive $ntuserPath } -ArgumentList $ntuserPath
    $regHive = Get-Item -Path $regHivePath
}

# Registry key modified to enable file explorer to open on “This PC”.
$registryPath = "HKU:\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$registryName = 'LaunchTo'
$newValue = 1

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "The registry key $registryPath\$registryName has been successfully modified."
    } else {
        Handle-Error "The value of the registry key $registryPath\$registryName has not been modified."
    }
} catch {
    Handle-Error $_.Exception.Message
}

# Changing registry keys to modify taskbar settings
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "TaskbarMn" /t REG_DWORD /d 0 /f
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarMode" /t REG_DWORD /d 1 /f
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarModeCache" /t REG_DWORD /d 1 /f

# Modification of the registry key to remove “Widgets'” from the taskbar
$registryPath = "HKU:\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$registryName = 'TaskbarDa'
$newValue = 0

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "The registry key $registryPath\$registryName has been successfully modified."
    } else {
        Handle-Error "The value of the registry key $registryPath\$registryName has not been modified."
    }
} catch {
    Handle-Error $_.Exception.Message
}

# https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index
$registryPath = "HKU:\TempHive\Keyboard Layout\Preload"

try {
    Remove-ItemProperty -Path $registryPath -Name "2" -ErrorAction Stop
    Write-Host "The Keyboard $registryPath key has been removede" -ForegroundColor Green
} catch {
    Write-Host "The Keyboard $registryPath key did not exist" -ForegroundColor Yellow
}

# Restart computer when Ninite is closed
Write-Host "Restarting the computer when Ninite is closed"
$process.WaitForExit()
Restart-Computer -Force
