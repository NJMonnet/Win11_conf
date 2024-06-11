<#
.SYNOPSIS
  Script de configuration de Windows 11
.DESCRIPTION
  Permets de configurer les sessions Windows 11 de manière à être utilisé dans un environnement professionnel
.NOTES
  Version:        1.1
  Author:         Monnet
.LINK
  https://github.com/NMJLorsal/Win11_conf
#>

# Affichage du menu de sélection du layout du clavier
Write-Host "Veuillez sélectionner le layout du clavier :"
Write-Host "1. fr-CH"
Write-Host "2. de-CH"
Write-Host "3. en-US"
$choice = Read-Host "Entrez le numéro correspondant au layout choisi (1/2/3) :"

switch ($choice) {
    "1" { $lang = "fr-CH"; $executeLanguageRemoval = $true }
    "2" { $lang = "de-CH"; $executeLanguageRemoval = $true }
    "3" { $lang = "en-US"; $executeLanguageRemoval = $true }
    default { Write-Host "Choix du layout non valide. Utilisation par défaut de fr-CH."; $lang = "fr-CH"; $executeLanguageRemoval = $true }
}

# Affichage du message en fonction du layout sélectionné
Write-Host "Layout sélectionné : $lang"

# Suppression des layouts autres que celui sélectionné
if ($executeLanguageRemoval) {
    Write-Host "Retrait des layouts autres que $lang"
    try {
        Set-WinUserLanguageList -LanguageList $lang -Force
        Write-Host "Les layouts autres que $lang ont été retirés avec succès." -ForegroundColor Green
    } catch {
        Write-Host "Une erreur s'est produite lors de la suppression des layouts : $_" -ForegroundColor Red
    }
}

# Modification du nom du volume 'C' en 'System'
Write-Host "Changement du nom du volume 'C' en 'System'"
try {
    $volume = Get-Volume -DriveLetter "C"
    $volume | Set-Volume -NewFileSystemLabel "System"
    Write-Host "Le nom du volume C a été modifié avec succès." -ForegroundColor Green
} catch {
    Write-Host "Une erreur s'est produite lors du changement de nom du volume : $_" -ForegroundColor Red
}

# Exécution du fichier Ninite.exe
$filePath = ".\Ninite.exe"
Write-Host "Exécution du fichier Ninite.exe..."
$process = Start-Process -FilePath $filePath -PassThru -Verb RunAs
# Vérification du lancement de l'exécutable
if ($process -ne $null) {
    Write-Host "Le fichier Ninite.exe a ete execute avec succès." -ForegroundColor Green
} else {
    Write-Host "Echec de l'exécution du fichier Ninite.exe." -ForegroundColor Red
}

# Modification du Layout du menu de démarrage pour l'utilisateur actuel
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$username = (Get-ChildItem Env:\USERNAME).Value
$destinationPath = "C:\Users\$username\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
try {
    if (-not (Test-Path -Path $destinationPath)) {
        New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
    }

    Copy-Item -Path "$scriptPath\start2.bin" -Destination "$destinationPath\start2.bin" -Force

    if (Test-Path -Path "$destinationPath\start2.bin") {
        Write-Host "Le fichier start2.bin a été copié avec succès vers $destinationPath." -ForegroundColor Green
    } else {
        Write-Host "Une erreur s'est produite lors de la copie du fichier start2.bin." -ForegroundColor Red
    }
} catch {
    Write-Host "Une erreur s'est produite lors de la modification du Layout du menu de démarrage : $_" -ForegroundColor Red
}

# Modification du Layout du menu de démarrage pour les nouveaux utilisateurs
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$destinationPath = "C:\Users\default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
try {
    if (-not (Test-Path -Path $destinationPath)) {
        New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
    }

    Copy-Item -Path "$scriptPath\start2.bin" -Destination "$destinationPath\start2.bin" -Force

    if (Test-Path -Path "$destinationPath\start2.bin") {
        Write-Host "Le fichier start2.bin a été copié avec succès vers $destinationPath." -ForegroundColor Green
    } else {
        Write-Host "Une erreur s'est produite lors de la copie du fichier start2.bin." -ForegroundColor Red
    }
} catch {
    Write-Host "Une erreur s'est produite lors de la modification du Layout du menu de démarrage : $_" -ForegroundColor Red
}

# Désinstallation des packages des bloatwares Windows
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

# Désinstallation de chaque application pour tous les utilisateurs
foreach ($appName in $appNames) {
    $app = Get-AppxPackage -AllUsers -Name $appName
    if ($null -ne $app) {
        $app | Remove-AppxPackage -AllUsers
        if ($null -eq (Get-AppxPackage -AllUsers -Name $appName)) {
            Write-Host "$appName désinstallé avec succès." -ForegroundColor Green
        } else {
            Write-Host "Échec de la désinstallation de $appName." -ForegroundColor Red
        }
    } else {
        Write-Host "$appName n'est pas installé."
    }
}

# Installation de .NET Framework 3.5 depuis internet
Write-Host "Installation de .NET Framework 3.5..."
Add-WindowsCapability -Online -Name NetFx3~~~~ -Source C:\path\to\cabfile
Write-Host ".NET Framework 3.5 a été installé avec succès." -ForegroundColor Green

# Suppression des icônes du bureau, excepté la corbeille
$desktopPath = [Environment]::GetFolderPath("Desktop")
$desktopItems = Get-ChildItem -Path $desktopPath | Where-Object { $_.Name -ne "Corbeille" }
foreach ($item in $desktopItems) {
    Write-Host "Suppression de l'icône $($item.Name)..." -ForegroundColor Green
    Remove-Item -Path $item.FullName -Force
}

# Suppression des icônes du dossier Desktop Public, excepté la Corbeille
try {
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $desktopItems = Get-ChildItem -Path $desktopPath | Where-Object { $_.Name -ne "Corbeille" }
    foreach ($item in $desktopItems) {
        Write-Host "Suppression de l'icône $($item.Name)..." -ForegroundColor Green
        Remove-Item -Path $item.FullName -Force
    }

    # Suppression des icônes du dossier Desktop Public, excepté la Corbeille
    $publicDesktopPath = [Environment]::GetFolderPath("CommonDesktopDirectory")
    $publicDesktopItems = Get-ChildItem -Path $publicDesktopPath | Where-Object { $_.Name -ne "Corbeille" }
    foreach ($item in $publicDesktopItems) {
        Write-Host "Suppression de l'icône $($item.Name) du dossier Desktop Public..." -ForegroundColor Green
        Remove-Item -Path $item.FullName -Force
    }
    Write-Host "Les icônes du bureau et du Desktop Public ont été supprimées avec succès." -ForegroundColor Green
} catch {
    Write-Host "Une erreur s'est produite lors de la suppression des icônes du bureau et du Desktop Public : $_" -ForegroundColor Red
}

# Synchronisation de l'horloge
Write-Host "Synchronisation de l'horloge..."
try {
    w32tm /resync
    Write-Host "L'horloge a été synchronisée avec succès." -ForegroundColor Green
} catch {
    Write-Host "Une erreur s'est produite lors de la synchronisation de l'horloge : $_" -ForegroundColor Red
}

# Déinistallation de OneDrive 
# Source : https://github.com/asheroto/UninstallOneDrive
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

# Modification regedit
# Fonction permettant d'afficher les messages en couleur
function Write-ColorMessage {
    param (
        [string]$message,
        [string]$color = "Green"
    )
    Write-Host $message -ForegroundColor $color
}

# Fonction permettant de gérer les erreurs
function Handle-Error {
    param (
        [string]$errorMessage
    )
    Write-ColorMessage "Erreur : $errorMessage" "Red"
}

# Fonction permettant de mettre à jour une clé de registre
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
            Write-ColorMessage "La valeur $valueName de la clé de registre a été activée avec succès."
        } else {
            Handle-Error "La valeur $valueName de la clé de registre n'a pas été activée."
        }
    } catch {
        Handle-Error $_.Exception.Message
    }
}

# Modification des clés de registre pour activer DisableConsumerAccountStateContent, DisableCloudOptimizedContent et DisableWindowsConsumerFeatures
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

# Modification de la clé de registre pour la correction d'erreur DCOM, cette clé peut ne pas exister
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{1b562e86-b7aa-4131-badc-b6f3a001407e}"
$valueName = "Enabled"
$newValue = 0

Set-ItemProperty -Path $registryPath -Name $valueName -Value $newValue

# Modification de la clé de registre pour activer l'ouverture de l'explorateur de fichiers sur "Ce PC"
$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$registryName = 'LaunchTo'
$newValue = 1

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "La valeur de la clé de registre $registryPath\$registryName a été modifiée avec succès."
    } else {
        Handle-Error "La valeur de la clé de registre $registryPath\$registryName n'a pas été modifiée."
    }
} catch {
    Handle-Error $_.Exception.Message
}

# Modification de clés de registre pour modifier les paramètres de la barre des tâches
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "TaskbarMn" /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarMode" /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarModeCache" /t REG_DWORD /d 1 /f

# Modification de la clé de registre pour retirer "Widgets'" de la barre des tâches
$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$registryName = 'TaskbarDa'
$newValue = 0

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "La valeur de la clé de registre $registryPath\$registryName a été modifiée avec succès."
    } else {
        Handle-Error "La valeur de la clé de registre $registryPath\$registryName n'a pas été modifiée."
    }
} catch {
    Handle-Error $_.Exception.Message
}

# Modification de la clé de registre pour désactiver l'IPv6
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$registryName = 'DisabledComponents'
$newValue = 255

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "La valeur de la clé de registre $registryPath\$registryName a été modifiée avec succès."
    } else {
        Handle-Error "La valeur de la clé de registre $registryPath\$registryName n'a pas été modifiée."
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
         Write-ColorMessage "La GPO $path\$GPOName a été activée avec succès."
     } catch {
         Handle-Error $_.Exception.Message
     }
 }
# https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index
$registryPath = "HKCU:\Keyboard Layout\Preload"

try {
    Remove-ItemProperty -Path $registryPath -Name "2" -ErrorAction Stop
    Write-Host "La clé Keyboard $registryPath a été retirée" -ForegroundColor Green
} catch {
    Write-Host "La clé Keyboard $registryPath n'existait pas" -ForegroundColor Yellow
}

 # Modification de la clé de registre pour activer le numpad au démarrage
$registryPath = "Registry::HKU\.DEFAULT\Control Panel\Keyboard"
$registryName = "InitialKeyboardIndicators"
$newValue = 2

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "La valeur de la clé de registre $registryPath\$registryName a été modifiée avec succès."
    } else {
        Handle-Error "La valeur de la clé de registre $registryPath\$registryName n'a pas été modifiée."
    }
} catch {
    Handle-Error $_.Exception.Message
}

# Permets de modifier le Registre utilisé par les nouveaux utilisateurs
# Si une session est créée pendant la modification elle sera corrompue
# Définition du lecteur HKU:
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

$ntuserPath = "C:\Users\Default\NTUSER.DAT"

# Chargement du fichier de registre utilisé par défaut 
$regHivePath = "HKU:\TempHive"
$regHive = Get-Item -Path $regHivePath -ErrorAction SilentlyContinue
if ($null -eq $regHive) {
    Invoke-Command -ScriptBlock { param($ntuserPath) reg.exe load HKU\TempHive $ntuserPath } -ArgumentList $ntuserPath
    $regHive = Get-Item -Path $regHivePath
}

# Modification de la clé de registre pour activer l'ouverture de l'explorateur de fichiers sur "Ce PC"
$registryPath = "HKU:\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$registryName = 'LaunchTo'
$newValue = 1

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "La valeur de la clé de registre $registryPath\$registryName a été modifiée avec succès."
    } else {
        Handle-Error "La valeur de la clé de registre $registryPath\$registryName n'a pas été modifiée."
    }
} catch {
    Handle-Error $_.Exception.Message
}

# Modification de clés de registre pour modifier les paramètres de la barre des tâches
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "TaskbarMn" /t REG_DWORD /d 0 /f
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarMode" /t REG_DWORD /d 1 /f
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarModeCache" /t REG_DWORD /d 1 /f

# Modification de la clé de registre pour retirer "Widgets'" de la barre des tâches
$registryPath = "HKU:\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$registryName = 'TaskbarDa'
$newValue = 0

try {
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue -ErrorAction Stop
    $currentValue = Get-ItemProperty -Path $registryPath -Name $registryName
    if ($currentValue.$registryName -eq $newValue) {
        Write-ColorMessage "La valeur de la clé de registre $registryPath\$registryName a été modifiée avec succès."
    } else {
        Handle-Error "La valeur de la clé de registre $registryPath\$registryName n'a pas été modifiée."
    }
} catch {
    Handle-Error $_.Exception.Message
}

# https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index
$registryPath = "HKU:\TempHive\Keyboard Layout\Preload"

try {
    Remove-ItemProperty -Path $registryPath -Name "2" -ErrorAction Stop
    Write-Host "La clé Keyboard $registryPath a été retirée" -ForegroundColor Green
} catch {
    Write-Host "La clé Keyboard $registryPath n'existait pas" -ForegroundColor Yellow
}

# Redémarrage de l'ordinateur a la fermeture de Ninite
Write-Host "Redémarrage de l'ordinateur a la fermeture de Ninite"
$process.WaitForExit()
Restart-Computer -Force