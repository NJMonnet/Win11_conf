# Affichage du menu de selection du layout du clavier
Write-Host "Veuillez selectionner le layout du clavier :"
Write-Host "1. fr-CH"
Write-Host "2. de-CH"
Write-Host "3. en-US"
$choice = Read-Host "Entrez le numero correspondant au layout choisie (1/2/3) :"

switch ($choice) {
    "1" { $lang = "fr-CH"; $executeLanguageRemoval = $true }
    "2" { $lang = "de-CH"; $executeLanguageRemoval = $true }
    "3" { $lang = "en-US"; $executeLanguageRemoval = $true }
    default { Write-Host "Choix du layout non valide. Utilisation par defaut de fr-CH."; $lang = "fr-CH"; $executeLanguageRemoval = $true }
}

# Affichage du message en fonction du layout selectionnee
Write-Host "Layout selectionnee : $lang"

if ($executeLanguageRemoval) {
    Write-Host "Retrait des layouts autres que $lang"
    try {
        Set-WinUserLanguageList -LanguageList $lang -Force
        Write-Host "Les layouts autres que $lang ont ete retires avec succes." -ForegroundColor Green
    } catch {
        Write-Host "Une erreur s'est produite lors de la suppression des layouts : $_" -ForegroundColor Red
    }
}

# Modification du nom du volume 'C' en 'System'
Write-Host "Changement du nom du volume 'C' en 'System'"
try {
    $volume = Get-Volume -DriveLetter "C"
    $volume | Set-Volume -NewFileSystemLabel "System"
    Write-Host "Le nom du volume C a ete modifie avec succes." -ForegroundColor Green
} catch {
    Write-Host "Une erreur s'est produite lors du changement de nom du volume : $_" -ForegroundColor Red
}

# Suppresion des shortcurt dans le menu demarrer
$batFile = ".\removemsapp.bat"
Write-Host "Execution du fichier .bat en tant qu'administrateur pour suppression des shortcut inutilises dans le menu demarrer..."
try {
    Start-Process -FilePath $batFile -Verb RunAs -Wait
    Write-Host "Le fichier .bat a ete execute avec succes." -ForegroundColor Green
} catch {
    Write-Host "Une erreur s'est produite lors de l'execution du fichier .bat : $_" -ForegroundColor Red
}

# Execution du fichier Ninite.exe
$filePath = ".\Ninite.exe"
Write-Host "Execution du fichier Ninite.exe..."
$process = Start-Process -FilePath $filePath -PassThru -Verb RunAs
# Verification du lancement de l'executable
if ($process -ne $null) {
    Write-Host "Le fichier Ninite.exe a ete execute avec succes." -ForegroundColor Green
} else {
    Write-Host "Echec de l'execution du fichier Ninite.exe." -ForegroundColor Red
}

# Modification du Layout du menu de demarrage pour les nouveaux utilisateurs
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$destinationPath = "C:\Users\default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
try {
    if (-not (Test-Path -Path $destinationPath)) {
        New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
    }

    Copy-Item -Path "$scriptPath\start2.bin" -Destination "$destinationPath\start2.bin" -Force

    if (Test-Path -Path "$destinationPath\start2.bin") {
        Write-Host "Le fichier start2.bin a ete copie avec succes vers $destinationPath." -ForegroundColor Green
    } else {
        Write-Host "Une erreur s'est produite lors de la copie du fichier start2.bin." -ForegroundColor Red
    }
} catch {
    Write-Host "Une erreur s'est produite lors de la modification du Layout du menu de demarrage : $_" -ForegroundColor Red
}


# Desinstallation des packages des bloatwares Windows
$appNames = @(
    "Microsoft.549981C3F5F10"

    "Clipchamp.Clipchamp"

    "Microsoft.BingNews"

	"Microsoft.BingWeather"

	"Microsoft.GamingApp"

	"Microsoft.GetHelp"

	"Microsoft.MicrosoftOfficeHub"

	"Microsoft.MicrosoftSolitaireCollection"

	"Microsoft.WindowsFeedbackHub"

	"Microsoft.WindowsMaps"

	"Microsoft.Xbox.TCUI"

	"Microsoft.XboxGameOverlay"

	"Microsoft.XboxGamingOverlay"

	"Microsoft.XboxIdentityProvider"

	"Microsoft.XboxSpeechToTextOverlay"

	"Microsoft.ZuneMusic"

	"Microsoft.ZuneVideo"

	"MicrosoftTeams"

	"BytedancePte.Ltd.TikTok"

	"SpotifyAB.SpotifyMusic"

	"Facebook.InstagramBeta"

	"5319275A.WhatsAppDesktop"

	"AmazonVideo.PrimeVideo"

	"22364Disney.ESPNBetaPWA"


)

# Desinstallation de chaque application pour tous les utilisateurs
foreach ($appName in $appNames) {
    $app = Get-AppxPackage -AllUsers -Name $appName
    if ($app -ne $null) {
        $app | Remove-AppxPackage -AllUsers
        if ((Get-AppxPackage -AllUsers -Name $appName) -eq $null) {
            Write-Host "$appName desinstalle avec succes." -ForegroundColor Green
        } else {
            Write-Host "Echec de la desinstallation de $appName." -ForegroundColor Red
        }
    } else {
        Write-Host "$appName n'est pas installe."
    }
}

# Installation de .NET Framework 3.5 depuis internet
Write-Host "Installation de .NET Framework 3.5..."
Add-WindowsCapability -Online -Name NetFx3~~~~ -Source C:\path\to\cabfile
Write-Host ".NET Framework 3.5 a ete installe avec succes." -ForegroundColor Green

# Suppression des icones du bureau, exceptees corbeilles et applications specifiques
Write-Host "Suppression des icones du bureau, excepte la corbeille..."
$desktopPath = [Environment]::GetFolderPath("Desktop")
$desktopItems = Get-ChildItem -Path $desktopPath | Where-Object { $_.Name -ne "Corbeille" }
foreach ($item in $desktopItems) {
    Write-Host "Suppression de l'icone $($item.Name)..." -ForegroundColor Green
    Remove-Item -Path $item.FullName -Force
}

# Suppression des icones du dossier Desktop Public, excepte la Corbeille
try {
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $desktopItems = Get-ChildItem -Path $desktopPath | Where-Object { $_.Name -ne "Corbeille" }
    foreach ($item in $desktopItems) {
        Write-Host "Suppression de l'icône $($item.Name)..." -ForegroundColor Green
        Remove-Item -Path $item.FullName -Force
    }

    # Suppression des icônes du dossier Desktop Public, excepte la Corbeille
    $publicDesktopPath = [Environment]::GetFolderPath("CommonDesktopDirectory")
    $publicDesktopItems = Get-ChildItem -Path $publicDesktopPath | Where-Object { $_.Name -ne "Corbeille" }
    foreach ($item in $publicDesktopItems) {
        Write-Host "Suppression de l'icône $($item.Name) du dossier Desktop Public..." -ForegroundColor Green
        Remove-Item -Path $item.FullName -Force
    }
    Write-Host "Les icônes du bureau et du Desktop Public ont ete supprimees avec succes." -ForegroundColor Green
} catch {
    Write-Host "Une erreur s'est produite lors de la suppression des icônes du bureau et du Desktop Public : $_" -ForegroundColor Red
}

# Synchronisation de l'horloge
W32tm /resync /force > $null 2>&1

# Modification REGEDIT

# Correction d'erreur DCOM
# Chemin de la cle de registre a modifier
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{1b562e86-b7aa-4131-badc-b6f3a001407e}"

# Nouvelle valeur a definir pour Enabled (0 pour desactiver)
$newValue = 0

# Modification de la valeur de Enabled dans la cle de registre
Set-ItemProperty -Path $registryPath -Name "Enabled" -Value $newValue
Write-Host "La valeur Enabled de la cle de registre a ete modifiee avec succes." -ForegroundColor Green

# Modification du registre CUSER

# Definition des parametres pour Set-ItemProperty, cela permet d'ouvrir l'explorateur de fichier sur "Ce PC"
$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$registryName = 'LaunchTo'
$newValue = 1

Write-Host "Modification de la cle de registre pour ouverture de l'explorateur de fichier sur Ce PC : $registryPath\$registryName..."
# Execution de Set-ItemProperty avec les parametres definis ci-dessus
Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue
Write-Host "La valeur de la cle de registre $registryPath\$registryName a ete modifiee avec succes." -ForegroundColor Green

# Modification des parametres de la barre des taches
Write-Host "Modification des parametres de la barre des taches..."
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "TaskbarMn" /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarMode" /t REG_DWORD /d 1 /f
# Chemin de la cle de registre pour retirer 'Widgets' dans la barre des taches
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Write-Host "Ajout de la cle de registre TaskbarDa..."
Set-ItemProperty -Path $registryPath -Name "TaskbarDa" -Value 0
Write-Host "Les parametres de la barre des taches ont ete modifies avec succes." -ForegroundColor Green

# Modification des cles de registre Local Machine et Current User

#Desactivation de l'IPv6
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 255 -Type DWORD

# Definition du chemin de la cle de registre Local Machine
Write-Host "Mise en place de la GPO Local Machine NoPinningStoreToTaskbar"
$localMachinePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
# Creation de la cle de registre "Explorer" dans Local Machine
New-Item -Path $localMachinePath -Force | Out-Null
# Definition de la valeur DWORD "NoPinningStoreToTaskbar" avec une valeur de 1 dans Local Machine
Set-ItemProperty -Path $localMachinePath -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord
Write-Host "La GPO Local Machine NoPinningStoreToTaskbar a ete activee avec succes"

# Definition du chemin de la cle de registre Current User
Write-Host "Mise en place de la GPO Current User NoPinningStoreToTaskbar"
$currentUserPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
# Creation de la cle de registre "Explorer" dans Current User
New-Item -Path $currentUserPath -Force | Out-Null
# Definition de la valeur DWORD "NoPinningStoreToTaskbar" avec une valeur de 1 dans Current User
Set-ItemProperty -Path $currentUserPath -Name "NoPinningStoreToTaskbar" -Value 1 -Type DWord
Write-Host "La GPO Current User NoPinningStoreToTaskbar a ete activee avec succes"

# Modification du registre USER

# Activation du numpad au demarrage
$registryPath = "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard"
$registryName = "InitialKeyboardIndicators"
$newValue = 2

Write-Host "Modification de la cle de registre pour l'activation du numpad au demarrage : $registryPath\$registryName..."
Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue
Write-Host "La valeur de la cle de registre a ete modifiee avec succes." -ForegroundColor Green

# Definition du lecteur HKU:
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

$ntuserPath = "C:\Users\Default\NTUSER.DAT"

# Charger la ruche par defaut
$regHivePath = "HKU:\TempHive"
$regHive = Get-Item -Path $regHivePath -ErrorAction SilentlyContinue
if ($regHive -eq $null) {
    Invoke-Command -ScriptBlock { param($ntuserPath) reg.exe load HKU\TempHive $ntuserPath } -ArgumentList $ntuserPath
    $regHive = Get-Item -Path $regHivePath
}


# Definition des parametres pour Set-ItemProperty, cela permet d'ouvrir l'explorateur de fichier sur "Ce PC"
$registryPath = "HKU:\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$registryName = 'LaunchTo'
$newValue = 1

Write-Host "Modification de la cle de registre pour ouverture de l'explorateur de fichier sur Ce PC : $registryPath\$registryName..."
# Execution de Set-ItemProperty avec les parametres definis ci-dessus
Set-ItemProperty -Path $registryPath -Name $registryName -Value $newValue
Write-Host "La valeur de la cle de registre $registryPath\$registryName a ete modifiee avec succes." -ForegroundColor Green

# Modification des parametres de la barre des taches
Write-Host "Modification des parametres de la barre des taches..."
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "TaskbarMn" /t REG_DWORD /d 0 /f
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarMode" /t REG_DWORD /d 1 /f
reg add HKU\TempHive\Software\Microsoft\Windows\CurrentVersion\Search /v "SearchboxTaskbarModeCache" /t REG_DWORD /d 1 /f
# Chemin de la cle de registre pour retirer 'Widgets' dans la barre des taches
$registryPath = "HKU:\TempHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Write-Host "Ajout de la cle de registre TaskbarDa..."
Set-ItemProperty -Path $registryPath -Name "TaskbarDa" -Value 0
Write-Host "Les parametres de la barre des taches ont ete modifies avec succes." -ForegroundColor Green

$registryPath = "HKU:\TempHive\software\Microsoft\Windows\CurrentVersion\Run"
$valueName = "OneDriveSetup"

if (Test-Path $registryPath) {
    Remove-ItemProperty -Path $registryPath -Name $valueName -Force
}
Remove-ItemProperty -Path "HKU:\TempHive\Keyboard Layout\Preload" -Name "2"

# Redemarrage de l'ordinateur a la fermeture de Ninite
Write-Host "Redemarrage de l'ordinateur a la fermeture de Ninite"
$process.WaitForExit()
Restart-Computer -Force