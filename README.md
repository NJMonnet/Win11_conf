# Script de configuration de Windows 11
Ce script a pour but de simplifier les installations et de permettre aux nouvelles sessions utilisateurs d'être préconfiguré correctement.

# Prérequis
Un installation de Windows 11 est necéssaire pour le bon fonctionnement du script 

# Fonctions du script
* Modification du nom du volume 'C' en 'System'
* Exécution du fichier Ninite.exe
* Suppression des layout de clavier non-utilisé
* Modification du Layout du menu de démarrage pour les nouveaux utilisateurs et l'utilisateur actuel
* Désinstallation des packages des bloatwares Windows
* Installation de .NET Framework 3.5 depuis internet
* Suppression des icônes du bureau, excepté la corbeille
* Synchronisation de l'horloge
* Modification des clés de registre pour activer DisableConsumerAccountStateContent et DisableWindowsConsumerFeatures
* Modification de la clé de registre pour la correction d'erreur DCOM
* Modification de la clé de registre pour activer l'ouverture de l'explorateur de fichiers sur "Ce PC"
* Modification de clés de registre pour modifier les paramètres de la barre des tâches
* Modification de la clé de registre pour désactiver l'IPv6
* Modification de la clé de registre pour retirer le Microsoft store de la barre des tâches
* Modification de la clé de registre pour activer le numpad au démarrage

# Utilisation du script :
Lors de l'exécution du script, il ne faut pas créer de compte utilisateur.

Exemple dans un invite de commande Powershell avec les droits adiministrateur :
```
$ cd D:\Ventoy\Win11_Conf_Script; Set-ExecutionPolicy Unrestricted; .\win11conf.ps1
```
