# Script de configuration de Windows 11
Ce script a pour but de simplifier les installations et
de permettre aux nouvelles sessions utilisateurs d'être préconfiguré correctement.

## Le script permet de :
1. Modification du nom du volume 'C' en 'System'
2. Suppression des langues indésirable
3. Modification du layout du menu de demarrage pour les nouveaux utilisateurs et l'utilisateur actuel
4. Désinstallation des applications indésirable
5. Installation de .NET Framework 3.5 depuis internet
6. Suppression des icônes du bureau, exceptées corbeilles et applications spécifiques
7. Résolution erreur DCOM 'APPID non disponible'
8. Modification Regedit sur l'explorateur de fichier (Parametre d'ouverture 'CE PC')
9. Désactivation de l'IPv6
10. Modification des paramètres de la barre de tâche et autres changements pratique sous regedit
11. Installation des apps voulu avec le Ninite.exe

## Utilisation du script :
Il est déconseillé d’exécuter le script sur le bureau du fait qu’il supprime les icônes étant présente à cet endroit.
Lors de l'exécution du script, il ne faut pas se connecter à un compte utilisateur.
Il est conseillé de faire les mises à jour Windows avant l'exécution du script.

Exécuter cette commande dans une invite de commande Powershell avec les droits administrateur :
cd emplacement_du_script; Set-ExecutionPolicy Unrestricted; .\Win11_Conf.ps1
