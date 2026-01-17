## Description
Ce projet permet de recueillir des bulletins d’information et d’alerte de l’ANSSI – CERT-FR à partir de leur flux RSS.
Puis extraire les identifiants CVE de ces bulletins ensuite enrichir chaque CVE avec des descriptions du Score CVSS et du niveau de gravité CWE.
Mais aussi du type de vulnérabili Score EPSS Logiciels et versions affectés.
Pour finalement envoyer des alertes par email si un CVE critique touche un éditeur ou un produit configuré. 

## Prérequis
- Python 3.8+
-Bibliothèques Python utilisées :
  -requests
  -feedparser
  -pandas
  -smtplib
  -email
- APIs :
  - ANSSI CERT-FR
  - MITRE CVE
  - FIRST EPSS
- Accès Internet
- Un compte Gmail avec **mot de passe d’application**

## Structure
- le code pricipale qui fait la collecte,l'enrichissement et l'export en un fichier CSV
- le code pour l'envoi de mail qui fait un filtrage et un envoi des alertes par email
- cve_anssi_enriched.csv est un fichier généré contenant les CVE enrichies

## utilisation
Étape 1 : Collecte et enrichissement des CVE
Lancer le script de collecte :
Projet_python.py
Cela génère le fichier :
cve_anssi_enriched.csv

Étape 2 : Envoi des alertes email
Lancer le script d’alerte :
Envoi email.py

CONFIGURATION DES ALERTES
Les abonnés sont définis directement dans le script d’email :
email : adresse de réception
nom : nom de l’abonné
editeurs : liste des éditeurs à surveiller ou "all"
cvss_min : score CVSS minimum pour déclencher une alerte

Exemple :
editeurs = ["all"] → tous les éditeurs
cvss_min = 7.0 → vulnérabilités élevées et critiques

## AMÉLIORATIONS POSSIBLES

Fonctionement automatique 
Interface web ou tableau de bord
Support multi-utilisateurs
