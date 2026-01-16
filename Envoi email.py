# -*- coding: utf-8 -*-
"""
Created on Fri Jan 16 06:05:49 2026

@author: hp
"""
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

#%% CONFIGURATION

EMAIL = "greenfeatherp2ip@gmail.com"
PASSWORD = "jyrf uday jfgm phem"
ABONNES = [{"email": "rshidou79@gmail.com","nom": "Sécurité","editeurs": ["all"],"cvss_min": 7.0}]

#%% FONCTIONS

def envoyer_email(destinataire, sujet, message):

    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL
        msg['To'] = destinataire
        msg['Subject'] = sujet
        msg.attach(MIMEText(message, 'plain', 'utf-8'))
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(EMAIL, PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"Email envoyé à {destinataire}")
        return True
    except Exception:
        print("Erreur")
        return False


def filtrer_cves(df, editeurs, cvss_min):
    df_filtre = df.copy()
    if "all" not in editeurs:
        pattern = "|".join(editeurs)
        df_filtre = df_filtre[
            df_filtre["Éditeur/Vendor"].str.contains(pattern, case=False, na=False)
        ]
    df_filtre = df_filtre[df_filtre["Score CVSS"] >= cvss_min]
    return df_filtre


def creer_message(df_alertes, nom):
    message = f"""
ALERTE CVE CRITIQUE
Bonjour {nom},

{len(df_alertes)} vulnérabilité(s) critique(s) détectée(s):

"""
    
    for idx, row in df_alertes.head(10).iterrows():
        message += f"""

CVE: {row["Identifiant CVE"]}
Sévérité: {row["Base Severity"]} (Score CVSS: {row["Score CVSS"]})
Éditeur: {row["Éditeur/Vendor"]}
Produit: {row["Produit"]}
Versions: {row["Versions affectées"]}

Description: {str(row["Description"])[:200]}...

Bulletin ANSSI: {row["Titre du bulletin (ANSSI)"]}
Lien: {row['Lien du bulletin (ANSSI)']}


"""
    
    message += """
RECOMMANDATIONS:
- Vérifiez si vos systèmes sont affectés
- Appliquez les correctifs rapidement
- Consultez les bulletins ANSSI

Cordialement,
Système d'alerte CVE
"""
    
    return message


def generer_alertes(fichier_csv):
    df = pd.read_csv(fichier_csv, sep=";")
    print(f"Données chargées: {len(df)} lignes\n")
    for abonne in ABONNES:
        print(f"Traitement de {abonne['nom']}...")
        df_alertes = filtrer_cves(df, abonne['editeurs'], abonne['cvss_min'])
        if len(df_alertes) == 0:
            print(f"  Aucune alerte pour {abonne['nom']}\n")
            continue
        print(f"  {len(df_alertes)} vulnérabilité(s) trouvée(s)")
        sujet = f" {len(df_alertes)} Alerte(s) CVE Critique(s)"
        message = creer_message(df_alertes, abonne['nom'])
        envoyer_email(abonne['email'], sujet, message)
        print()

#%% EXECUTION
if __name__ == "__main__":
    fichier = "cve_anssi_enriched.csv"
    generer_alertes(fichier)