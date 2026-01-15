# -*- coding: utf-8 -*-
"""
Created on Thu Jan 15 12:48:14 2026

@author: hp
"""

# -*- coding: utf-8 -*-
"""
Système d'alertes et notifications email pour les CVE critiques
Dernière mise à jour : Janvier 2026
"""

import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import json
import traceback
import sys

# =============================================================================
# CONFIGURATION EMAIL – À MODIFIER IMPÉRATIVEMENT
# =============================================================================

EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 465,                     # 465 avec SMTP_SSL (recommandé si 587 pose problème)
    "from_email": "greenfeatherp2ip@gmail.com",
    "password": "jyrf uday jfgm phem",       # ← REMPLACE PAR TON MOT DE PASSE D'APPLICATION (16 caractères sans espaces)
}

# Sécurité : on arrête tout de suite si mot de passe vide ou trop court
if not EMAIL_CONFIG["password"] or len(EMAIL_CONFIG["password"].replace(" ", "")) != 16:
    print("\n" + "="*70)
    print("ERREUR CRITIQUE : MOT DE PASSE D'APPLICATION MANQUANT OU INCORRECT")
    print("→ Va sur : https://myaccount.google.com/apppasswords")
    print("→ Génère un mot de passe pour 'Python SMTP'")
    print("→ Copie les 16 caractères SANS ESPACES")
    print("="*70 + "\n")
    sys.exit(1)

# Liste des destinataires
SUBSCRIBERS = [
    {
        "email": "rshidou79@gmail.com",
        "name": "Équipe Sécurité",
        "vendors": ["all"],
        "min_cvss": 7.0,
        "severity": ["Élevée", "Critique"],
    },
    # Ajoute d'autres profils ici si besoin
]

# =============================================================================
# ENVOI D'EMAIL – VERSION ROBUSTE AVEC BEAUCOUP DE LOGS
# =============================================================================

def send_email(to_email, to_name, subject, body_html, body_text=None):
    print(f"\n[EMAIL] → Envoi vers {to_name} <{to_email}> | Sujet: {subject}")
    
    msg = MIMEMultipart('alternative')
    msg['From'] = EMAIL_CONFIG["from_email"]
    msg['To'] = to_email
    msg['Subject'] = subject
    
    if body_text:
        msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
    msg.attach(MIMEText(body_html, 'html', 'utf-8'))
    
    try:
        print(f"[SMTP] Connexion SSL vers {EMAIL_CONFIG['smtp_server']}:{EMAIL_CONFIG['smtp_port']}")
        server = smtplib.SMTP_SSL(
            EMAIL_CONFIG["smtp_server"],
            EMAIL_CONFIG["smtp_port"],
            timeout=20
        )
        
        server.set_debuglevel(1)  # Change à 2 si tu veux TOUS les détails SMTP
        
        print("[SMTP] Connexion établie")
        
        print(f"[SMTP] Authentification : {EMAIL_CONFIG['from_email']}")
        server.login(EMAIL_CONFIG["from_email"], EMAIL_CONFIG["password"])
        print("[SMTP] Login OK")
        
        print("[SMTP] Envoi du message...")
        server.sendmail(EMAIL_CONFIG["from_email"], to_email, msg.as_string())
        print("[SMTP] Envoi réussi")
        
        server.quit()
        print(f"[EMAIL] ✓ Email envoyé avec succès à {to_name}")
        return True
        
    except smtplib.SMTPAuthenticationError:
        print("✗ ÉCHEC AUTHENTIFICATION → Mot de passe d'application incorrect ou expiré")
        print("→ Vérifie / régénère ici : https://myaccount.google.com/apppasswords")
        return False
        
    except smtplib.SMTPException as e:
        print(f"✗ Erreur SMTP : {type(e).__name__}")
        print(f"  → {str(e)}")
        traceback.print_exc()
        return False
        
    except Exception as e:
        print(f"✗ Erreur inattendue : {type(e).__name__}")
        traceback.print_exc()
        return False


# =============================================================================
# FILTRAGE DES CVE
# =============================================================================

def filter_cves_for_subscriber(df, subscriber):
    df_filtered = df.copy()
    
    # Filtre par vendor
    if "all" not in [v.lower() for v in subscriber["vendors"]]:
        vendor_pattern = "|".join(subscriber["vendors"])
        df_filtered = df_filtered[
            df_filtered["Éditeur/Vendor"].str.contains(vendor_pattern, case=False, na=False)
        ]
    
    # Score CVSS minimum
    df_filtered = df_filtered[df_filtered["Score CVSS"] >= subscriber["min_cvss"]]
    
    # Sévérité (insensible à la casse)
    df_filtered = df_filtered[
        df_filtered["Base Severity"].str.lower().isin([s.lower() for s in subscriber["severity"]])
    ]
    
    return df_filtered


# =============================================================================
# GÉNÉRATION DES CORPS D'EMAIL (HTML + TEXTE)
# =============================================================================

def generate_email_body_html(df_alerts, subscriber_name):
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .header {{ background-color: #d32f2f; color: white; padding: 20px; text-align: center; }}
            .content {{ padding: 20px; }}
            .alert-box {{ border: 2px solid #d32f2f; margin: 15px 0; padding: 15px; border-radius: 5px; background-color: #fff3f3; }}
            .alert-critical {{ border-color: #d32f2f; background-color: #ffebee; }}
            .alert-high {{ border-color: #f57c00; background-color: #fff3e0; }}
            .cve-title {{ font-size: 18px; font-weight: bold; color: #d32f2f; }}
            .label {{ font-weight: bold; color: #555; }}
            .footer {{ margin-top: 30px; padding: 15px; background-color: #f5f5f5; text-align: center; font-size: 12px; color: #666; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🚨 Alerte CVE Critique</h1>
            <p>Rapport pour {subscriber_name}</p>
        </div>
        <div class="content">
            <p>Bonjour {subscriber_name},</p>
            <p><strong>{len(df_alerts)}</strong> vulnérabilité(s) correspondant à vos critères détectée(s).</p>
            <hr>
    """
    
    for _, row in df_alerts.iterrows():
        severity_class = "alert-critical" if row["Base Severity"] == "Critique" else "alert-high"
        html += f"""
        <div class="alert-box {severity_class}">
            <div class="cve-title">{row["Identifiant CVE"]}</div>
            <p><span class="label">Sévérité :</span> {row["Base Severity"]} (CVSS : {row["Score CVSS"]})</p>
            <p><span class="label">Éditeur :</span> {row["Éditeur/Vendor"]}</p>
            <p><span class="label">Produit :</span> {row["Produit"]}</p>
            <p><span class="label">Description :</span><br>{row["Description"][:300]}...</p>
            <p><a href="{row['Lien du bulletin (ANSSI)']}">Voir le bulletin ANSSI</a></p>
        </div>
        """
    
    html += """
            <hr>
            <p><strong>Recommandations :</strong> Appliquez les correctifs rapidement.</p>
        </div>
        <div class="footer">
            <p>Généré le {}</p>
        </div>
    </body>
    </html>
    """.format(datetime.now().strftime("%d/%m/%Y à %H:%M"))
    
    return html


def generate_email_body_text(df_alerts, subscriber_name):
    text = f"""
ALERTE CVE - {datetime.now().strftime("%d/%m/%Y")}

Bonjour {subscriber_name},

{len(df_alerts)} vulnérabilité(s) détectée(s) selon vos critères.

"""
    for _, row in df_alerts.iterrows():
        text += f"""
----------------------------------------
CVE : {row["Identifiant CVE"]}
Sévérité : {row["Base Severity"]} (CVSS {row["Score CVSS"]})
Éditeur : {row["Éditeur/Vendor"]}
Produit : {row["Produit"]}
Description : {row["Description"][:200]}...
Lien ANSSI : {row["Lien du bulletin (ANSSI)"]}
----------------------------------------
"""
    
    text += """
Recommandations :
- Vérifiez vos systèmes
- Appliquez les patches
- Consultez les bulletins ANSSI

Généré le {}
""".format(datetime.now().strftime("%d/%m/%Y %H:%M"))
    return text


# =============================================================================
# FONCTION PRINCIPALE
# =============================================================================

def generate_and_send_alerts(csv_file):
    print("\n" + "="*70)
    print("DÉMARRAGE SYSTÈME D'ALERTES CVE")
    print("="*70)
    
    try:
        df = pd.read_csv(csv_file, sep=";", encoding="utf-8-sig")
        print(f"→ {len(df)} lignes chargées depuis {csv_file}")
    except Exception as e:
        print(f"Erreur lecture CSV : {e}")
        return
    
    total_sent = 0
    
    for subscriber in SUBSCRIBERS:
        print(f"\n→ Traitement {subscriber['name']} ({subscriber['email']})")
        
        df_alerts = filter_cves_for_subscriber(df, subscriber)
        
        if len(df_alerts) == 0:
            print("  → Aucune vulnérabilité correspondante")
            continue
        
        print(f"  → {len(df_alerts)} alerte(s) trouvée(s)")
        df_top = df_alerts.nlargest(10, "Score CVSS")
        
        subject = f"🚨 {len(df_alerts)} Alerte(s) CVE - {datetime.now().strftime('%d/%m/%Y')}"
        html_body = generate_email_body_html(df_top, subscriber["name"])
        text_body = generate_email_body_text(df_top, subscriber["name"])
        
        success = send_email(
            subscriber["email"],
            subscriber["name"],
            subject,
            html_body,
            text_body
        )
        
        if success:
            total_sent += 1
    
    print("\n" + "="*70)
    print(f"RÉSUMÉ : {total_sent}/{len(SUBSCRIBERS)} email(s) envoyé(s)")
    print("="*70)


# =============================================================================
# LANCEMENT
# =============================================================================

if __name__ == "__main__":
    csv_file = "cve_anssi_enriched.csv"
    
    print("=== MODE DEBUG / TEST ===")
    print("Pour envoyer les vrais emails → décommente la ligne ci-dessous\n")
    
    # Pour tester la connexion seule (décommente si besoin)
    # send_email("rshidou79@gmail.com", "Test utilisateur", "Test connexion SMTP", "<p>Ceci est un test</p>", "Test texte")
    
    # Pour lancer le vrai traitement :
    generate_and_send_alerts(csv_file)
    
    # Par défaut : on affiche juste les infos pour debug
    print("Fichier CSV attendu :", csv_file)
    print("Nombre d'abonnés :", len(SUBSCRIBERS))
    print("Port SMTP configuré :", EMAIL_CONFIG["smtp_port"])
    print("Prêt à tester ? Décommente generate_and_send_alerts()")
