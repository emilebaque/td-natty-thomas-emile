@author: hp
"""

import requests 
import re
import feedparser
import time
import pandas as pd

#%% etape 1

url="https://cert.ssi.gouv.fr/avis/feed/"
url1="https://cert.ssi.gouv.fr/alerte/feed/"
rss_feed_avis=feedparser.parse(url)
rss_feed_alertes=feedparser.parse(url1)
cves_link=[]
# for entry in rss_feed_avis.entries:
#     print("Titre :", entry.title) 
#     print("Description:", entry.description) 
#     print("Lien :", entry.link) 
#     print("Date :", entry.published)
#     json_url = entry.link.rstrip("/") + "/json/"
#     print("JSON :", json_url)
#     try:
#         response = requests.get(json_url)
#         data = response.json()
#         if "cves" in data:
#             for cve in data["cves"]:
#                 cves_link.append(cve["name"])
                
#     except Exception as e:
#         print("erreur")
# for entry in rss_feed_alertes.entries:
#     print("Titre :", entry.title) 
#     print("Description:", entry.description) 
#     print("Lien :", entry.link) 
#     print("Date :", entry.published)
#     time.sleep(2)


#%% etape 2

def extraction(feed,cves_link):
    
    for entry in feed.entries:
        time.sleep(2)
        json_url = entry.link.rstrip("/") + "/json/"
        try:
            response = requests.get(json_url)
            data = response.json()
            if "cves" in data:
                for cve in data["cves"]:
                    cves_link.append(cve["name"])
                    time.sleep(2)
                    
        except Exception as e:
            print("erreur")
        
            
extraction(rss_feed_avis, cves_link)
extraction(rss_feed_alertes, cves_link)
cves_link=list(set(cves_link))
df=pd.DataFrame(cves_link,columns=["CVE"])
print(df)

#%% etape 3
def enrichissement(cve_id):
    url=f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return {
                "description": None,
                "cvss_score": None,
                "cwe_id": None,
                "cwe_desc": None,
            }
        data = r.json()
        
        cna = data.get("containers", {}).get("cna", {})

        
        description = None
        for d in cna.get("descriptions", []):
            if d.get("lang") in (None, "en", "fr"):
                description = d.get("value")
                break

        
        cvss_score = None
        metrics = cna.get("metrics", [])
        if metrics:
            m = metrics[0]
            for key in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if key in m and "baseScore" in m[key]:
                    cvss_score = m[key]["baseScore"]
                    break

        # CWE
        cwe_id = None
        cwe_desc = None
        problem_types = cna.get("problemTypes", [])
        if problem_types and "descriptions" in problem_types[0]:
            desc0 = problem_types[0]["descriptions"][0]
            cwe_id = desc0.get("cweId")
            cwe_desc = desc0.get("description")

        return {
            "description": description,
            "cvss_score": cvss_score,
            "cwe_id": cwe_id,
            "cwe_desc": cwe_desc,
        }

    except Exception:
        return {
            "description": None,
            "cvss_score": None,
            "cwe_id": None,
            "cwe_desc": None,
        }

def get_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        results = data.get("data", [])
        if not results:
            return None
        return float(results[0].get("epss"))
    except Exception:
        return None


def cvss_severity(score):
    """
    Retourne le niveau de gravité CVSS en fonction du score.
    0-3   : Faible
    4-6   : Moyenne
    7-8   : Élevée
    9-10  : Critique
    """
    if score is None:
        return "Inconnu"
    try:
        s = float(score)
    except ValueError:
        return "Invalide"

    if 0 <= s <= 3:
        return "Faible"
    elif 4 <= s <= 6:
        return "Moyenne"
    elif 7 <= s <= 8:
        return "Élevée"
    elif 9 <= s <= 10:
        return "Critique"
    else:
        return "Hors échelle"

details_list = []
for cve_id in df["CVE"]:
    info = enrichissement(cve_id)
    epss = get_epss_score(cve_id)
    info["CVE"] = cve_id
    info["epss"] = epss
    details_list.append(info)
    time.sleep(0.2)

enriched_df = pd.DataFrame(details_list, columns=["CVE", "description", "cvss_score", "cwe_id", "cwe_desc", "epss"])
enriched_df["cvss_severity"] = enriched_df["cvss_score"].apply(cvss_severity)
enriched_df = pd.DataFrame(details_list, columns=["CVE", "description", "cvss_score", "cwe_id", "cwe_desc", "epss"])
print(enriched_df.head())
