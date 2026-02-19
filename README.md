# 📊 Analyseur de Résultats de Performance WAF/IPS

Ce projet contient les scripts d'extraction et de visualisation des résultats pour un projet de recherche portant sur les performances des systèmes **IPS (Intrusion Prevention System)** et **WAF (Web Application Firewall)**.

Il permet de transformer des journaux de tests bruts (CPU, débit, latence) en graphiques clairs et en rapports HTML détaillés.

---

## 🚀 Fonctionnalités

- **Extraction Automatisée** : Parcourt une structure de dossiers complexe pour extraire les données de `wrk` et `mpstat`.
- **Analyse Multi-Scénarios** : Compare différents montages réseau (avec/sans IPS, avec/sans WAF, proxy seul, etc.).
- **Visualisation Graphique** : Génère des graphiques PNG pour l'utilisation CPU, le débit (throughput) et la latence (P50/P90).
- **Rapport HTML Professionnel** : Produit un rapport web complet incluant une légende descriptive et tous les graphiques.
- **Export CSV** : Génère un fichier `summary_results.csv` pour des analyses ultérieures (Excel, R, etc.).

---

## 📂 Structure du Projet

- `analyze_results_report.py` : Script principal générant le rapport HTML et les graphiques améliorés.
- `analyze_results.py` : Script de base pour l'extraction et le traçage rapide.
- `analysis_output/` : Contient les résultats générés (Rapport HTML, images, CSV).
- `INJ_*/` : Dossiers de données brutes classés par scénario d'injection.
- `RESULTS.pdf` : Document de synthèse des résultats du projet de recherche.

---

## 🛠️ Installation

Le script nécessite Python 3 et les dépendances suivantes :

```bash
pip install pandas matplotlib
```

---

## 📖 Utilisation

Pour lancer l'analyse complète et générer le rapport :

```bash
python analyze_results_report.py .
```

Les résultats seront créés ou mis à jour dans le dossier `analysis_output/`.

---

## 📋 Scénarios Analysés

| Scénario                 | Description                                                     |
| :----------------------- | :-------------------------------------------------------------- |
| **INJ_IPS_WAF_WEB**      | Injecteur → IPS (Suricata) → WAF (Apache+ModSecurity) → Backend |
| **INJ_IPS_WEB_NO_PROXY** | Injecteur → IPS → Backend (connexion directe)                   |
| **INJ_WAF_WEB**          | Injecteur → WAF → Backend (IPS inactif)                         |
| **INJ_WEB**              | Baseline : Injecteur → Backend (direct)                         |
| **INJ_WEB_PROXY**        | Injecteur → Proxy seul (WAF sans ModSecurity) → Backend         |

---

## 🧪 Contexte de Recherche

Ce générateur de courbes a été conçu pour aider à visualiser l'overhead introduit par les couches de sécurité (IPS et WAF) dans des architectures web haute performance. Il permet d'identifier précisément quel composant devient un goulot d'étranglement selon le niveau de concurrence (concurrency).

---

_Projet développé dans le cadre d'un travail de recherche sur la sécurité des réseaux._
