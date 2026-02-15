#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_results_report.py

But
----
Ce script parcourt une arborescence de résultats d'expériences de performance
(organisation utilisée : dossiers INJ_* contenant des sous-dossiers run X),
extrait les métriques importantes (AVG CPU busy/idle pour IPS & WAF, débit
Requests/sec issu de wrk, percentiles de latence p50/p75/p90/p99) et génère :
  - un CSV résumé (analysis_output/summary_results.csv)
  - plusieurs graphiques PNG (cpu, throughput, latency, combined)
  - un rapport HTML (analysis_output/report.html) contenant une légende
    descriptive des scénarios et les graphiques.

Contexte expérimental
---------------------
Tu utilises cette structure pour comparer différents scénarios réseau :
  - INJ_IPS_WAF_WEB : Injector → IPS (Suricata) → WAF (Apache+ModSecurity) → Backend
  - INJ_IPS_WEB_NO_PROXY : Injector → IPS → Backend (pas de proxy)
  - INJ_WAF_WEB : Injector → WAF → Backend (IPS inactif)
  - etc.

Pourquoi ce script est important
--------------------------------
1. Centralise et normalise l'extraction des métriques à partir de fichiers texte
   produits par tes expériences (fichiers AVG_CPU_*.txt et wrk_*.txt).
2. Produit des graphiques lisibles et comparables sur une seule figure pour
   faciliter l'analyse : overhead CPU, throughput et latence.
3. Ajoute une "légende" automatique expliquant chaque scénario pour le rapport,
   utile pour partager les résultats.
4. Affiche les valeurs exactes au-dessus des barres pour permettre une lecture
   rapide sans devoir ouvrir les fichiers sources.

Usage
-----
  python3 analyze_results_report.py /chemin/vers/le/dossier_racine
Le fichier de sortie (report.html + images + summary_results.csv) sera créé dans
/chemin/vers/le/dossier_racine/analysis_output/

Dépendances Python
------------------
  - pandas
  - matplotlib

Installe-les si besoin :
  sudo apt install -y python3-pip
  pip3 install pandas matplotlib

Notes sur l'interprétation
--------------------------
- "AVG busy (all cpus)" : estimation du pourcentage moyen de CPU occupé
  pendant la période de mesure (calculé à partir de mpstat: busy = 100 - avg idle).
  Exemple de format extrait : "AVG busy (all cpus) = 22.51 % (avg idle=77.49%) over 2010 samples"
- "Requests/sec" : débit mesuré par wrk (valeur agrégée)
- Latences p50/p90 : valeurs en millisecondes utilisées pour les graphiques.

Structure attendue (exemple)
---------------------------
root/
  INJ_IPS_WAF_WEB/
    run 1/
      AVG_CPU_ips_500.txt
      AVG_CPU_waf_500.txt
      wrk_via_waf_c500_t4_200s_run1.txt
    run 2/ ...
  INJ_WEB/ ...
  ...

Le script tolère des variations raisonnables de noms de fichiers (il cherche
les patterns habituels : 'AVG_CPU_ips', 'AVG_CPU_waf', présence d'un fichier wrk).

--------------------------------------------------------------------------------
"""

import sys
import re
from pathlib import Path
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from datetime import datetime

# Configuration des couleurs et styles pour améliorer la lisibilité
plt.rcParams.update({
    'font.size': 10,
    'axes.titlesize': 12,
    'axes.labelsize': 11,
    'xtick.labelsize': 8,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.titlesize': 14
})

# Palette de couleurs distinctes et contrastées
COLORS = {
    'ips': '#2E86AB',      # Bleu moyen pour IPS
    'waf': '#A23B72',      # Violet pour WAF
    'throughput': '#F18F01', # Orange pour throughput
    'p50': '#C73E1D',      # Rouge pour p50
    'p90': '#592E83',      # Violet foncé pour p90
    'background': '#F8F9FA', # Gris très clair pour background
    'grid': '#E9ECEF'      # Gris clair pour grid
}

# -----------------------
# Description des scénarios (FR)
# -----------------------
SCENARIO_DESCRIPTIONS = {
    "INJ_IPS_WAF_WEB": "Injector → IPS (Suricata) actif → WAF (proxy Apache avec ModSecurity) actif → Backend web. Test complet avec IDS/IPS et WAF inline.",
    "INJ_IPS_WEB_NO_PROXY": "Injector → IPS actif → connexion directe vers le Backend (pas de proxy WAF). Permet mesurer l'impact de l'IPS seul.",
    "INJ_IPS_WEB_PROXY": "Injector → IPS actif → WAF machine en mode proxy (sans ModSecurity activé) → Backend. Mesure l'overhead du proxy seul avec IPS.",
    "INJ_NFQ_WAF_WEB": "Injector → NFQUEUE présent mais Suricata pas en mode bloquant (ou acceptant) → WAF actif → Backend. Test du cas où NFQUEUE est installé mais trafic accepté.",
    "INJ_WAF_WEB": "Injector → Pas d'IPS → WAF (proxy + ModSecurity) actif → Backend. Mesure l'impact du WAF seul.",
    "INJ_WEB": "Injector → Pas d'IPS → Pas de proxy (accès direct au Backend). Mesures baseline sans WAF ni proxy ni IPS.",
    "INJ_WEB_PROXY": "Injector → Pas d'IPS → Proxy (WAF machine en tant que reverse-proxy, ModSecurity désactivé) → Backend. Test proxy sans fonctionnalités WAF.",
    "NO INJECTION": "Tests sans trafic d'injection (contrôles ou mesures à vide).",
}

def describe_scenario(name):
    """Génère une description automatique pour les scénarios non documentés"""
    if name in SCENARIO_DESCRIPTIONS:
        return SCENARIO_DESCRIPTIONS[name]
    parts = name.split('_')
    desc = []
    if 'INJ' in parts or name.startswith('INJ'):
        desc.append("Injection depuis Injector")
    if 'IPS' in parts:
        desc.append("IPS (Suricata) actif")
    if 'NFQ' in parts:
        desc.append("NFQUEUE présent")
    if 'WAF' in parts:
        desc.append("WAF (proxy / ModSecurity) actif")
    if 'WEB' in parts or 'BACKEND' in parts:
        desc.append("Backend web présent")
    if 'PROXY' in parts or 'NO_PROXY' in parts or 'NO' in parts:
        if 'NO' in parts or 'NO_PROXY' in parts:
            desc.append("accès direct au backend (pas de proxy)")
        else:
            desc.append("reverse-proxy en place")
    if not desc:
        return "Scénario non documenté — nom brut: {}".format(name)
    return " — ".join(desc)

# -----------------------
# Parsers pour fichiers (inchangés)
# -----------------------
def parse_avg_cpu_file(path):
    """Parse les fichiers AVG_CPU_*.txt pour extraire les métriques CPU"""
    text = Path(path).read_text(errors='ignore')
    m = re.search(r"AVG busy.*=\s*([0-9]+(?:\.[0-9]+)?)\s*%.*avg idle\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*%.*over\s*([0-9]+)\s*samples", text, re.IGNORECASE | re.DOTALL)
    if m:
        return {'busy': float(m.group(1)), 'idle': float(m.group(2)), 'samples': int(m.group(3))}
    m2 = re.search(r"AVG busy.*=\s*([0-9]+(?:\.[0-9]+)?)\s*%.*over\s*([0-9]+)\s*samples", text, re.IGNORECASE)
    if m2:
        return {'busy': float(m2.group(1)), 'idle': None, 'samples': int(m2.group(2))}
    m3 = re.search(r"AVG busy.*=\s*([0-9]+(?:\.[0-9]+)?)\s*%", text, re.IGNORECASE)
    if m3:
        return {'busy': float(m3.group(1)), 'idle': None, 'samples': None}
    m4 = re.search(r"avg idle\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*%", text, re.IGNORECASE)
    if m4:
        idle = float(m4.group(1))
        busy = round(100.0 - idle, 2)
        return {'busy': busy, 'idle': idle, 'samples': None}
    return None

def convert_to_seconds(val_str):
    """Convertit les valeurs de latence en secondes"""
    if val_str is None:
        return None
    s = val_str.strip().lower()
    m = re.match(r"([0-9]+(?:\.[0-9]+)?)\s*(ms|s|us)?", s)
    if not m:
        try:
            return float(s)
        except:
            return None
    val = float(m.group(1)); unit = (m.group(2) or 's')
    if unit == 'ms':
        return val/1000.0
    if unit == 'us':
        return val/1_000_000.0
    return val

def parse_wrk_file(path):
    """Parse les fichiers wrk pour extraire les métriques de performance"""
    text = Path(path).read_text(errors='ignore')
    res = {'requests_per_sec': None, 'p50': None, 'p75': None, 'p90': None, 'p99': None, 'socket_errors': None, 'transfer_per_sec': None}
    m = re.search(r"Requests/sec:\s*([0-9]+(?:\.[0-9]+)?)", text)
    if m:
        res['requests_per_sec'] = float(m.group(1))
    m2 = re.search(r"Transfer/sec:\s*([0-9]+(?:\.[0-9]+)?)(\w+)?", text)
    if m2:
        val = float(m2.group(1)); unit = (m2.group(2) or '').lower()
        if unit in ('kb','k'):
            res['transfer_per_sec'] = val
        elif unit in ('mb','m'):
            res['transfer_per_sec'] = val*1024.0
        else:
            res['transfer_per_sec'] = val
    # percentiles: try multiple patterns
    for perc in ('50','75','90','99'):
        mm = re.search(r"^\s*"+perc+r"%\s+([0-9]+(?:\.[0-9]+)?\s*(?:ms|s|us)?)", text, re.MULTILINE | re.IGNORECASE)
        if mm:
            res['p'+perc] = convert_to_seconds(mm.group(1))
    # fallback for the inline percentiles block
    inline = re.search(r"50%[^\d]*([0-9]+(?:\.[0-9]+)?\s*(?:ms|s|us)?)[^\n]*75%[^\d]*([0-9]+(?:\.[0-9]+)?\s*(?:ms|s|us)?)[^\n]*90%[^\d]*([0-9]+(?:\.[0-9]+)?\s*(?:ms|s|us)?)", text, re.IGNORECASE)
    if inline:
        res['p50'] = convert_to_seconds(inline.group(1)); res['p75'] = convert_to_seconds(inline.group(2)); res['p90'] = convert_to_seconds(inline.group(3))
    m_err = re.search(r"Socket errors:\s*([^\n]+)", text)
    if m_err:
        res['socket_errors'] = m_err.group(1).strip()
    return res

# -----------------------
# Collect results + add description (inchangé)
# -----------------------
def collect_results(root_path):
    """Collecte tous les résultats depuis l'arborescence de fichiers"""
    root = Path(root_path)
    rows = []
    missing = []
    for scenario_dir in sorted(root.iterdir()):
        if not scenario_dir.is_dir():
            continue
        scenario = scenario_dir.name
        scenario_desc = SCENARIO_DESCRIPTIONS.get(scenario, describe_scenario(scenario))
        for run_dir in sorted(scenario_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            runname = run_dir.name
            files = list(run_dir.iterdir())
            wrk = None
            for f in files:
                if f.is_file() and 'wrk' in f.name.lower():
                    wrk = f; break
            avg_ips = None; avg_waf = None
            for f in files:
                n = f.name.lower()
                if 'avg_cpu_ips' in n or 'summary_ips' in n:
                    avg_ips = f
                if 'avg_cpu_waf' in n or 'summary_waf' in n:
                    avg_waf = f
            concurrency = None
            for f in files:
                m = re.search(r'(?<!\d)(\d{2,5})(?!\d)', f.name)
                if m:
                    num = int(m.group(1))
                    if num in (50,100,200,300,500,1000,2000) or num > 100:
                        concurrency = num; break
            if concurrency is None and wrk:
                m = re.search(r'c(\d+)', wrk.name)
                if m:
                    concurrency = int(m.group(1))
            data = dict(
                scenario=scenario, scenario_desc=scenario_desc, run=runname, concurrency=concurrency, path=str(run_dir),
                avg_busy_ips=None, avg_idle_ips=None, samples_ips=None,
                avg_busy_waf=None, avg_idle_waf=None, samples_waf=None,
                requests_per_sec=None, p50=None, p75=None, p90=None, p99=None,
                socket_errors=None, transfer_per_sec=None, wrk_file=(str(wrk) if wrk else None)
            )
            if avg_ips and avg_ips.exists():
                p = parse_avg_cpu_file(avg_ips)
                if p:
                    data['avg_busy_ips'] = p.get('busy'); data['avg_idle_ips'] = p.get('idle'); data['samples_ips'] = p.get('samples')
                else:
                    missing.append(str(avg_ips))
            else:
                missing.append(f"{run_dir}/AVG_CPU_ips_*.txt")
            if avg_waf and avg_waf.exists():
                p = parse_avg_cpu_file(avg_waf)
                if p:
                    data['avg_busy_waf'] = p.get('busy'); data['avg_idle_waf'] = p.get('idle'); data['samples_waf'] = p.get('samples')
                else:
                    missing.append(str(avg_waf))
            else:
                missing.append(f"{run_dir}/AVG_CPU_waf_*.txt")
            if wrk and wrk.exists():
                w = parse_wrk_file(wrk)
                data['requests_per_sec'] = w.get('requests_per_sec'); data['p50'] = w.get('p50'); data['p75'] = w.get('p75'); data['p90'] = w.get('p90'); data['p99'] = w.get('p99'); data['socket_errors'] = w.get('socket_errors'); data['transfer_per_sec'] = w.get('transfer_per_sec')
            else:
                missing.append(f"{run_dir}/*wrk*.txt")
            rows.append(data)
    df = pd.DataFrame(rows)
    return df, missing

def custom_order(df):
    # NO INJECTION en premier
    noinj = df[df['scenario'] == 'NO INJECTION']
    # puis c300, c500, c1000 (hors NO INJECTION)
    c300 = df[(df['concurrency'] == 300) & (df['scenario'] != 'NO INJECTION')]
    c500 = df[(df['concurrency'] == 500) & (df['scenario'] != 'NO INJECTION')]
    c1000 = df[(df['concurrency'] == 1000) & (df['scenario'] != 'NO INJECTION')]
    # autres configs (s'il y en a)
    rest = df[~df.index.isin(noinj.index.tolist() + c300.index.tolist() + c500.index.tolist() + c1000.index.tolist())]
    # concatène dans l'ordre
    ordered = pd.concat([noinj, c300, c500, c1000, rest], axis=0)
    return ordered

# -----------------------
# Plot helpers AMÉLIORÉS (avec annotations intelligentes)
# -----------------------
def save_plot(fig, out_path):
    """Sauvegarde le graphique avec une qualité optimisée"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=300, bbox_inches='tight', facecolor='white', edgecolor='none')
    plt.close(fig)
    return out_path

def smart_annotate_bars(ax, bars, fmt="{:.1f}", units="", rotation_angle=0):
    """
    Ajoute les valeurs au-dessus des barres avec gestion intelligente des superpositions.
    
    Args:
        ax: Axes matplotlib
        bars: BarContainer résultat de ax.bar()
        fmt: Format string pour les valeurs
        units: Suffixe d'unités
        rotation_angle: Angle de rotation du texte (0, 45, 90)
    """
    if not bars:
        return
        
    # Calculer les positions et hauteurs
    positions = []
    heights = []
    for bar in bars:
        if bar.get_height() > 0:  # Ignorer les barres de hauteur 0
            x = bar.get_x() + bar.get_width() / 2
            h = bar.get_height()
            positions.append((x, h))
            heights.append(h)
    
    if not heights:
        return
        
    max_height = max(heights)
    min_height = min(heights)
    height_range = max_height - min_height
    
    # Ajustement dynamique de l'offset basé sur la plage de valeurs
    base_offset = max_height * 0.03  # 3% de la hauteur max comme base
    
    # Pour éviter les superpositions, grouper les barres par hauteurs similaires
    text_positions = []
    
    for i, (x, h) in enumerate(positions):
        # Calculer l'offset adaptatif
        if height_range > 0:
            relative_height = (h - min_height) / height_range
            offset = base_offset * (1 + relative_height * 0.5)  # Offset plus grand pour les barres hautes
        else:
            offset = base_offset
            
        y_text = h + offset
        
        # Vérifier les conflits avec les textes déjà placés
        conflict_count = 0
        for prev_x, prev_y in text_positions:
            if abs(x - prev_x) < max_height * 0.1 and abs(y_text - prev_y) < max_height * 0.05:
                conflict_count += 1
        
        # Ajuster la position si conflit
        if conflict_count > 0:
            y_text += conflict_count * base_offset * 0.5
            
        text_positions.append((x, y_text))
        
        # Formatage intelligent de la valeur
        if abs(h) >= 1000:
            label = f"{h:.0f}{units}"
        elif abs(h) >= 100:
            label = f"{h:.0f}{units}"
        elif abs(h) >= 1:
            label = f"{h:.1f}{units}"
        else:
            label = f"{h:.2f}{units}"
            
        # Taille de police adaptative
        fontsize = max(7, min(10, 120 // len(positions)))  # Entre 7 et 10, dépendant du nombre de barres
        
        ax.text(x, y_text, label, 
               ha='center', va='bottom', 
               fontsize=fontsize, 
               rotation=rotation_angle,
               bbox=dict(boxstyle="round,pad=0.2", facecolor='white', alpha=0.8, edgecolor='none') if rotation_angle != 0 else None)

def create_readable_labels(df):
    """Crée des labels lisibles pour l'axe X avec gestion intelligente de la longueur"""
    labels = []
    for _, row in df.iterrows():
        scenario = row['scenario']
        concurrency = row['concurrency']
        
        # Abréviations intelligentes pour les scénarios longs
        scenario_short = scenario
        if len(scenario) > 15:
            # Abréger les scénarios trop longs
            scenario_short = scenario.replace('INJ_', '').replace('_WEB', '').replace('_PROXY', '_P')
            if len(scenario_short) > 12:
                parts = scenario_short.split('_')
                scenario_short = '_'.join(p[:3] if len(p) > 3 else p for p in parts)
        
        conc_str = f"c{int(concurrency)}" if pd.notna(concurrency) else "NA"
        labels.append(f"{scenario_short}\n{conc_str}")
    
    return labels

def plot_cpu(df, outdir):
    """Génère le graphique CPU avec améliorations visuelles"""
    df2 = custom_order(df.copy())
    labels = create_readable_labels(df2)
    x = list(range(len(labels)))
    ips = df2['avg_busy_ips'].fillna(0).tolist()
    waf = df2['avg_busy_waf'].fillna(0).tolist()
    
    # Taille de figure adaptative
    fig_width = max(10, len(labels) * 0.8)
    fig, ax = plt.subplots(figsize=(fig_width, 6))
    
    width = 0.35
    bars_ips = ax.bar([i-width/2 for i in x], ips, width=width, 
                     label='IPS CPU busy (%)', color=COLORS['ips'], alpha=0.8)
    bars_waf = ax.bar([i+width/2 for i in x], waf, width=width, 
                     label='WAF CPU busy (%)', color=COLORS['waf'], alpha=0.8)
    
    # Configuration des axes
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    ax.set_ylabel('CPU busy (%)', fontweight='bold')
    ax.set_title('Utilisation CPU par composant et scénario', fontweight='bold', pad=20)
    
    # Grille améliorée
    ax.grid(axis='y', linestyle='--', alpha=0.3, color=COLORS['grid'])
    ax.set_facecolor(COLORS['background'])
    
    # Légende améliorée
    ax.legend(loc='upper left', frameon=True, fancybox=True, shadow=True)
    
    # Annotations avec gestion des superpositions
    smart_annotate_bars(ax, bars_ips, fmt="{:.1f}", units="%")
    smart_annotate_bars(ax, bars_waf, fmt="{:.1f}", units="%")
    
    # Ajustement des marges
    plt.tight_layout()
    
    return save_plot(fig, outdir / 'cpu_busy.png')

def plot_throughput(df, outdir):
    """Génère le graphique de débit avec améliorations visuelles"""
    df2 = custom_order(df.copy())
    labels = create_readable_labels(df2)
    x = list(range(len(labels)))
    thr = df2['requests_per_sec'].fillna(0).tolist()
    
    fig_width = max(10, len(labels) * 0.7)
    fig, ax = plt.subplots(figsize=(fig_width, 6))
    
    bars = ax.bar(x, thr, color=COLORS['throughput'], alpha=0.8, 
                  edgecolor='white', linewidth=1.2)
    
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    ax.set_ylabel('Requêtes par seconde', fontweight='bold')
    ax.set_title('Débit de traitement par scénario', fontweight='bold', pad=20)
    
    # Grille et fond
    ax.grid(axis='y', linestyle='--', alpha=0.3, color=COLORS['grid'])
    ax.set_facecolor(COLORS['background'])
    
    # Annotations
    smart_annotate_bars(ax, bars, fmt="{:.0f}", units=" req/s")
    
    plt.tight_layout()
    return save_plot(fig, outdir / 'throughput.png')

def plot_latency(df, outdir):
    """Génère le graphique de latence avec améliorations visuelles"""
    df2 = custom_order(df.copy())
    labels = create_readable_labels(df2)
    x = list(range(len(labels)))
    
    # Conversion en ms pour affichage
    p50 = df2['p50'].fillna(0).astype(float).tolist()
    p90 = df2['p90'].fillna(0).astype(float).tolist()
    p50_ms = [v*1000.0 for v in p50]
    p90_ms = [v*1000.0 for v in p90]
    
    fig_width = max(10, len(labels) * 0.8)
    fig, ax = plt.subplots(figsize=(fig_width, 6))
    
    width = 0.35
    bars50 = ax.bar([i-width/2 for i in x], p50_ms, width=width, 
                   label='Latence P50 (ms)', color=COLORS['p50'], alpha=0.8)
    bars90 = ax.bar([i+width/2 for i in x], p90_ms, width=width, 
                   label='Latence P90 (ms)', color=COLORS['p90'], alpha=0.8)
    
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    ax.set_ylabel('Latence (millisecondes)', fontweight='bold')
    ax.set_title('Latences par percentile et scénario', fontweight='bold', pad=20)
    
    # Grille et légende
    ax.grid(axis='y', linestyle='--', alpha=0.3, color=COLORS['grid'])
    ax.set_facecolor(COLORS['background'])
    ax.legend(loc='upper left', frameon=True, fancybox=True, shadow=True)
    
    # Annotations intelligentes
    smart_annotate_bars(ax, bars50, fmt="{:.1f}", units=" ms")
    smart_annotate_bars(ax, bars90, fmt="{:.1f}", units=" ms")
    
    plt.tight_layout()
    return save_plot(fig, outdir / 'latency_p50_p90.png')

def plot_combined(df, outdir):
    """Génère le graphique combiné avec layout amélioré"""
    df2 = custom_order(df.copy())
    labels = create_readable_labels(df2)
    x = list(range(len(labels)))
    
    # Figure plus large pour éviter l'encombrement
    fig, axs = plt.subplots(3, 1, figsize=(max(12, len(labels) * 0.8), 14))
    fig.suptitle('Analyse comparative complète des performances', fontsize=16, fontweight='bold', y=0.98)
    
    # Subplot 1: CPU
    ips_vals = df2['avg_busy_ips'].fillna(0).tolist()
    waf_vals = df2['avg_busy_waf'].fillna(0).tolist()
    bars_ips = axs[0].bar([i-0.2 for i in x], ips_vals, width=0.4, 
                         label='IPS CPU busy (%)', color=COLORS['ips'], alpha=0.8)
    bars_waf = axs[0].bar([i+0.2 for i in x], waf_vals, width=0.4, 
                         label='WAF CPU busy (%)', color=COLORS['waf'], alpha=0.8)
    
    axs[0].set_ylabel('CPU busy (%)', fontweight='bold')
    axs[0].set_title('A. Utilisation CPU par composant', fontweight='bold', loc='left', pad=10)
    axs[0].legend(loc='upper left', frameon=True, fancybox=True, shadow=True)
    axs[0].grid(axis='y', linestyle='--', alpha=0.3, color=COLORS['grid'])
    axs[0].set_facecolor(COLORS['background'])
    
    smart_annotate_bars(axs[0], bars_ips, fmt="{:.1f}", units="%")
    smart_annotate_bars(axs[0], bars_waf, fmt="{:.1f}", units="%")
    
    # Subplot 2: Throughput
    thr_vals = df2['requests_per_sec'].fillna(0).tolist()
    bars_thr = axs[1].bar(x, thr_vals, color=COLORS['throughput'], alpha=0.8, 
                         edgecolor='white', linewidth=1)
    
    axs[1].set_ylabel('Requêtes/seconde', fontweight='bold')
    axs[1].set_title('B. Débit de traitement', fontweight='bold', loc='left', pad=10)
    axs[1].grid(axis='y', linestyle='--', alpha=0.3, color=COLORS['grid'])
    axs[1].set_facecolor(COLORS['background'])
    
    smart_annotate_bars(axs[1], bars_thr, fmt="{:.0f}", units=" req/s")
    
    # Subplot 3: Latency
    p50_vals = df2['p50'].fillna(0).astype(float).tolist()
    p90_vals = df2['p90'].fillna(0).astype(float).tolist()
    p50_ms = [v*1000.0 for v in p50_vals]
    p90_ms = [v*1000.0 for v in p90_vals]
    
    bars_p50 = axs[2].bar([i-0.15 for i in x], p50_ms, width=0.3, 
                         label='P50 (ms)', color=COLORS['p50'], alpha=0.8)
    bars_p90 = axs[2].bar([i+0.15 for i in x], p90_ms, width=0.3, 
                         label='P90 (ms)', color=COLORS['p90'], alpha=0.8)
    
    axs[2].set_ylabel('Latence (ms)', fontweight='bold')
    axs[2].set_title('C. Latences par percentile', fontweight='bold', loc='left', pad=10)
    axs[2].legend(loc='upper left', frameon=True, fancybox=True, shadow=True)
    axs[2].grid(axis='y', linestyle='--', alpha=0.3, color=COLORS['grid'])
    axs[2].set_facecolor(COLORS['background'])
    
    smart_annotate_bars(axs[2], bars_p50, fmt="{:.1f}", units=" ms")
    smart_annotate_bars(axs[2], bars_p90, fmt="{:.1f}", units=" ms")
    
    # Configuration des axes X pour tous les subplots
    for i, ax in enumerate(axs):
        ax.set_xticks(x)
        if i == len(axs) - 1:  # Seulement le dernier subplot affiche les labels
            ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
        else:
            ax.set_xticklabels([])  # Masquer les labels intermédiaires
    
    plt.tight_layout()
    plt.subplots_adjust(top=0.94)  # Ajuster pour le titre principal
    
    return save_plot(fig, outdir / 'combined_summary.png')

# -----------------------
# HTML report generator (inchangé)
# -----------------------
def html_escape(s):
    """Échapper les caractères HTML"""
    return (s.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;') if s else '')

def generate_html_report(outdir, df, missing, images):
    """Génère le rapport HTML avec les graphiques et la légende"""
    outdir = Path(outdir)
    report_file = outdir / 'report.html'
    now = datetime.utcnow().isoformat() + 'Z'
    small_df = df.copy()
    for c in ['avg_busy_ips','avg_idle_ips','avg_busy_waf','avg_idle_waf','requests_per_sec','p50','p75','p90','p99','transfer_per_sec']:
        if c in small_df.columns:
            small_df[c] = small_df[c].apply(lambda v: round(v,3) if pd.notna(v) else v)
    table_html = small_df.to_html(index=False, classes='table', na_rep='', escape=False)

    scenarios_present = sorted(df['scenario'].unique()) if 'scenario' in df.columns else []
    legend_lines = []
    for s in scenarios_present:
        desc = SCENARIO_DESCRIPTIONS.get(s, describe_scenario(s))
        legend_lines.append(f"<tr><td><strong>{html_escape(s)}</strong></td><td>{html_escape(desc)}</td></tr>")
    legend_html = "<table class='table'><tr><th>Scénario</th><th>Description</th></tr>{}</table>".format("".join(legend_lines))

    html = f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Rapport d'analyse — WAF/IPS Performance</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:20px;color:#333;background-color:#f8f9fa}}
h1,h2{{color:#0b4d8a;border-bottom:2px solid #0b4d8a;padding-bottom:5px}}
h1{{font-size:28px}}h2{{font-size:20px}}
.table{{border-collapse:collapse;width:100%;background:white;box-shadow:0 2px 4px rgba(0,0,0,0.1)}}
.table th, .table td{{border:1px solid #dee2e6;padding:8px;font-size:11px}}
.table th{{background-color:#e9ecef;font-weight:bold;text-align:center}}
.imgbox{{margin:20px 0;padding:15px;border:1px solid #dee2e6;background:white;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}}
.imgbox h3{{margin-top:0;color:#495057}}
.imgbox img{{max-width:100%;height:auto;border:1px solid #dee2e6;border-radius:4px}}
.header{{background:linear-gradient(135deg,#0b4d8a,#2e86ab);color:white;padding:20px;border-radius:8px;margin-bottom:20px}}
.summary{{background:white;padding:15px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}}
pre{{background:#f8f9fa;padding:10px;border:1px solid #dee2e6;border-radius:4px;overflow-x:auto;font-size:11px}}
</style>
</head><body>

<div class="header">
<h1>📊 Rapport d'Analyse de Performance WAF/IPS</h1>
<p><strong>Généré le:</strong> {now} (UTC)</p>
<p><em>Analyse automatisée des métriques de performance pour différents scénarios d'architecture réseau</em></p>
</div>

<div class="summary">
<h2>🔍 Légende des scénarios testés</h2>
{legend_html}
</div>

<div class="summary">
<h2>📈 Résumé des métriques collectées</h2>
{table_html}
</div>

<h2>📊 Visualisations graphiques</h2>

<div class="imgbox">
<h3>💻 Utilisation CPU (IPS &amp; WAF)</h3>
<p><em>Pourcentage moyen d'utilisation CPU pendant les tests de charge</em></p>
<img src="./{images.get('cpu','cpu_busy.png')}" alt="Graphique CPU">
</div>

<div class="imgbox">
<h3>🚀 Débit de traitement (Requests/sec)</h3>
<p><em>Nombre de requêtes HTTP traitées par seconde (mesure wrk)</em></p>
<img src="./{images.get('throughput','throughput.png')}" alt="Graphique Throughput">
</div>

<div class="imgbox">
<h3>⏱️ Latences par percentile</h3>
<p><em>Temps de réponse P50 et P90 en millisecondes</em></p>
<img src="./{images.get('latency','latency_p50_p90.png')}" alt="Graphique Latence">
</div>

<div class="imgbox">
<h3>📋 Vue d'ensemble combinée</h3>
<p><em>Analyse comparative complète de tous les indicateurs</em></p>
<img src="./{images.get('combined','combined_summary.png')}" alt="Graphique Combiné">
</div>

<div class="summary">
<h2>⚠️ Détails techniques & fichiers manquants</h2>
<p><strong>Fichiers non trouvés ou non parsables:</strong></p>
<pre>{html_escape(chr(10).join(sorted(set(missing))[:50]))}</pre>
</div>

<div style="text-align:center;margin-top:30px;color:#6c757d;font-size:12px">
<p>Rapport généré automatiquement par analyze_results_report.py</p>
</div>

</body></html>
"""
    report_file.write_text(html, encoding='utf-8')
    print("✅ Rapport HTML généré:", report_file)
    return report_file

# -----------------------
# Main (inchangé)
# -----------------------
def main():
    parser = argparse.ArgumentParser(description='Analyser et générer rapport HTML (WAF/IPS tests) avec descriptions et graphiques améliorés.')
    parser.add_argument('root', help='dossier racine contenant les dossiers INJ_*')
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if not root.exists():
        print("❌ Erreur: dossier racine non trouvé:", root); sys.exit(1)

    outdir = root / 'analysis_output'
    outdir.mkdir(parents=True, exist_ok=True)
    print("🔍 Collecte des données depuis:", root)
    df, missing = collect_results(root)
    if df.empty:
        print("❌ Aucune donnée trouvée. Vérifie la structure des dossiers (INJ_*/run*)"); sys.exit(1)
    df['concurrency'] = pd.to_numeric(df['concurrency'], errors='coerce')

    csv_path = outdir / 'summary_results.csv'
    df.to_csv(csv_path, index=False)
    print("📄 Résumé CSV généré:", csv_path)

    images = {}
    try:
        print("🎨 Génération des graphiques...")
        images['cpu'] = Path(plot_cpu(df, outdir)).name
        images['throughput'] = Path(plot_throughput(df, outdir)).name
        images['latency'] = Path(plot_latency(df, outdir)).name
        images['combined'] = Path(plot_combined(df, outdir)).name
        print("✅ Graphiques générés avec succès")
    except Exception as e:
        print("❌ Erreur lors de la génération des graphiques:", e)
        import traceback
        traceback.print_exc()
    
    report = generate_html_report(outdir, df, missing, images)
    print("🎉 Analyse terminée! Ouvre le rapport:", report)

if __name__ == '__main__':
    main()