#!/usr/bin/env python3
"""
analyze_results.py

Parcourt une arborescence de tests (structure indiquée par l'utilisateur),
extrait:
 - AVG CPU (fichiers nommés AVG_CPU_ips_<c>.txt ou AVG_CPU_waf_<c>.txt)
 - WRK results (fichiers contenant "Requests/sec" et "Latency Distribution")

Produit:
 - summary.csv contenant une ligne par run (scenario, run name, concurrency)
 - PNGs: cpu_busy.png, throughput.png, latency.png
 - un dossier analysis_output/ contenant CSV + PNG

Usage:
    python3 analyze_results.py /path/to/results_root

"""

import sys
import re
import os
import csv
import argparse
from pathlib import Path
import math

import matplotlib.pyplot as plt
import pandas as pd

# -----------------------
# Helpers: parsing
# -----------------------

def parse_avg_cpu_file(path):
    """
    Parse a file containing a line like:
    AVG busy (all cpus) = 11.75 % (avg idle=88.25%) over 1990 samples
    Returns dict { 'busy': float, 'idle': float, 'samples': int } or None if not found.
    """
    text = Path(path).read_text(errors='ignore')
    # try several regex patterns
    patterns = [
        r"AVG busy.*=\s*([0-9]+(?:\.[0-9]+)?)\s*%.*avg idle\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*%.*over\s*([0-9]+)\s*samples",
        r"AVG busy.*=\s*([0-9]+(?:\.[0-9]+)?)\s*%.*over\s*([0-9]+)\s*samples",  # without idle
        r"AVG busy.*=\s*([0-9]+(?:\.[0-9]+)?)\s*%",  # minimal
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if m:
            if len(m.groups()) == 3:
                busy = float(m.group(1))
                idle = float(m.group(2))
                samples = int(m.group(3))
                return {'busy': busy, 'idle': idle, 'samples': samples}
            elif len(m.groups()) == 2:
                busy = float(m.group(1))
                samples = int(m.group(2))
                return {'busy': busy, 'idle': None, 'samples': samples}
            else:
                busy = float(m.group(1))
                return {'busy': busy, 'idle': None, 'samples': None}
    # fallback: search "avg idle" alone
    m2 = re.search(r"avg idle\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*%", text, re.IGNORECASE)
    if m2:
        return {'busy': None, 'idle': float(m2.group(1)), 'samples': None}
    return None

def convert_to_seconds(val_str):
    """Convert string like '65.54ms' or '1.04s' or '200ms' to seconds (float)."""
    if val_str is None:
        return None
    val_str = val_str.strip()
    m = re.match(r"([0-9]+(?:\.[0-9]+)?)\s*(ms|s|us)?", val_str, re.IGNORECASE)
    if not m:
        try:
            return float(val_str)
        except:
            return None
    val = float(m.group(1))
    unit = (m.group(2) or 's').lower()
    if unit == 'ms':
        return val / 1000.0
    if unit == 'us':
        return val / 1_000_000.0
    return val

def parse_wrk_file(path):
    """
    Parse wrk output:
     - Requests/sec: <num>
     - Latency Distribution block: look for lines with '50%','75%','90%','99%'
    Returns dict with keys: requests_per_sec, p50, p75, p90, p99 (seconds)
    """
    text = Path(path).read_text(errors='ignore')
    res = {'requests_per_sec': None, 'p50': None, 'p75': None, 'p90': None, 'p99': None, 'raw_errors': None}
    # Requests/sec (global)
    m = re.search(r"Requests/sec:\s*([0-9]+(?:\.[0-9]+)?)", text)
    if m:
        res['requests_per_sec'] = float(m.group(1))
    # fallback: sometimes "Req/Sec" appears under Thread Stats; ignore for now
    # Latency distribution: find the block "Latency Distribution" and following lines
    # Accept lines like: " 50%   65.54ms"
    for perc in ('50','75','90','99'):
        mm = re.search(r"^\s*"+perc+r"%\s+([0-9]+(?:\.[0-9]+)?\s*(?:ms|s|us)?)", text, re.MULTILINE | re.IGNORECASE)
        if mm:
            val = convert_to_seconds(mm.group(1))
            res_key = 'p'+perc
            res[res_key] = val
    # also try inline pattern like "50%   65.54ms  75% 541.17ms 90% 840.63ms" in one line
    inline = re.search(r"50%[^\d]*([0-9]+(?:\.[0-9]+)?\s*(?:ms|s|us)?)[^\n]*75%[^\d]*([0-9]+(?:\.[0-9]+)?\s*(?:ms|s|us)?)[^\n]*90%[^\d]*([0-9]+(?:\.[0-9]+)?\s*(?:ms|s|us)?)", text, re.IGNORECASE)
    if inline:
        res['p50'] = convert_to_seconds(inline.group(1))
        res['p75'] = convert_to_seconds(inline.group(2))
        res['p90'] = convert_to_seconds(inline.group(3))
    # sometimes 99% is present separately
    m99 = re.search(r"99%[^\d]*([0-9]+(?:\.[0-9]+)?\s*(?:ms|s|us)?)", text, re.IGNORECASE)
    if m99:
        res['p99'] = convert_to_seconds(m99.group(1))
    # attempt to find socket errors
    m_err = re.search(r"Socket errors:[^\n]*", text)
    if m_err:
        res['raw_errors'] = m_err.group(0).strip()
    return res

# -----------------------
# Walk tree and collect
# -----------------------

def collect_results(root_path):
    root = Path(root_path)
    rows = []
    missing = []
    # Expected pattern: /SCENARIO/run N/ files...
    for scenario_dir in sorted(root.iterdir()):
        if not scenario_dir.is_dir():
            continue
        scenario = scenario_dir.name
        # each run folder inside
        for run_dir in sorted(scenario_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            runname = run_dir.name
            # find the wrk file (pattern contains 'wrk' and '.txt')
            wrk_file = None
            for f in run_dir.iterdir():
                if f.is_file() and 'wrk' in f.name and f.suffix in ('.txt', '.log'):
                    wrk_file = f
                    break
            # find AVG CPU files for ips and waf - pattern AVG_CPU_ips_<c>.txt
            avg_ips = None
            avg_waf = None
            for f in run_dir.iterdir():
                if f.is_file() and f.name.lower().startswith('avg_cpu_ips'):
                    avg_ips = f
                if f.is_file() and f.name.lower().startswith('avg_cpu_waf'):
                    avg_waf = f
            # also try summary files (summary_ips.txt)
            for f in run_dir.iterdir():
                if f.is_file() and f.name.lower().startswith('summary_ips'):
                    avg_ips = f
                if f.is_file() and f.name.lower().startswith('summary_waf'):
                    avg_waf = f
            # concurrency detection: try to extract number from filenames or dir files
            concurrency = None
            # common patterns: file named '500.txt' or 'AVG_CPU_ips_500.txt' or 'wrk_via_waf_c500_...'
            for f in run_dir.iterdir():
                n = f.name
                m = re.search(r'(?<!\d)(\d{2,5})(?!\d)', n)  # 2-5 digit number
                if m:
                    # prefer 500/1000/300 etc in file names, but skip year-like numbers by checking file context
                    num = int(m.group(1))
                    if num in (50,100,200,300,500,1000,2000,4000) or num >= 100:
                        concurrency = num
                        break
            # fallback: parse avg_ips filename for concurrency
            if concurrency is None and avg_ips is not None:
                m = re.search(r'(\d{2,5})', avg_ips.name)
                if m:
                    concurrency = int(m.group(1))
            if concurrency is None and wrk_file is not None:
                m = re.search(r'c(\d+)', wrk_file.name)
                if m:
                    concurrency = int(m.group(1))
            # extract metrics
            data = {
                'scenario': scenario,
                'run': runname,
                'concurrency': concurrency,
                'path': str(run_dir),
                'avg_busy_ips': None,
                'avg_idle_ips': None,
                'avg_busy_waf': None,
                'avg_idle_waf': None,
                'samples_ips': None,
                'samples_waf': None,
                'requests_per_sec': None,
                'p50': None,
                'p75': None,
                'p90': None,
                'p99': None,
                'raw_errors': None,
            }
            if avg_ips:
                parsed = parse_avg_cpu_file(avg_ips)
                if parsed:
                    data['avg_busy_ips'] = parsed.get('busy')
                    data['avg_idle_ips'] = parsed.get('idle')
                    data['samples_ips'] = parsed.get('samples')
                else:
                    missing.append(str(avg_ips))
            else:
                missing.append(f"{run_dir}/AVG_CPU_ips_*.txt")
            if avg_waf:
                parsed = parse_avg_cpu_file(avg_waf)
                if parsed:
                    data['avg_busy_waf'] = parsed.get('busy')
                    data['avg_idle_waf'] = parsed.get('idle')
                    data['samples_waf'] = parsed.get('samples')
                else:
                    missing.append(str(avg_waf))
            else:
                missing.append(f"{run_dir}/AVG_CPU_waf_*.txt")
            if wrk_file:
                parsed = parse_wrk_file(wrk_file)
                data['requests_per_sec'] = parsed.get('requests_per_sec')
                data['p50'] = parsed.get('p50')
                data['p75'] = parsed.get('p75')
                data['p90'] = parsed.get('p90')
                data['p99'] = parsed.get('p99')
                data['raw_errors'] = parsed.get('raw_errors')
            else:
                missing.append(f"{run_dir}/*wrk*.txt")
            rows.append(data)
    df = pd.DataFrame(rows)
    return df, missing

# -----------------------
# Plotting helpers
# -----------------------

def save_summary_csv(df, outdir):
    path = Path(outdir) / "summary_results.csv"
    df.to_csv(path, index=False)
    print(f"Saved summary CSV -> {path}")

def plot_cpu(df, outdir):
    # Create display label: scenario (concurrency)
    df2 = df.copy()
    df2['label'] = df2.apply(lambda r: f"{r['scenario']} ({r['concurrency']})", axis=1)
    df2 = df2.sort_values(['scenario','concurrency'])
    labels = df2['label'].tolist()
    x = range(len(labels))
    ips_busy = df2['avg_busy_ips'].fillna(0).tolist()
    waf_busy = df2['avg_busy_waf'].fillna(0).tolist()

    fig, ax = plt.subplots(figsize=(max(8, len(labels)*0.6), 6))
    width = 0.35
    ax.bar([i - width/2 for i in x], ips_busy, width=width, label='IPS busy (%)')
    ax.bar([i + width/2 for i in x], waf_busy, width=width, label='WAF busy (%)')
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    ax.set_ylabel('CPU busy (%)')
    ax.set_title('CPU busy (IPS & WAF) par scénario (concurrency)')
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    plt.tight_layout()
    out = Path(outdir) / "cpu_busy.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Saved CPU plot -> {out}")

def plot_throughput(df, outdir):
    df2 = df.copy()
    df2['label'] = df2.apply(lambda r: f"{r['scenario']} ({r['concurrency']})", axis=1)
    df2 = df2.sort_values(['scenario','concurrency'])
    labels = df2['label'].tolist()
    x = range(len(labels))
    thr = df2['requests_per_sec'].fillna(0).tolist()

    fig, ax = plt.subplots(figsize=(max(8, len(labels)*0.6), 5))
    ax.bar(x, thr)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    ax.set_ylabel('Requests/sec (wrk)')
    ax.set_title('Throughput (Requests/sec) par scénario')
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    plt.tight_layout()
    out = Path(outdir) / "throughput.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Saved throughput plot -> {out}")

def plot_latency(df, outdir):
    df2 = df.copy()
    df2['label'] = df2.apply(lambda r: f"{r['scenario']} ({r['concurrency']})", axis=1)
    df2 = df2.sort_values(['scenario','concurrency'])
    labels = df2['label'].tolist()
    x = range(len(labels))
    p50 = df2['p50'].fillna(0).astype(float).tolist()
    p90 = df2['p90'].fillna(0).astype(float).tolist()

    fig, ax = plt.subplots(figsize=(max(8, len(labels)*0.6), 5))
    width = 0.35
    ax.bar([i - width/2 for i in x], [v*1000 if v is not None else 0 for v in p50], width=width, label='p50 (ms)')
    ax.bar([i + width/2 for i in x], [v*1000 if v is not None else 0 for v in p90], width=width, label='p90 (ms)')
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    ax.set_ylabel('Latency (ms)')
    ax.set_title('Latency percentiles (p50 & p90) par scénario')
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    plt.tight_layout()
    out = Path(outdir) / "latency_p50_p90.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Saved latency plot -> {out}")

# -----------------------
# Main
# -----------------------

def main():
    parser = argparse.ArgumentParser(description="Analyse résultats: CPU + WRK pour scénarios WAF/IPS")
    parser.add_argument('root', help='dossier racine contenant les dossiers INJ_*')
    parser.add_argument('--out', help='dossier où sauvegarder outputs', default=None)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print("Erreur: dossier racine non trouvé:", root)
        sys.exit(1)

    outdir = Path(args.out) if args.out else root / "analysis_output"
    outdir.mkdir(parents=True, exist_ok=True)
    print("Collecting results from:", root)
    df, missing = collect_results(root)

    if df.empty:
        print("Aucune donnée trouvée. Vérifie la structure des dossiers.")
        sys.exit(1)

    # normalize concurrency to numeric
    df['concurrency'] = pd.to_numeric(df['concurrency'], errors='coerce')

    # save raw summary
    save_summary_csv(df, outdir)

    # Produce plots
    plot_cpu(df, outdir)
    plot_throughput(df, outdir)
    plot_latency(df, outdir)

    # Also produce a combined figure with 3 subplots (stacked)
    fig, axs = plt.subplots(3, 1, figsize=(12, 12))
    df2 = df.copy().sort_values(['scenario','concurrency'])
    labels = df2.apply(lambda r: f"{r['scenario']}\n({int(r['concurrency']) if pd.notna(r['concurrency']) else 'NA'})", axis=1).tolist()
    x = range(len(labels))
    # CPU
    axs[0].bar([i-0.2 for i in x], df2['avg_busy_ips'].fillna(0), width=0.4, label='IPS busy (%)')
    axs[0].bar([i+0.2 for i in x], df2['avg_busy_waf'].fillna(0), width=0.4, label='WAF busy (%)')
    axs[0].set_ylabel('CPU busy (%)')
    axs[0].legend()
    axs[0].set_xticks(list(x))
    axs[0].set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    axs[0].grid(axis='y', linestyle='--', alpha=0.4)
    # Throughput
    axs[1].bar(x, df2['requests_per_sec'].fillna(0))
    axs[1].set_ylabel('Requests/sec')
    axs[1].set_xticks(list(x))
    axs[1].set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    axs[1].grid(axis='y', linestyle='--', alpha=0.4)
    # Latency p50 (ms)
    axs[2].bar([i-0.15 for i in x], (df2['p50'].fillna(0).astype(float)*1000), width=0.3, label='p50 (ms)')
    axs[2].bar([i+0.15 for i in x], (df2['p90'].fillna(0).astype(float)*1000), width=0.3, label='p90 (ms)')
    axs[2].set_ylabel('Latency (ms)')
    axs[2].legend()
    axs[2].set_xticks(list(x))
    axs[2].set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
    axs[2].grid(axis='y', linestyle='--', alpha=0.4)

    plt.tight_layout()
    combined_out = outdir / "combined_summary.png"
    fig.savefig(combined_out, dpi=150)
    plt.close(fig)
    print(f"Saved combined figure -> {combined_out}")

    # Print missing patterns
    if missing:
        print("\nQuelques fichiers/patterns non trouvés ou non parsés (exemples) :")
        for x in sorted(set(missing))[:30]:
            print(" -", x)
    print("\nTerminé. Résultats dans:", outdir)

if __name__ == '__main__':
    main()
