# WAF/IPS Performance Test Results — Analysis Toolkit

This repository contains the raw test data and analysis scripts produced as part of a network security research project. The goal of the project was to quantify the performance overhead introduced by different combinations of IPS (Intrusion Prevention System) and WAF (Web Application Firewall) components in a web application architecture.

The tools in this repository parse the raw output files generated during load testing, extract the relevant performance metrics, and produce charts and an HTML summary report.

---

## Table of Contents

1. [Project Context](#project-context)
2. [Repository Structure](#repository-structure)
3. [Raw Data Files](#raw-data-files)
4. [Test Scenarios](#test-scenarios)
5. [Analysis Scripts](#analysis-scripts)
6. [Generated Outputs](#generated-outputs)
7. [Dependencies and Installation](#dependencies-and-installation)
8. [Usage](#usage)

---

## Project Context

The experiments compared several network topologies involving the following components:

- **Injector** : the machine running `wrk`, the HTTP load testing tool.
- **IPS** : a machine running Suricata in NFQUEUE mode, inspecting packets inline.
- **WAF** : a machine running Apache with the ModSecurity module as a reverse proxy.
- **Backend** : the target web server receiving HTTP requests.

Each scenario was tested at a fixed concurrency level (number of simultaneous connections) over a duration of 200 seconds. Metrics collected at each test machine included CPU usage (via `mpstat`) and HTTP throughput and latency (via `wrk`).

---

## Repository Structure

```
.
├── analyze_results.py          # Basic extraction and plotting script
├── analyze_results_report.py   # Full extraction, plotting, and HTML report script
├── requirements.txt            # Python dependencies
├── RESULTS.pdf                 # Compiled research results document
├── analysis_output/            # Directory containing all generated outputs
│   ├── summary_results.csv
│   ├── cpu_busy.png
│   ├── throughput.png
│   ├── latency_p50_p90.png
│   ├── combined_summary.png
│   └── report.html
├── INJ_IPS_WAF_WEB/            # Scenario: Injector -> IPS -> WAF -> Backend
├── INJ_IPS_WEB_NO_PROXY/       # Scenario: Injector -> IPS -> Backend (direct)
├── INJ_IPS_WEB_PROXY/          # Scenario: Injector -> IPS -> Proxy (no ModSec) -> Backend
├── INJ_NFQ_WAF_WEB/            # Scenario: Injector -> NFQUEUE (no Suricata) -> WAF -> Backend
├── INJ_WAF_WEB/                # Scenario: Injector -> WAF -> Backend (no IPS)
├── INJ_WEB/                    # Scenario: Injector -> Backend (baseline, no IPS, no WAF)
├── INJ_WEB_PROXY/              # Scenario: Injector -> Proxy (no ModSec, no IPS) -> Backend
└── NO INJECTION/               # Control: CPU measurement with no load traffic
```

---

## Raw Data Files

Each scenario directory contains one or more numbered run subdirectories (e.g., `run 1`, `run 2`, `run 3`). Inside each run, three types of files are present:

### `AVG_CPU_ips_<concurrency>.txt`

CPU usage summary for the **IPS machine**, collected using `mpstat` then averaged over the duration of the test.

**Example content:**

```
Resume de la mesure IPS (duree 200s)

AVG busy (all cpus) = 22.51 % (avg idle=77.49%) over 2010 samples
```

The script extracts the `busy` percentage (and `idle` when available) from this file using regular expressions. In some scenarios where Suricata is not running, this file reports the base system CPU usage without the IPS process.

### `AVG_CPU_waf_<concurrency>.txt`

CPU usage summary for the **WAF machine**, structured identically to the IPS file.

**Example content:**

```
Resume de la mesure WAF (duree 200s)

AVG busy (all cpus) = 18.34 % (avg idle=81.66%) over 2010 samples
```

### `wrk_via_waf_c<concurrency>_t<threads>_<duration>s_run<N>.txt`

Raw output from the `wrk` HTTP benchmarking tool, run on the **Injector machine**. This file contains throughput, latency statistics, and percentile distributions.

**Example content:**

```
Running 3m test @ http://10.0.2.1/
  4 threads and 500 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   295.58ms  318.09ms   2.00s    78.53%
    Req/Sec   608.37     81.84     1.06k    72.89%
  Latency Distribution
     50%   65.41ms
     75%  527.99ms
     90%  843.32ms
     99%    1.03s
  472836 requests in 3.33m, 111.83MB read
  Socket errors: connect 0, read 73477, write 0, timeout 311
Requests/sec:   2363.00
Transfer/sec:    572.29KB
```

The script extracts `Requests/sec` (global throughput) and the latency percentiles `p50`, `p75`, `p90`, and `p99` from this file.

### `<concurrency>.txt`

A time-series file recording the cumulative request count over time, sampled every second. Each line contains a timestamp and the cumulative number of requests handled at that moment, separated by a comma.

**Example content:**

```
03:04:59,1
03:05:00,1
03:05:01,1
03:05:02,20408
...
03:08:15,2074143
```

This file is present in some scenarios (e.g., `INJ_IPS_WAF_WEB`, `INJ_IPS_WEB_NO_PROXY`) and represents the request injection ramp-up over the test duration. It is not parsed by the current analysis scripts, but is kept for reference and potential further analysis.

### `summary_ips.txt` / `summary_waf.txt`

Alternative naming convention used in the `NO INJECTION` scenario. Structurally identical to the `AVG_CPU_*.txt` files, but may include additional detail such as per-process CPU usage (e.g., the Suricata process specifically).

**Example content:**

```
Resume de la mesure IPS (duree 200s)

AVG busy (all cpus) = 10.18 % (avg idle=89.82%) over 2000 samples
avg %CPU (suricata process) = 0.00 % over 398 samples
```

The scripts handle both naming conventions transparently.

---

## Test Scenarios

| Directory              | Architecture                       | Description                                                                                                                                                                |
| :--------------------- | :--------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `INJ_IPS_WAF_WEB`      | Injector → IPS → WAF → Backend     | Full security stack. Suricata inspects all packets inline via NFQUEUE. Apache+ModSecurity acts as a reverse proxy. This is the most complete scenario.                     |
| `INJ_IPS_WEB_NO_PROXY` | Injector → IPS → Backend           | IPS active, no proxy. Allows isolating the overhead of Suricata alone, with direct access to the backend.                                                                  |
| `INJ_IPS_WEB_PROXY`    | Injector → IPS → Proxy → Backend   | IPS active, proxy in place but ModSecurity disabled. Measures the combined overhead of IPS + a plain reverse proxy, without WAF filtering.                                 |
| `INJ_NFQ_WAF_WEB`      | Injector → NFQUEUE → WAF → Backend | NFQUEUE is configured but Suricata is not running (or is in accept-all mode). WAF is active. Measures the overhead of the NFQUEUE kernel hook alone combined with the WAF. |
| `INJ_WAF_WEB`          | Injector → WAF → Backend           | WAF active, no IPS. Isolates the overhead of Apache+ModSecurity as a proxy.                                                                                                |
| `INJ_WEB`              | Injector → Backend                 | Baseline. No IPS, no WAF, no proxy. Direct connections to the backend. Used as the reference measurement.                                                                  |
| `INJ_WEB_PROXY`        | Injector → Proxy → Backend         | Proxy in place (ModSecurity disabled), no IPS. Measures the cost of the reverse proxy layer alone.                                                                         |
| `NO INJECTION`         | —                                  | Control run. No load traffic. CPU is measured at idle to establish a baseline system overhead.                                                                             |

---

## Analysis Scripts

### `analyze_results_report.py` (recommended)

The primary analysis script. It performs the full pipeline: data collection, CSV export, chart generation, and HTML report generation.

**Capabilities:**

- Walks the entire scenario directory tree and collects metrics from all `AVG_CPU_*.txt` and `wrk_*.txt` files.
- Handles naming variations (`AVG_CPU_ips_*`, `summary_ips`, etc.) and tolerates missing files gracefully.
- Extracts: `avg_busy_ips`, `avg_idle_ips`, `avg_busy_waf`, `avg_idle_waf`, `requests_per_sec`, `p50`, `p75`, `p90`, `p99`, `socket_errors`, `transfer_per_sec`.
- Detects the concurrency level from filenames automatically (e.g., `_c500_` or `_500.txt`).
- Exports a consolidated `summary_results.csv`.
- Generates four PNG charts (see [Generated Outputs](#generated-outputs)).
- Generates a self-contained `report.html` with an embedded scenario legend, the full data table, and all charts.

### `analyze_results.py` (lightweight alternative)

A simpler, standalone script producing the same CSV and PNG charts without the HTML report. Useful for quick inspection or integration into other pipelines. It shares the same parsing logic but has fewer visual enhancements (no value annotations on bars, no scenario legend).

---

## Generated Outputs

All outputs are written to the `analysis_output/` directory.

| File                   | Description                                                                                                                            |
| :--------------------- | :------------------------------------------------------------------------------------------------------------------------------------- |
| `summary_results.csv`  | One row per test run, containing all extracted metrics. Suitable for import into spreadsheet software or further statistical analysis. |
| `cpu_busy.png`         | Grouped bar chart comparing IPS and WAF CPU busy percentage across all scenarios and concurrency levels.                               |
| `throughput.png`       | Bar chart showing `Requests/sec` for each scenario run.                                                                                |
| `latency_p50_p90.png`  | Grouped bar chart comparing the median (P50) and 90th percentile (P90) latency in milliseconds.                                        |
| `combined_summary.png` | A single figure stacking the three charts above for a compact comparative overview.                                                    |
| `report.html`          | A standalone HTML report embedding all charts, the full data table, and a descriptive legend for each scenario.                        |

---

Python 3.7 or later is required. The external dependencies are `pandas` and `matplotlib`, listed in `requirements.txt`.

```bash
pip install -r requirements.txt
```

On Debian/Ubuntu systems:

```bash
sudo apt install -y python3-pip
pip3 install -r requirements.txt
```

---

## Usage

Run the full analysis from the root of this repository:

```bash
python analyze_results_report.py .
```

The script will scan all subdirectories, extract the metrics, and write all outputs to `./analysis_output/`. Open `analysis_output/report.html` in any browser to view the report.

To use the lightweight script instead:

```bash
python analyze_results.py .
```

An optional `--out` argument can redirect outputs to a different directory:

```bash
python analyze_results.py . --out /path/to/custom_output
```

---

_This repository was produced as part of a research project on the performance impact of network security layers (IPS/WAF) in web environments._
