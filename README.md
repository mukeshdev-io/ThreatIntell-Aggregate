# ThreatIntel Aggregator

A Python tool that checks an Indicator of Compromise (IP address, domain, or file hash) against **VirusTotal v3** and **AlienVault OTX**, normalises both sources into a single 0-100 risk score, and shows a combined verdict — via a CLI and a Streamlit dashboard.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Prerequisites](#prerequisites)
3. [Setup](#setup)
4. [Usage](#usage)
   - [CLI](#cli)
   - [Streamlit Dashboard](#streamlit-dashboard)
5. [Scoring Formula](#scoring-formula)
6. [Project Structure](#project-structure)
7. [Running Tests](#running-tests)
8. [Limitations](#limitations)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   User / CLI / UI                   │
└───────────────┬─────────────────────┬───────────────┘
                │                     │
         main.py (CLI)            app.py (Streamlit)
                │                     │
                └──────────┬──────────┘
                           │
                    validators.py
                 (type detection + regex)
                           │
              ┌────────────┴────────────┐
              │                         │
         vt_client.py             otx_client.py
      (VirusTotal API v3)      (AlienVault OTX API)
              │                         │
              └────────────┬────────────┘
                           │
                      scoring.py
               (0-100 score + verdict)
                           │
                      database.py
               (SQLite: persist + cache)
```

Each module has a single responsibility:

| Module | Responsibility |
|---|---|
| `config.py` | Load `.env`, expose typed constants |
| `validators.py` | Regex-based IoC type detection |
| `vt_client.py` | VirusTotal API v3 with rate-limit retry |
| `otx_client.py` | AlienVault OTX API with retry |
| `scoring.py` | Normalise + combine into 0-100 score |
| `database.py` | SQLite persistence + 24-hour cache |
| `main.py` | CLI entry point |
| `app.py` | Streamlit dashboard |

---

## Prerequisites

- Python 3.10 or later
- A free [VirusTotal](https://www.virustotal.com/gui/join-us) account (API key)
- A free [AlienVault OTX](https://otx.alienvault.com/) account (API key)

---

## Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-org/threatintel-aggregator.git
cd threatintel-aggregator

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp .env.example .env
# Edit .env and paste your real keys:
#   VIRUSTOTAL_API_KEY=<your key>
#   OTX_API_KEY=<your key>
```

The SQLite database (`threatintel.db`) is created automatically on first run.

---

## Usage

### CLI

```bash
# Single lookup
python main.py 8.8.8.8
python main.py evil.example.com
python main.py 44d88612fea8a8f36de82e1278abb02f

# Bulk lookup from a file (one IoC per line, # = comment)
python main.py --bulk iocs.txt
```

Example output:

```
  IoC       : 8.8.8.8 [ipv4]
  Score     : 3.2 / 100
  Verdict   : Low

  VirusTotal: 0 malicious, 0 suspicious (out of 94 engines)
  OTX       : 1 pulse(s) – malware families: none identified
```

### Streamlit Dashboard

```bash
streamlit run app.py
```

Open the URL shown in your terminal (usually `http://localhost:8501`).

**Dashboard features:**

- **Single Lookup** tab — type any IoC, press Look Up, see a colour-coded verdict card.
- **Bulk Lookup** tab — upload a `.txt` file; each IoC is queried in sequence with a progress bar.
- **History** tab — scrollable table of all past lookups, pie chart of verdict counts, CSV export.

---

## Scoring Formula

### VirusTotal sub-score (0-100)

```
weighted_hits = malicious + 0.5 × suspicious
vt_score      = min((weighted_hits / total_engines) × 100, 100)
```

Suspicious detections count at half weight because they represent ambiguous signals. Harmless/undetected engines do **not** reduce the score.

### AlienVault OTX sub-score (0-100)

Mapped non-linearly via pulse-count buckets:

| Pulses | Sub-score |
|--------|-----------|
| 0      | 0         |
| 1      | 20        |
| 2–4    | 40        |
| 5–9    | 60        |
| 10–24  | 80        |
| ≥ 25   | 100       |

### Combined score

```
combined = 0.65 × vt_score + 0.35 × otx_score
```

If one source is unavailable its weight transfers entirely to the other source.

### Verdict thresholds

| Score | Verdict |
|-------|---------|
| 0–30  | 🟢 Low  |
| 31–70 | 🟡 Medium |
| 71–100 | 🔴 High |

---

## Project Structure

```
threatintel-aggregator/
├── main.py            CLI entry point
├── app.py             Streamlit dashboard
├── config.py          Environment & constants
├── validators.py      IoC type detection
├── vt_client.py       VirusTotal API v3 client
├── otx_client.py      AlienVault OTX client
├── scoring.py         Risk scoring logic
├── database.py        SQLite persistence + cache
├── requirements.txt
├── .env.example       API key template
├── .env               ← create from .env.example (git-ignored)
├── threatintel.db     ← created on first run (git-ignored)
└── tests/
    ├── __init__.py
    ├── test_validators.py
    └── test_scoring.py
```

---

## Running Tests

```bash
pytest tests/ -v
```

The test suite uses only the Python standard library plus `pytest` — no API keys or network access required.

---

## Limitations

| Limitation | Detail |
|---|---|
| **VirusTotal free tier** | ~4 requests/minute. The client auto-paces and retries with exponential back-off, but bulk lookups of many IoCs will be slow. |
| **OTX free tier** | No hard rate limit documented, but very high request volumes may be throttled. |
| **IPv6** | Not currently supported; only dotted-decimal IPv4 addresses are accepted. |
| **URL indicators** | URLs are not yet a supported IoC type (extract the domain/IP first). |
| **Cache TTL** | Results are cached for 24 hours. Rapidly-changing threat data (e.g., a new malware campaign) may not be reflected until the cache expires. |
| **File analysis** | Only hash lookups are performed; the tool does not submit new files to VirusTotal for scanning. |
| **Concurrent requests** | The CLI and dashboard run lookups sequentially to respect rate limits; parallelism is not implemented. |
