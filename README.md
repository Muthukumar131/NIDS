# NetGuard: Network Intrusion Detection System

NetGuard is a local, beginner-friendly intrusion detection dashboard built with Python, Scapy, Streamlit, and Plotly. It is designed for a college hackathon demo and analyzes synthetic or authorized network traffic from PCAP files and log datasets. The project does not inspect encrypted payloads and does not claim to identify real malicious behavior without supporting evidence.

## What this project does

- Reviews uploaded PCAP/PCAPNG files and extracts packet-level metadata
- Detects suspicious patterns such as port scanning and unusual traffic spikes
- Analyzes authentication logs for brute-force attempts
- Assesses VPN login and session patterns from CSV logs
- Produces severity-based alerts using a shared schema
- Shows alerts in a dark-themed cybersecurity dashboard
- Exports alerts to CSV or JSON
- Stores activity logs locally in the `logs` folder

## Project structure

```text
netguard-nids/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── detector/
│   ├── __init__.py
│   ├── pcap_analyzer.py
│   ├── port_scan.py
│   ├── brute_force.py
│   ├── anomaly.py
│   ├── vpn_analyzer.py
│   ├── severity.py
│   └── recommendations.py
├── utils/
│   ├── __init__.py
│   ├── file_handler.py
│   ├── logger.py
│   └── data_generator.py
├── data/
│   ├── sample_auth_logs.csv
│   ├── sample_vpn_logs.csv
│   ├── sample_capture.pcap
│   └── README.md
├── logs/
│   └── .gitkeep
├── reports/
│   └── .gitkeep
└── tests/
    ├── __init__.py
    ├── test_port_scan.py
    ├── test_brute_force.py
    ├── test_vpn_analyzer.py
    ├── test_file_handler.py
    └── test_severity.py
```

## Requirements

- Python 3.12 (recommended for Windows)
- Local machine with access to the project folder
- No external paid APIs or services required

## Setup on Windows PowerShell

1. Open PowerShell in the project folder.
2. Create a virtual environment:

```powershell
python -m venv .venv
```

3. Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

4. Install dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

5. Generate synthetic demo data:

```powershell
python -c "from utils.data_generator import generate_sample_data; from pathlib import Path; generate_sample_data(Path.cwd())"
```

6. Run the automated tests:

```powershell
python -m pytest -q
```

7. Launch the dashboard:

```powershell
streamlit run app.py
```

## Demo guide

1. Start the app with the command above.
2. Open the browser window shown by Streamlit.
3. Click "Generate demo dataset" on the Overview page.
4. Click "Run demo analysis".
5. Visit the PCAP Traffic Analysis, Port Scan Detection, Brute-Force Detection, and VPN Security Assessment pages.
6. Review the alert table and export results to CSV or JSON.

## Architecture overview

- `utils/data_generator.py` creates synthetic sample data for warning and detection testing.
- `detector/pcap_analyzer.py` parses PCAP files and extracts basic packet metadata such as timestamps, src/dst IPs, ports, and protocol.
- `detector/port_scan.py` groups packets by source and destination and looks for high port counts in a short time window.
- `detector/brute_force.py` counts failed authentication attempts against a username and IP.
- `detector/anomaly.py` looks for unusual traffic spikes, repeated attempts, and elevated packet counts.
- `detector/vpn_analyzer.py` checks VPN authentication and session patterns with a rule-based approach.
- `detector/severity.py` centralizes severity assignment.
- `detector/recommendations.py` gives practical next steps for each alert type.
- `app.py` provides the Streamlit dashboard and data export interface.

## Important limitations

- This project is a prototype for authorized educational use and synthetic data.
- It analyzes packet metadata, not encrypted payload contents.
- It does not claim to prove malicious intent from one event alone.
- This is not an enterprise-grade IDS and should not be used for live production monitoring without review.
- The app is designed to run locally on a Windows machine and stores reports in the local project folders.

## Security notes

- Only analyze traffic you are authorized to inspect.
- Do not run the app against real external systems or attack targets.
- Do not auto-block or exploit remote hosts.
- Keep reports local and avoid uploading sensitive information to external services.

## Testing summary

The included pytest tests cover:

- port scan detection
- brute-force detection
- VPN authentication analysis
- severity thresholds
- malformed CSV handling
- empty input validation
- duplicate alert suppression

## Troubleshooting

### Python version problems

If `pip install` fails on Python 3.13, use Python 3.12 instead. This project was validated on Python 3.12.10.

### Streamlit launch issues

Run the command from the `netguard-nids` folder so that `app.py` is visible to the interpreter.

```powershell
Set-Location .\netguard-nids
streamlit run app.py
```

### Sample data missing

Generate the synthetic dataset again with:

```powershell
python -c "from utils.data_generator import generate_sample_data; from pathlib import Path; generate_sample_data(Path.cwd())"
```

## Conclusion

NetGuard provides a clear, hackathon-friendly prototype for local network analysis, alerting, and VPN risk review. It is intentionally simple, transparent, and explainable so students can understand the detection logic and present the project confidently.
