# EventGraph: Provenance-Aware Forensic Timeline

A multi-device digital forensics correlation and provenance visualization workbench built with Python, Streamlit, Pandas, and PyVis.
 *Live Demo:* [Launch EventGraph on Streamlit](https://eventgraph-forensics-eexxl4zzlgn25kwegeupjf.streamlit.app/)

## Core Capabilities
1. *Multi-Format Log Ingestion & Schema Normalization:* Parses device logs from *JSON, **CSV* (Windows Event Viewer exports), and raw *Android adb logcat* dumps into a unified UTC chronological timeline.
2. *Cryptographic Chain of Custody:* Computes SHA-256 digests on every uploaded evidence file at ingestion and embeds a report-level SHA-256 signature (report_sha256) inside exported bundles.
3. *Rule-Based Cross-Device Correlation Engine:* Detects spatial-temporal continuity (GPS_PING -> USB_TETHER_ON), cross-device hardware handshakes (USB_TETHER_ON -> Windows ADB/MTP enumeration), and external storage data exfiltration (USB_CONNECTED -> FILE_COPIED).
4. *Interactive Provenance Graph:* Renders a directed PyVis node-edge graph distinguishing mobile artifacts (blue), host artifacts (amber), and high-confidence attack paths (red edges).
5. *Forensic Workbench Controls & Tamper Verification:* Includes live device filtering, confidence threshold sliders, keyword search, and a built-in SHA-256 integrity verifier for exported JSON evidence reports.
6. *Automated Case Narrative:* Generates court-ready executive summaries via a local Ollama instance (deepseek-r1:8b) with an automatic deterministic offline fallback.

## Quickstart

```bash
# 1. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the forensic workbench
streamlit run app.py
