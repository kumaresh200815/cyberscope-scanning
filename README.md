# CyberScope - Redesigned UI

A Flask + Nmap network security scanner based on the CyberScope project architecture, with a redesigned dashboard UI. Backend scan/report functionality is retained; the interface has been changed.

## Run
1. Install Python 3.10+ and Nmap.
2. `python -m venv .venv`
3. Windows: `.venv\\Scripts\\activate`
4. `pip install -r requirements.txt`
5. `python app.py`
6. Open `http://127.0.0.1:5000`

Only scan localhost/private targets you are authorized to test.
