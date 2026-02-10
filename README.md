# AWSAS – Automated Web Application Analysis System

AWSAS is an automated web application security analysis system designed for educational and research purposes.

It performs a **full security analysis pipeline** starting from a target URL:

1. Technology fingerprinting
2. CVE matching using NVD data
3. Test payload generation using Claude LLM
4. Safe, non-destructive test execution
5. HTML & JSON report generation

The system provides a **web-based UI** and is fully containerized with Docker.

---

## ⚠️ Disclaimer

This tool is intended **only for authorized security testing**  
(e.g. labs like DVWA, Juice Shop, WebGoat, or systems you own).

Do **NOT** use it against targets you do not have permission to test.

---

## Features

- Automatic technology fingerprinting (headers, cookies, HTML, TLS)
- CVE matching using NVD (SQLite, offline)
- LLM-based payload generation (Claude)
- Safe PoC execution (non-destructive)
- HTML security report
- Web UI (FastAPI + vanilla JS)
- Docker & Docker Compose support

---

## Requirements

You need:

- Docker ≥ 20.x
- Docker Compose ≥ v2
- Internet access (for CVE feeds & Claude API)
- A Claude API key

---

## Project Structure
```
.
├── src/                 # Application source code
├── templates/           # HTML templates (UI)
├── scripts/             # Scripts for module testing
│   └── init_cve_store.py  # CVE DB builder (one-shot)
├── data/                # CVE database & feeds (mounted volume)
├── runs/                # Analysis outputs (mounted volume)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## Instalation

### 1. Clone repository
```bash
git clone https://github.com/Golovanito/Automated-Web-Application-Analysis-System.git
```

### 2. Create a `.env` file in the project root:
```env
CLAUDE_API_KEY=your_api_key_here
CLAUDE_MODEL=claude-sonnet-4-5-20250929
```

### 3. Build the CVE database
The CVE database is not included in the repository (it is large and must be generated locally).

Run once:
```bash
docker compose run --rm db_builder
```
What this does:
+ Downloads NVD CVE feeds (JSON 2.0)
+ Verifies SHA256 checksums
+ Builds data/cve_store.db
+ Exits automatically (one-shot job)

After this step, you should have: `data/cve_store.db`

### 4. Start the web application
```bash
docker compose up awsas
```
Then open:
http://localhost:8000


Using the Web UI
1. Paste a target URL (e.g. DVWA)
2. Click Start
3. Watch live logs
4. Open the generated HTML report
5. Download JSON / artifacts if needed
   
### Changing CVE feed range (optional)
You can control which CVEs are included by editing the db_builder command
inside `docker-compose.yml`, for example:
```yaml
command: >
  python scripts/init_cve_store.py
  --since 2019
  --with-recent
  --with-modified
```

### Volumes & Persistence

The following directories are mounted:

| Local directory | Container path | Purpose |
|-|-|-|
./data | /app/data |CVE DB & feeds
./runs| /app/runs | Analysis results

This means:
+ CVE DB persists across restarts
+ Reports are kept locally
+ Rebuilding the image does not delete data

## License

This project is intended for academic and educational use.\
See thesis documentation for usage context.