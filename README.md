# Malware Detector (Static Analysis Prototype)

A small FastAPI app that ingests emails/documents and returns a structured security analysis JSON (links, scripts, attachments, images, heuristics, scores, sanitized preview).

## Quick start (local)
```bash
git clone <this-repo>
cd malware-detector
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# Open http://localhost:8000
