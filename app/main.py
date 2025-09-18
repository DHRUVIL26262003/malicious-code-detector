from fastapi import FastAPI, Form, UploadFile, File, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .analyzer import analyze

app = FastAPI(title="Malware Detector (Static)")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("app/static/index.html","r") as f:
        return HTMLResponse(f.read())

@app.post("/analyze")
async def analyze_endpoint(file: UploadFile = File(None), raw_text: str = Form(None)):
    filename = None
    content_type = None
    data = b""
    text = ""
    if file:
        filename = file.filename
        content_type = file.content_type
        data = await file.read()
        # try to decode small text-like uploads
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            text = ""
    if raw_text:
        text = (text + "\n" + raw_text) if text else raw_text

    # fallback: if no text, try to extract from common binary types
    if not text and filename and filename.lower().endswith('.pdf'):
        try:
            text = pdf_extract_text(io.BytesIO(data))
        except Exception:
            text = ""

    result = analyze(filename or "", content_type or "", data, text or "")
    return JSONResponse(content=result)
