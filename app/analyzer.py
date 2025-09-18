import io
import json
import re
from typing import List, Dict, Any
from pdfminer.high_level import extract_text as pdf_extract_text
from PIL import Image, ExifTags
import zipfile

from .utils import (
    find_urls, find_data_uris, decode_base64_safe, levenshtein_ratio,
    normalize_url, is_obfuscated_js, has_powershell_indicator, score_label
)

BRAND_DOMAINS = ["paypal.com","google.com","microsoft.com","apple.com","github.com","amazon.com"]

def extract_text_from_docx(data: bytes) -> str:
    # docx is a zip; we can try to extract document.xml
    try:
        with io.BytesIO(data) as b:
            with zipfile.ZipFile(b) as z:
                if 'word/document.xml' in z.namelist():
                    return z.read('word/document.xml').decode(errors='ignore')
    except Exception:
        return ""
    return ""

def extract_exif(image_bytes: bytes) -> Dict[str, Any]:
    try:
        with Image.open(io.BytesIO(image_bytes)) as im:
            exif = {}
            raw = im._getexif() or {}
            for k, v in raw.items():
                name = ExifTags.TAGS.get(k, k)
                exif[name] = v
            return exif
    except Exception:
        return {}

def basic_ioc_enumeration(filename: str, content_type: str, data: bytes, raw_text: str):
    iocs = []
    # URLs in raw_text
    urls = find_urls(raw_text)
    for u in urls:
        nu = normalize_url(u)
        # simple typosquat check vs brand list
        best = max(((d, levenshtein_ratio(nu, d)) for d in BRAND_DOMAINS), key=lambda x: x[1])
        evidence = []
        score = 10
        if best[1] > 0.8 and best[0] not in nu:
            evidence.append(f"typosquat-similarity~{best[0]}:{best[1]:.2f}")
            score += 50
        if 'http://' in nu and 'https://' not in nu:
            evidence.append("http-not-https")
            score += 10
        if any(ch.isdigit() for ch in nu.split('//')[-1].split('.')[0]) and 'ip' in nu:
            evidence.append("ip-literal")
            score += 20
        iocs.append({
            "type":"url", "value": nu,
            "severity": {"score": min(100, score), "label": score_label(min(100, score))},
            "evidence": evidence or ["found in body"],
            "recommended_action": "external-check-needed (WHOIS/VirusTotal) or block if suspicious",
            "yara_like_rule": f"url =~ /{re.escape(nu)}/i"
        })

    # data URIs
    for mime,b64 in find_data_uris(raw_text):
        dec = decode_base64_safe(b64)
        evidence = [f"data-uri mime={mime}"]
        score = 20
        if mime.startswith('image'):
            # inspect exif
            exif = extract_exif(dec)
            if exif:
                evidence.append("contains-exif")
                score += 5
        if dec and len(dec) > 1024:
            evidence.append("large-embedded-payload")
            score += 20
        iocs.append({
            "type":"decoded_payload", "value": mime,
            "severity":{"score":min(100,score), "label":score_label(min(100,score))},
            "evidence": evidence,
            "recommended_action": "isolate and further inspect in sandbox",
            "yara_like_rule": None
        })

    # detect simple obfuscated JS in raw_text
    if is_obfuscated_js(raw_text):
        iocs.append({
            "type":"script", "value":"inline-js-obfuscation",
            "severity":{"score":75, "label":score_label(75)},
            "evidence":["JS obfuscation pattern matched (eval/Function/\\x)"],
            "recommended_action":"render-sanitized-preview; treat as suspicious",
            "yara_like_rule": "js_obf =~ /eval\\(|Function\\(|\\\\x[0-9a-fA-F]{2}/"
        })

    # powershell indicators
    if has_powershell_indicator(raw_text):
        iocs.append({
            "type":"script", "value":"powershell-indicator",
            "severity":{"score":90, "label":score_label(90)},
            "evidence":["PowerShell -EncodedCommand or powershell execution pattern"],
            "recommended_action":"isolate host; do not execute; dynamic analysis recommended",
            "yara_like_rule": "powershell =~ /-EncodedCommand|powershell\\s+-e/i"
        })

    # attachments (by filename pattern)
    if filename:
        fname = filename.lower()
        suspicious_exts = ('.js','.vbs','.exe','.scr','.lnk','.docm','.xlsm','.pif')
        if any(fname.endswith(e) for e in suspicious_exts):
            score = 80 if fname.endswith(('.exe','.scr','.lnk')) else 65
            iocs.append({
                "type":"attachment", "value":filename,
                "severity":{"score":score, "label":score_label(score)},
                "evidence":[f"suspicious extension {fname.split('.')[-1]}"],
                "recommended_action":"isolate file; do not open; scan in sandbox",
                "yara_like_rule": f"filename =~ /{re.escape(filename)}/i"
            })
        # docx/docm content scan
        if fname.endswith('.docx') or fname.endswith('.docm'):
            txt = extract_text_from_docx(data)
            if 'autoopen' in txt.lower() or 'vba' in txt.lower():
                iocs.append({
                    "type":"attachment","value":filename,
                    "severity":{"score":95,"label":score_label(95)},
                    "evidence":["suspicious Macro/AutoOpen token in docx content"],
                    "recommended_action":"isolate and inspect in Windows VM with macros disabled",
                    "yara_like_rule":"docx_macro_presence"
                })
    return iocs

def build_sanitized_preview(raw_text: str) -> str:
    # remove script tags and replace src/href with placeholders
    t = re.sub(r'(?is)<script.*?>.*?</script>', '[REMOVED SCRIPT]', raw_text)
    t = re.sub(r'(?i)(src|href)\s*=\s*["\']([^"\']+)["\']', r'\1="[REMOVED]"', t)
    return t

def analyze(filename: str, content_type: str, data: bytes, raw_text: str) -> Dict:
    iocs = basic_ioc_enumeration(filename, content_type, data, raw_text)
    overall_score = 0
    if iocs:
        overall_score = max(i['severity']['score'] for i in iocs)
    summary = f"Found {len(iocs)} IOC(s). Highest severity: {overall_score}"

    return {
        "summary": summary,
        "overall_risk": {"score": overall_score, "label": score_label(overall_score)},
        "iocs": iocs,
        "sanitized_preview": build_sanitized_preview(raw_text),
        "notes": "Static analysis only. Dynamic/sandbox checks marked as external-check-needed. Integrate WHOIS/VirusTotal for reputation."
    }
