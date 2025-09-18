import re
import base64
from difflib import SequenceMatcher
from typing import List, Tuple
from urllib.parse import unquote, urlparse

URL_RE = re.compile(
    r'(?:(?:https?|ftp):\/\/)?'            # scheme optional
    r'(?:[\w\-_]+\.)+[\w\-_]+'            # domain
    r'(?:[:]\d+)?'                        # port
    r'(?:[\/?][^\s\'"<>]*)?' , re.I)

DATA_URI_RE = re.compile(r'data:([-\w]+\/[-\w+.]+)?;base64,([A-Za-z0-9+/=]+)')

JS_OBFUSC_RE = re.compile(r'(eval\(|Function\(|unescape\(|atob\(|\\x[0-9a-fA-F]{2})')
POWERSHELL_RE = re.compile(r'(-EncodedCommand|powershell\s+-e|pwsh\s+-e)', re.I)

def find_urls(text: str) -> List[str]:
    return list({m.group(0) for m in URL_RE.finditer(text)})

def find_data_uris(text: str) -> List[Tuple[str,str]]:
    out = []
    for m in DATA_URI_RE.finditer(text):
        mime = m.group(1) or ''
        b64 = m.group(2)
        out.append((mime, b64))
    return out

def decode_base64_safe(b64: str) -> bytes:
    try:
        return base64.b64decode(b64, validate=False)
    except Exception:
        return b''

def levenshtein_ratio(a: str, b: str) -> float:
    # use SequenceMatcher ratio as a proxy (1.0 == identical)
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()

def normalize_url(u: str) -> str:
    u = u.strip()
    if u.startswith('www.'):
        u = 'http://' + u
    # unquote percent-encodings
    try:
        u = unquote(u)
        return u
    except Exception:
        return u

def is_obfuscated_js(snippet: str) -> bool:
    return bool(JS_OBFUSC_RE.search(snippet))

def has_powershell_indicator(text: str) -> bool:
    return bool(POWERSHELL_RE.search(text))

def score_label(score: int) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"
