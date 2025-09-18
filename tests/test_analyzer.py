import pytest
from app.analyzer import analyze

def test_simple_url():
    res = analyze("test.html", "text/html", b"", "Please visit http://paypa1.com/login")
    assert any(i['type']=="url" for i in res['iocs'])
    # typosquat should bump score
    assert res['overall_risk']['score'] >= 50

def test_obfuscated_js():
    txt = "<script>eval(unescape('%70%6f%77%65%72%73%68%65%6c%6c'))</script>"
    res = analyze("page.html", "text/html", b"", txt)
    assert any(i['type']=="script" for i in res['iocs'])

def test_powershell_indicator():
    txt = "powershell -EncodedCommand aGVsbG8="
    res = analyze("mail.txt", "text/plain", b"", txt)
    assert any(i['type']=="script" and 'powershell' in ' '.join(i['evidence']).lower() for i in res['iocs'])

def test_benign_newsletter():
    txt = '<img src="https://cdn.example.com/tracker.png"> Welcome!'
    res = analyze("news.html", "text/html", b"", txt)
    # Should not be critical
    assert res['overall_risk']['score'] < 70

def test_docm_macro_like():
    # Simulate docx binary containing 'VBA' token
    data = b'PK' + b'...word/document.xml...' + b'AutoOpen' + b'VBA'
    res = analyze("invoice.docm", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", data, "")
    assert any(i['type']=="attachment" for i in res['iocs'])
