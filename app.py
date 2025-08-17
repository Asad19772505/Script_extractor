import io
import json
import re
from urllib.parse import urlparse, urljoin

import requests
import streamlit as st
import pandas as pd
from bs4 import BeautifulSoup

# ---------------------------
# App Setup
# ---------------------------
st.set_page_config(page_title="URL → Script Generator + Data Export", layout="wide")
st.title("🔧 URL → Script Generator + Data Export")
st.caption("Paste any URL → get a ready-to-run script in your chosen language — and export extracted data as CSV/XLSX.")

# ---------------------------
# Helpers
# ---------------------------
LANGUAGES = [
    "Python",
    "JavaScript (Node)",
    "TypeScript (Node)",
    "bash (curl)",
    "bash (wget)",
    "PowerShell",
    "Java (Jsoup)",
    "C# (HttpClient)",
    "PHP",
    "Ruby",
    "Go",
]

TASKS = [
    "Auto-detect from URL",
    "Fetch JSON/API",
    "Scrape main text (HTML)",
    "Extract links (HTML)",
    "Download file (binary)",
]

EXT_MAP = {
    "Python": ".py",
    "JavaScript (Node)": ".js",
    "TypeScript (Node)": ".ts",
    "bash (curl)": ".sh",
    "bash (wget)": ".sh",
    "PowerShell": ".ps1",
    "Java (Jsoup)": ".java",
    "C# (HttpClient)": ".cs",
    "PHP": ".php",
    "Ruby": ".rb",
    "Go": ".go",
}

def parse_headers_input(text: str) -> dict:
    headers = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers

def probe_url(url: str, timeout: int = 15, headers: dict | None = None) -> dict:
    result = {"ok": False, "error": None, "content_type": None, "filename": None, "status": None, "is_html": False, "is_json": False}
    try:
        h = headers or {}
        r = requests.head(url, allow_redirects=True, timeout=timeout, headers=h)
        if r.status_code >= 400 or "content-type" not in r.headers:
            r = requests.get(url, stream=True, allow_redirects=True, timeout=timeout, headers=h)
        result["status"] = r.status_code
        ctype = r.headers.get("content-type", "").lower()
        disp = r.headers.get("content-disposition", "")
        result["content_type"] = ctype

        filename = None
        m = re.search(r'filename="?([^"]+)"?', disp)
        if m:
            filename = m.group(1)
        else:
            path = urlparse(r.url).path
            if path and path != "/":
                filename = path.split("/")[-1] or None
        result["filename"] = filename

        result["is_html"] = "text/html" in ctype
        result["is_json"] = "application/json" in ctype or ("+json" in ctype)
        result["ok"] = True
        try:
            r.close()
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)
    return result

def add_default_user_agent(headers: dict, enabled: bool) -> dict:
    if not enabled:
        return headers
    if not any(k.lower() == "user-agent" for k in headers):
        headers = dict(headers)
        headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    return headers

def lang_highlight(lang: str) -> str:
    return {
        "Python": "python",
        "JavaScript (Node)": "javascript",
        "TypeScript (Node)": "typescript",
        "bash (curl)": "bash",
        "bash (wget)": "bash",
        "PowerShell": "powershell",
        "Java (Jsoup)": "java",
        "C# (HttpClient)": "csharp",
        "PHP": "php",
        "Ruby": "ruby",
        "Go": "go",
    }.get(lang, "text")

# ---------------------------
# Code templates (unchanged core)
# ---------------------------
TPLS = {}
# (… keep all your TPLS entries exactly as before …)
# For brevity in this snippet, paste your previous TPLS dict here unchanged.
# ---- START of TPLS paste ----
# === COPY ALL TEMPLATE DEFINITIONS FROM YOUR PRIOR VERSION ===
# ---- END of TPLS paste ----

def to_shell_headers_curl(headers: dict) -> str:
    parts = []
    for k, v in (headers or {}).items():
        parts.append(f"  -H '{k}: {v}' \\")
    return "\n".join(parts) if parts else ""

def to_shell_headers_wget(headers: dict) -> str:
    parts = []
    for k, v in (headers or {}).items():
        parts.append(f"  --header='{k}: {v}' \\")
    return "\n".join(parts) if parts else ""

def to_go_headers(headers: dict) -> str:
    lines = []
    for k, v in (headers or {}).items():
        safe_k = k.replace('"', '\\"')
        safe_v = v.replace('"', '\\"')
        lines.append(f'    "{safe_k}": "{safe_v}",')
    return "\n".join(lines)

def default_filename_from_probe(url: str, probe: dict) -> str:
    if probe and probe.get("filename"):
        return probe["filename"]
    path = urlparse(url).path
    if path and path != "/":
        guess = path.split("/")[-1]
        if guess:
            return guess
    return "download.bin"

def choose_task(auto_task: str, probe: dict) -> str:
    if auto_task != "Auto-detect from URL":
        return auto_task
    if not probe or not probe.get("ok"):
        return "Fetch JSON/API"
    if probe.get("is_json"):
        return "Fetch JSON/API"
    if probe.get("is_html"):
        return "Scrape main text (HTML)"
    return "Download file (binary)"

def generate_script(language: str, task: str, url: str, headers: dict, timeout: int, filename: str) -> str:
    key = (language, task)
    if key not in TPLS:
        if (language, "Fetch JSON/API") in TPLS:
            key = (language, "Fetch JSON/API")
        else:
            language = "Python"
            key = (language, "Fetch JSON/API")
    tpl = TPLS[key]
    code = tpl
    code = code.replace("%%URL%%", url)
    code = code.replace("%%TIMEOUT%%", str(timeout))
    code = code.replace("%%FILENAME%%", filename)
    code = code.replace("%%HEADERS_JSON%%", json.dumps(headers or {}, indent=2))
    code = code.replace("%%CURL_HEADERS%%", to_shell_headers_curl(headers))
    code = code.replace("%%WGET_HEADERS%%", to_shell_headers_wget(headers))
    code = code.replace("%%GO_HEADERS%%", to_go_headers(headers))
    return code

# ---------------------------
# NEW: Extraction utilities (to CSV/XLSX)
# ---------------------------
def fetch_json_to_df(url: str, headers: dict, timeout: int) -> pd.DataFrame:
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    try:
        data = r.json()
    except Exception:
        # if it isn't valid JSON, return raw
        return pd.DataFrame({"raw_text": [r.text]})
    # Try to normalize into a flat table
    if isinstance(data, list):
        try:
            return pd.json_normalize(data)
        except Exception:
            return pd.DataFrame({"value": data})
    elif isinstance(data, dict):
        # If dict has a single large list key, normalize that list
        big_list_key = None
        for k, v in data.items():
            if isinstance(v, list) and len(v) >= 1:
                big_list_key = k
                break
        if big_list_key is not None:
            try:
                return pd.json_normalize(data[big_list_key])
            except Exception:
                pass
        try:
            return pd.json_normalize(data)
        except Exception:
            return pd.DataFrame([data])
    else:
        return pd.DataFrame({"value": [data]})

def scrape_text_to_df(url: str, headers: dict, timeout: int) -> pd.DataFrame:
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "lxml")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = " ".join(soup.get_text(separator=" ").split())
    # split into ~sentences/short chunks for tabular export
    chunks = re.split(r"(?<=[.?!])\s+", text)
    chunks = [c for c in chunks if c]
    return pd.DataFrame({"text": chunks})

def extract_links_to_df(url: str, headers: dict, timeout: int) -> pd.DataFrame:
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "lxml")
    out = []
    for a in soup.find_all("a", href=True):
        href = urljoin(url, a["href"])
        txt = " ".join((a.get_text() or "").split())
        out.append({"text": txt, "href": href})
    # De-duplicate by href + text
    df = pd.DataFrame(out)
    if not df.empty:
        df = df.drop_duplicates(subset=["href", "text"]).reset_index(drop=True)
    return df

def df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8-sig")

def df_to_xlsx_bytes(df: pd.DataFrame, sheet_name: str = "Data") -> bytes:
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
        df.to_excel(writer, sheet_name=sheet_name, index=False)
        # basic auto-width
        ws = writer.sheets[sheet_name]
        for i, col in enumerate(df.columns):
            width = min(60, max(10, int(df[col].astype(str).map(len).max() if not df.empty else 10)))
            ws.set_column(i, i, width)
    buf.seek(0)
    return buf.read()

# ---------------------------
# Sidebar
# ---------------------------
with st.sidebar:
    st.subheader("Options")
    language = st.selectbox("Output language", LANGUAGES, index=0)
    task_choice = st.selectbox("Task", TASKS, index=0)
    timeout = st.slider("HTTP timeout (seconds)", 5, 120, 30)
    add_ua = st.checkbox("Add browser-like User-Agent", value=True)
    headers_text = st.text_area("Custom headers (one per line: Key: Value)", placeholder="Authorization: Bearer YOUR_TOKEN\nAccept-Language: en-US")
    st.markdown("---")
    st.caption("⚖️ Please respect site Terms & robots.txt. Only scrape content you’re permitted to access.")

# ---------------------------
# Main Form
# ---------------------------
url = st.text_input("Paste URL", placeholder="https://example.com/api or https://example.com/page")
colA, colB, colC = st.columns([1, 1, 1])
with colA:
    analyze = st.button("🔎 Analyze URL")
with colB:
    generate = st.button("⚙️ Generate Script")
with colC:
    extract = st.button("📥 Extract & Preview (CSV/XLSX)")

probe = None
headers = None

if url.strip():
    # parse and merge headers once
    headers = parse_headers_input(headers_text or "")
    headers = add_default_user_agent(headers, add_ua)

if analyze and url.strip():
    with st.spinner("Probing URL..."):
        probe = probe_url(url.strip(), timeout=timeout, headers=headers)
    st.subheader("URL Probe")
    st.json(probe or {"ok": False})

if generate and url.strip():
    probe = probe_url(url.strip(), timeout=timeout, headers=headers)
    decided_task = choose_task(task_choice, probe)
    filename_guess = default_filename_from_probe(url.strip(), probe)
    code = generate_script(language, decided_task, url.strip(), headers or {}, timeout, filename_guess)
    st.success(f"Generated → {language} · {decided_task}")
    st.code(code, language=lang_highlight(language), line_numbers=True)
    st.download_button(
        "💾 Download Script",
        data=code.encode("utf-8"),
        file_name=f"generated{EXT_MAP.get(language, '.txt')}",
        mime="text/plain",
    )
    with st.expander("Detection & Notes", expanded=False):
        st.write({
            "decided_task": decided_task,
            "suggested_filename": filename_guess,
            "probe": probe
        })

# ---------------------------
# NEW: Extract & Export workflow
# ---------------------------
if extract and url.strip():
    st.subheader("Extracted Data Preview")
    with st.spinner("Fetching & parsing…"):
        # Decide extraction path using task selection or probe
        probe = probe_url(url.strip(), timeout=timeout, headers=headers)
        decided_task = choose_task(task_choice, probe)

        df = None
        note = ""
        try:
            if decided_task in ["Auto-detect from URL", "Fetch JSON/API"]:
                df = fetch_json_to_df(url.strip(), headers or {}, timeout)
                note = "Parsed JSON into a flat table where possible."
            elif decided_task == "Extract links (HTML)":
                df = extract_links_to_df(url.strip(), headers or {}, timeout)
                note = "Extracted anchor text and absolute links from HTML."
            elif decided_task == "Scrape main text (HTML)":
                df = scrape_text_to_df(url.strip(), headers or {}, timeout)
                note = "Scraped main page text and split into sentence-like chunks."
            else:
                note = "This looks like a file download. No tabular extraction was performed."
        except Exception as e:
            st.error(f"Extraction failed: {e}")
            df = None

    if df is not None:
        st.caption(note)
        st.dataframe(df.head(500))  # preview
        # Downloads
        csv_bytes = df_to_csv_bytes(df)
        xlsx_bytes = df_to_xlsx_bytes(df)
        c1, c2 = st.columns(2)
        with c1:
            st.download_button(
                "⬇️ Download CSV",
                data=csv_bytes,
                file_name="extracted_data.csv",
                mime="text/csv",
            )
        with c2:
            st.download_button(
                "⬇️ Download Excel (XLSX)",
                data=xlsx_bytes,
                file_name="extracted_data.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
    else:
        st.info("No tabular data to export. Try **Fetch JSON/API**, **Extract links (HTML)**, or **Scrape main text (HTML)**.")
