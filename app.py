# app.py
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
# Code templates
# ---------------------------
TPLS: dict[tuple[str, str], str] = {}

# ---- Python ----
TPLS[("Python", "Fetch JSON/API")] = """\
import requests, json

url = "%%URL%%"
headers = %%HEADERS_JSON%%
timeout = %%TIMEOUT%%

r = requests.get(url, headers=headers, timeout=timeout)
r.raise_for_status()
data = r.json()
print(json.dumps(data, indent=2, ensure_ascii=False))
"""

TPLS[("Python", "Scrape main text (HTML)")] = """\
import requests
from bs4 import BeautifulSoup

url = "%%URL%%"
headers = %%HEADERS_JSON%%
timeout = %%TIMEOUT%%

r = requests.get(url, headers=headers, timeout=timeout)
r.raise_for_status()

soup = BeautifulSoup(r.text, "lxml")
for tag in soup(["script","style","noscript"]):
    tag.decompose()

text = " ".join(soup.get_text(separator=" ").split())
print(text[:2000])
"""

TPLS[("Python", "Extract links (HTML)")] = """\
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

url = "%%URL%%"
headers = %%HEADERS_JSON%%
timeout = %%TIMEOUT%%

r = requests.get(url, headers=headers, timeout=timeout)
r.raise_for_status()

soup = BeautifulSoup(r.text, "lxml")
links = []
for a in soup.find_all("a", href=True):
    links.append(urljoin(url, a["href"]))

for link in sorted(set(links)):
    print(link)
"""

TPLS[("Python", "Download file (binary)")] = """\
import requests

url = "%%URL%%"
outfile = "%%FILENAME%%"
headers = %%HEADERS_JSON%%
timeout = %%TIMEOUT%%

with requests.get(url, headers=headers, stream=True, timeout=timeout) as r:
    r.raise_for_status()
    with open(outfile, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
print(f"Saved to {outfile}")
"""

# ---- JavaScript (Node) ----
TPLS[("JavaScript (Node)", "Fetch JSON/API")] = """\
/* npm i axios */
const axios = require("axios");

const url = "%%URL%%";
const headers = %%HEADERS_JSON%%;
const timeout = %%TIMEOUT%% * 1000;

axios.get(url, { headers, timeout })
  .then(res => console.log(JSON.stringify(res.data, null, 2)))
  .catch(err => { console.error(err.message); process.exit(1); });
"""

TPLS[("JavaScript (Node)", "Scrape main text (HTML)")] = """\
/* npm i axios cheerio */
const axios = require("axios");
const cheerio = require("cheerio");

const url = "%%URL%%";
const headers = %%HEADERS_JSON%%;
const timeout = %%TIMEOUT%% * 1000;

axios.get(url, { headers, timeout })
  .then(res => {
    const $ = cheerio.load(res.data);
    $("script,style,noscript").remove();
    const text = $("body").text().replace(/\\s+/g, " ").trim();
    console.log(text.slice(0, 2000));
  })
  .catch(err => { console.error(err.message); process.exit(1); });
"""

TPLS[("JavaScript (Node)", "Extract links (HTML)")] = """\
/* npm i axios cheerio */
const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");

const url = "%%URL%%";
const headers = %%HEADERS_JSON%%;
const timeout = %%TIMEOUT%% * 1000;

axios.get(url, { headers, timeout })
  .then(res => {
    const $ = cheerio.load(res.data);
    const base = new URL(url);
    const set = new Set();
    $("a[href]").each((_, a) => {
      try {
        const link = new URL($(a).attr("href"), base).href;
        set.add(link);
      } catch {}
    });
    [...set].sort().forEach(l => console.log(l));
  })
  .catch(err => { console.error(err.message); process.exit(1); });
"""

TPLS[("JavaScript (Node)", "Download file (binary)")] = """\
/* npm i axios */
const fs = require("fs");
const axios = require("axios");

const url = "%%URL%%";
const outfile = "%%FILENAME%%";
const headers = %%HEADERS_JSON%%;
const timeout = %%TIMEOUT%% * 1000;

axios.get(url, { headers, responseType: "stream", timeout })
  .then(res => {
    const writer = fs.createWriteStream(outfile);
    res.data.pipe(writer);
    writer.on("finish", () => console.log(`Saved to ${outfile}`));
    writer.on("error", err => { console.error(err); process.exit(1); });
  })
  .catch(err => { console.error(err.message); process.exit(1); });
"""

# ---- TypeScript (Node) ----
TPLS[("TypeScript (Node)", "Fetch JSON/API")] = """\
// npm i axios @types/node
import axios from "axios";

const url = "%%URL%%";
const headers = %%HEADERS_JSON%% as Record<string,string>;
const timeout = %%TIMEOUT%% * 1000;

(async () => {
  try {
    const res = await axios.get(url, { headers, timeout });
    console.log(JSON.stringify(res.data, null, 2));
  } catch (e:any) {
    console.error(e.message);
    process.exit(1);
  }
})();
"""

# ---- bash curl / wget ----
TPLS[("bash (curl)", "Fetch JSON/API")] = """\
#!/usr/bin/env bash
set -euo pipefail
curl -sSL -m %%TIMEOUT%% \\
%%CURL_HEADERS%% \\
  "%%URL%%"
"""

TPLS[("bash (curl)", "Download file (binary)")] = """\
#!/usr/bin/env bash
set -euo pipefail
curl -L --max-time %%TIMEOUT%% \\
%%CURL_HEADERS%% \\
  -o "%%FILENAME%%" "%%URL%%"
echo "Saved to %%FILENAME%%"
"""

TPLS[("bash (wget)", "Download file (binary)")] = """\
#!/usr/bin/env bash
set -euo pipefail
wget --timeout=%%TIMEOUT%% --trust-server-names \\
%%WGET_HEADERS%% \\
  -O "%%FILENAME%%" "%%URL%%"
echo "Saved to %%FILENAME%%"
"""

# ---- PowerShell ----
TPLS[("PowerShell", "Fetch JSON/API")] = """\
$Url = "%%URL%%"
$Headers = %%HEADERS_JSON%%
$Response = Invoke-RestMethod -Uri $Url -Headers $Headers -TimeoutSec %%TIMEOUT%%
$Response | ConvertTo-Json -Depth 10
"""

TPLS[("PowerShell", "Download file (binary)")] = """\
$Url = "%%URL%%"
$OutFile = "%%FILENAME%%"
$Headers = %%HEADERS_JSON%%
Invoke-WebRequest -Uri $Url -Headers $Headers -OutFile $OutFile -TimeoutSec %%TIMEOUT%%
Write-Host "Saved to $OutFile"
"""

# ---- Java (Jsoup) ----
TPLS[("Java (Jsoup)", "Scrape main text (HTML)")] = """\
/*
Dependencies (Maven):
  org.jsoup:jsoup:1.17.2
*/
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

public class Scrape {
  public static void main(String[] args) throws Exception {
    String url = "%%URL%%";
    Document doc = Jsoup.connect(url)
      .timeout(%%TIMEOUT%% * 1000)
      .header("User-Agent", "Mozilla/5.0")
      .get();
    String text = doc.text();
    System.out.println(text.substring(0, Math.min(2000, text.length())));
  }
}
"""

# ---- C# (HttpClient) ----
TPLS[("C# (HttpClient)", "Fetch JSON/API")] = """\
using System;
using System.Net.Http;
using System.Threading.Tasks;

class Fetch {
  static async Task Main() {
    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(%%TIMEOUT%%) };
    var req = new HttpRequestMessage(HttpMethod.Get, "%%URL%%");
    var headers = %%HEADERS_JSON%%;
    foreach (var kv in headers) {
      req.Headers.TryAddWithoutValidation(kv.Key, kv.Value.ToString());
    }
    var res = await http.SendAsync(req);
    res.EnsureSuccessStatusCode();
    var body = await res.Content.ReadAsStringAsync();
    Console.WriteLine(body);
  }
}
"""

# ---- PHP ----
TPLS[("PHP", "Fetch JSON/API")] = """\
<?php
$ch = curl_init("%%URL%%");
$headers = [];
$h = %%HEADERS_JSON%%;
foreach ($h as $k => $v) { $headers[] = $k . ": " . $v; }
curl_setopt_array($ch, [
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_HTTPHEADER => $headers,
  CURLOPT_TIMEOUT => %%TIMEOUT%%,
]);
$resp = curl_exec($ch);
if ($resp === false) { throw new Exception(curl_error($ch)); }
echo $resp;
"""

# ---- Ruby ----
TPLS[("Ruby", "Fetch JSON/API")] = """\
require "net/http"
require "uri"
require "json"

url = URI.parse("%%URL%%")
req = Net::HTTP::Get.new(url)
headers = %%HEADERS_JSON%%
headers.each { |k,v| req[k] = v }

http = Net::HTTP.new(url.host, url.port)
http.use_ssl = url.scheme == "https"
http.read_timeout = %%TIMEOUT%%
res = http.request(req)
puts res.body
"""

# ---- Go ----
TPLS[("Go", "Fetch JSON/API")] = """\
package main

import (
  "fmt"
  "io"
  "net/http"
  "time"
)

func main() {
  url := "%%URL%%"
  client := &http.Client{ Timeout: time.Second * %%TIMEOUT%% }
  req, _ := http.NewRequest("GET", url, nil)
  headers := map[string]string{
%%GO_HEADERS%%
  }
  for k, v := range headers {
    req.Header.Set(k, v)
  }
  resp, err := client.Do(req)
  if err != nil { panic(err) }
  defer resp.Body.Close()
  b, _ := io.ReadAll(resp.Body)
  fmt.Println(string(b))
}
"""

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
    """
    Safer template lookup with fallbacks:
      1) (language, task)
      2) (language, 'Fetch JSON/API')
      3) ('Python', 'Fetch JSON/API')
    """
    fallback_order = [
        (language, task),
        (language, "Fetch JSON/API"),
        ("Python", "Fetch JSON/API"),
    ]
    tpl = None
    used_lang, used_task = language, task
    for k in fallback_order:
        if k in TPLS:
            tpl = TPLS[k]
            used_lang, used_task = k
            break
    if tpl is None:
        # last-ditch minimal template to prevent crashes
        tpl = 'import requests; r=requests.get("%%URL%%", headers=%%HEADERS_JSON%%, timeout=%%TIMEOUT%%); print(r.status_code); print(r.text[:2000])'
        used_lang = "Python"
        used_task = "Fetch JSON/API"

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
# Extraction utilities (CSV/XLSX)
# ---------------------------
def fetch_json_to_df(url: str, headers: dict, timeout: int) -> pd.DataFrame:
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    try:
        data = r.json()
    except Exception:
        return pd.DataFrame({"raw_text": [r.text]})
    if isinstance(data, list):
        try:
            return pd.json_normalize(data)
        except Exception:
            return pd.DataFrame({"value": data})
    elif isinstance(data, dict):
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
    chunks = re.split(r"(?<=[.?!])\\s+", text)
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
    headers_text = st.text_area("Custom headers (one per line: Key: Value)", placeholder="Authorization: Bearer YOUR_TOKEN\\nAccept-Language: en-US")
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
# Extract & Export workflow
# ---------------------------
if extract and url.strip():
    st.subheader("Extracted Data Preview")
    with st.spinner("Fetching & parsing…"):
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
        st.dataframe(df.head(500))
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
