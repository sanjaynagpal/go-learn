"""Build the PDF versions of the code-signing docs, for readers who don't use Markdown.

    python tools/build_pdfs.py              # the three Test-Executable*.md docs
    python tools/build_pdfs.py --playbook   # also docs/Windows-code-signing.pdf from the playbook HTML

Each Markdown file is rendered into a printable HTML page (marked + mermaid from cdnjs, IBM Plex
fonts from Google Fonts), then printed to A4 PDF by Microsoft Edge (or Chrome) in headless mode.
Needs Windows, Python 3.9+, Edge or Chrome, and internet access for the libraries and fonts.

What the PDFs get that the Markdown doesn't:
  - a title block and a "How to run the script" box on page 1
  - "Page X of Y" footers
  - links to other docs written as "(in Other.pdf)" instead of a link that would break on the
    reader's PC (and carry a local path)
  - left-to-right Mermaid flowcharts drawn top to bottom, so they stay readable at page width
  - invisible text-direction characters shown as visible [U+202E] markers
"""
import argparse
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent                               # the code-signing folder

DOCS = {
    "Test-ExecutableSafety": "Combined safety check for a downloaded Windows program",
    "Test-ExecutableSignature": "Signature and certificate check, with actions for the publisher",
    "Test-ExecutableEnvironment": "Local safety check for this PC, with actions for you and IT",
}
PLAYBOOK_HTML = ROOT / "docs" / "Windows Code Signing Playbook.html"
PLAYBOOK_PDF = ROOT / "docs" / "Windows-code-signing.pdf"

# Unicode bidi embedding/override/isolate characters (U+202A-U+202E, U+2066-U+2069).
BIDI = "".join(map(chr, [*range(0x202A, 0x202F), *range(0x2066, 0x206A)]))

TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>__TITLE__</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans+Condensed:wght@600;700&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;1,400&display=swap">
<script src="https://cdnjs.cloudflare.com/ajax/libs/marked/12.0.2/marked.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.9.1/mermaid.min.js"></script>
<style>
:root{--ink:#13212B;--muted:#4A5961;--line:#C9D3D8;--accent:#0B7A66;--accent-soft:#DCF0EA;--code:#EEF2F4;
  --f-display:"IBM Plex Sans Condensed","Arial Narrow",sans-serif;--f-body:"IBM Plex Sans","Segoe UI",sans-serif;--f-mono:"IBM Plex Mono",Consolas,monospace}
*{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}
@page{size:A4;margin:16mm 14mm 18mm;
  @bottom-left{content:"__TITLE__";font:8pt "IBM Plex Sans",sans-serif;color:#6B7A82}
  @bottom-right{content:"Page " counter(page) " of " counter(pages);font:8pt "IBM Plex Sans",sans-serif;color:#6B7A82}}
@page :first{@bottom-left{content:none}}
html{background:#fff}
body{margin:0;color:var(--ink);font:10pt/1.55 var(--f-body)}
.cover{border-bottom:2px solid var(--accent);padding-bottom:12px;margin-bottom:6px}
.eyebrow{font:500 7.5pt var(--f-mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.cover .sub{font-size:11.5pt;color:var(--muted);margin-top:4px}
.cover .meta{font-size:8pt;color:var(--muted);margin-top:8px}
h1,h2,h3,h4{font-family:var(--f-display);line-height:1.2;break-after:avoid;color:var(--ink)}
h1{font-size:24pt;margin:6px 0 0}
#doc>h1:first-child{display:none}
h2{font-size:15pt;margin:22px 0 8px;padding-top:6px;border-top:1px solid var(--line)}
h3{font-size:12pt;margin:16px 0 6px}
h4{font-size:10.5pt;margin:14px 0 4px}
p{margin:6px 0}
a{color:var(--accent);text-decoration:none}
ul,ol{margin:6px 0;padding-left:20px}
li{margin:3px 0}
code{font-family:var(--f-mono);font-size:8.6pt;background:var(--code);padding:.05em .3em;border-radius:3px;overflow-wrap:anywhere}
pre{background:var(--code);border-radius:6px;padding:9px 11px;margin:8px 0;white-space:pre-wrap;overflow-wrap:anywhere;break-inside:avoid;line-height:1.4}
pre code{background:none;padding:0;font-size:8pt}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:8.6pt}
th,td{border:1px solid var(--line);padding:5px 7px;text-align:left;vertical-align:top}
th{background:var(--code);font-weight:600}
tr{break-inside:avoid}
td code{font-size:8pt}
blockquote{margin:10px 0;padding:8px 12px;border-left:3px solid var(--accent);background:var(--accent-soft);border-radius:0 6px 6px 0}
blockquote p{margin:4px 0}
.mermaid{text-align:center;margin:10px 0;break-inside:avoid}
.mermaid svg{max-width:48%;height:auto}
.howto{border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin:12px 0 4px;background:#FAFBFC;break-inside:avoid}
.howto b{font-family:var(--f-display);font-size:11pt}
.howto ol{margin:6px 0 2px}
</style></head>
<body>
<div class="cover">
  <div class="eyebrow">Windows code signing · PowerShell check</div>
  <h1>__TITLE__</h1>
  <div class="sub">__SUBTITLE__</div>
  <div class="meta">Source: __SRC__ · Generated __DATE__</div>
</div>
<div class="howto"><b>How to run the script</b>
<ol>
  <li>Save <code>__TITLE__.ps1</code> to a folder on your PC, e.g. <code>Documents\Checks</code>.</li>
  <li>Open the Start menu, type <b>PowerShell</b> and open <b>Windows PowerShell</b>.</li>
  <li>Type the command below, with the path to the downloaded file you want to check, and press Enter:</li>
</ol>
<pre><code>powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Documents\Checks\__TITLE__.ps1" -Path "$env:USERPROFILE\Downloads\setup.exe"</code></pre>
The script only reads the file; it never runs it. The sections below explain every result and what to do about it.
</div>
<div id="doc"></div>
<script>
const MD = __MD__;
function slug(t){return t.toLowerCase().replace(/[`*_~]/g,'').replace(/[^\p{L}\p{N}_\- ]/gu,'').replace(/ /g,'-')}
const seen = {};
marked.use({gfm:true, renderer:{
  heading(text, level, raw){
    let s = slug(raw); if (seen[s] !== undefined){ seen[s]++; s += '-' + seen[s]; } else seen[s] = 0;
    return `<h${level} id="${s}">${text}</h${level}>`;
  },
  link(href, title, text){
    if (/^(https?:|mailto:|#)/.test(href)) return `<a href="${href}">${text}</a>`;
    // Links to other files can't work once the PDF is handed out: name the PDF instead.
    const file = decodeURI(href).replace(/#.*$/, '');
    const base = file.replace(/^.*\//, '').replace(/\.pdf$/, '');
    return text.includes(base) ? text : `${text} (in <i>${file}</i>)`;
  },
  code(code, lang){
    if ((lang||'').trim() === 'mermaid') return `<div class="mermaid">${code.replace(/</g,'&lt;')}</div>`;
    const esc = code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return `<pre><code>${esc}</code></pre>`;
  }
}});
document.getElementById('doc').innerHTML = marked.parse(MD);
mermaid.initialize({startOnLoad:false, theme:'neutral', securityLevel:'strict', fontFamily:'IBM Plex Sans, sans-serif'});
// Wait for the web fonts, or Mermaid measures labels with a fallback font and clips them.
document.fonts.ready.then(()=>mermaid.run({querySelector:'.mermaid'})).then(()=>{}, ()=>{document.title+=' (diagram error)'});
</script>
</body></html>
"""


def find_browser(explicit):
    if explicit:
        return explicit
    candidates = [
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    sys.exit("Edge or Chrome not found; pass --browser <path to msedge.exe or chrome.exe>")


def prepare_markdown(md):
    md = md.replace("flowchart LR", "flowchart TB")
    md = re.sub("[" + re.escape(BIDI) + "]", lambda m: "[U+%04X]" % ord(m.group(0)), md)
    md = re.sub(r"\((Test-Executable\w+)\.md(#[^)]*)?\)", r"(\1.pdf)", md)
    md = md.replace("(docs/Windows%20Code%20Signing%20Playbook.md)", "(docs/Windows-code-signing.pdf)")
    return md


def unlink_local_files(html):
    """Replace <a href="relative/file"> links with plain text naming the PDF.

    Chrome turns relative links into absolute file:/// links when printing, which break on the
    reader's PC and expose the local folder path. Web and in-page (#) links are kept.
    """
    def repl(m):
        href, text = m.group(1), m.group(2)
        if re.match(r"(https?:|mailto:|#)", href):
            return m.group(0)
        target = re.sub(r"#.*$", "", href).replace("../", "")
        target = re.sub(r"(Test-Executable\w+)\.md$", r"\1.pdf", target)
        base = re.sub(r"\.pdf$", "", target.rsplit("/", 1)[-1])
        text = re.sub(r"(Test-Executable\w+)\.md\b", r"\1.pdf", text)
        return text if base in text else f"{text} (in <i>{target}</i>)"
    return re.sub(r'<a\s+href="([^"]*)"\s*>(.*?)</a>', repl, html, flags=re.S)


def print_pdf(browser, profile, src, out):
    if out.exists():
        out.unlink()
    subprocess.run([browser, "--headless=new", "--disable-gpu", "--no-first-run",
                    f"--user-data-dir={profile}", "--no-pdf-header-footer",
                    "--virtual-time-budget=20000", f"--print-to-pdf={out}", src.as_uri()],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(120):                         # the browser may return before the file is written
        if out.exists() and out.stat().st_size > 0:
            break
        time.sleep(0.5)
    if not out.exists():
        sys.exit(f"Printing failed: {src.name}")
    data = out.read_bytes()
    pages = len(re.findall(rb"/Type\s*/Page[^s]", data))
    title = re.search(rb"/Title\s*\(([^)]*)\)", data)
    problems = []
    if b"diagram error" in data:
        problems.append("a Mermaid diagram failed to render")
    if str(pathlib.Path.home()).encode() in data or b"file:///" in data:
        problems.append("contains a local file link")
    return pages, (title.group(1).decode("latin-1") if title else "?"), problems


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--playbook", action="store_true", help="also rebuild docs/Windows-code-signing.pdf")
    ap.add_argument("--browser", help="path to msedge.exe or chrome.exe")
    args = ap.parse_args()

    browser = find_browser(args.browser)
    work = pathlib.Path(tempfile.mkdtemp(prefix="cs-pdf-"))
    failed = False
    try:
        today = datetime.date.today().isoformat()
        jobs = []
        for name, subtitle in DOCS.items():
            md = prepare_markdown((ROOT / f"{name}.md").read_text(encoding="utf-8"))
            html = (TEMPLATE.replace("__TITLE__", name).replace("__SUBTITLE__", subtitle)
                    .replace("__SRC__", f"{name}.md").replace("__DATE__", today)
                    .replace("__MD__", json.dumps(md).replace("</", "<\\/")))
            page = work / f"{name}.html"
            page.write_text(html, encoding="utf-8")
            jobs.append((page, ROOT / f"{name}.pdf"))
        if args.playbook:
            page = work / PLAYBOOK_HTML.name
            page.write_text(unlink_local_files(PLAYBOOK_HTML.read_text(encoding="utf-8")), encoding="utf-8")
            jobs.append((page, PLAYBOOK_PDF))

        for src, out in jobs:
            pages, title, problems = print_pdf(browser, work / "profile", src, out)
            note = "; ".join(problems) if problems else "ok"
            failed |= bool(problems)
            print(f"{out.relative_to(ROOT)}: {pages} pages, title '{title}' - {note}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
