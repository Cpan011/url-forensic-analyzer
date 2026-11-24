import json
from datetime import datetime
from html import escape

import pandas as pd
import streamlit as st

from analyzer.report import build_pdf
from analyzer.scoring import BENIGN_MAX, SUSPICIOUS_MAX, TOOL_NAME, TOOL_VERSION, run_analysis

st.set_page_config(page_title="URL Forensic Analyzer", layout="centered")


HEADLINE = {
    "Phishing": "Phishing",
    "Malware": "Malware",
    "Phishing & Malware": "Phishing and malware",
    "Undetermined": "Risky, type unclear",
    "No threat detected": "No threat detected",
}

TAB_NAMES = {"Lexical": "URL structure", "WHOIS": "WHOIS", "SSL/TLS": "Certificate",
             "Threat intel": "VirusTotal"}

st.markdown("""
<style>
[data-testid="stDecoration"] {display: none;}
h1 {font-size: 1.7rem !important; font-weight: 600 !important;}
.result {border: 1px solid #D1D9E0; border-top: 4px solid #16A34A; border-radius: 6px;
         padding: 16px 20px 4px; margin: 4px 0 20px; background: #FFFFFF;}
.result .kicker {font-size: .8rem; color: #59636E; margin: 0;}
.result .verdict {font-size: 1.6rem; font-weight: 600; color: #16A34A !important; margin: 2px 0 4px; line-height: 1.25;}
.result .desc {margin: 0 0 14px; color: #1F2328;}
.result .row {display: grid; grid-template-columns: 34% 1fr; gap: 12px; padding: 7px 0;
              border-top: 1px solid #EAEEF2; font-size: .92rem;}
.result .row .k {color: #59636E;}
.result .row .v {color: #1F2328; overflow-wrap: anywhere;}
.result .mono {font-family: ui-monospace, Consolas, monospace; font-size: .85rem;}
.result .note {font-size: .85rem; color: #59636E; margin: 10px 0 12px;}
.result h4 {font-size: .95rem; font-weight: 600; margin: 14px 0 4px; padding: 0; color: #1F2328 !important;}
.result ul {margin: 0 0 14px; padding-left: 1.1rem; font-size: .92rem;}
.result li {margin: 3px 0; color: #1F2328 !important;}
/* Card colours: green = no threat, bright red = suspicious or malicious */
.result.safe {border-top-color: #16A34A;}
.result.safe .verdict {color: #16A34A !important;}
.result.threat {border-top-color: #E5251B;}
.result.threat .verdict {color: #E5251B !important;}
</style>
""", unsafe_allow_html=True)


def _secret_key() -> str:
    try:
        return st.secrets.get("VT_API_KEY", "")
    except Exception:
        return ""


def _row(label: str, value: str, mono: bool = False) -> str:
    cls = "v mono" if mono else "v"
    return f'<div class="row"><div class="k">{escape(label)}</div><div class="{cls}">{escape(value)}</div></div>'


def _colour(threat_type: str, verdict: str) -> str:
    """CSS class for the result card: 'safe' (green) or 'threat' (bright red)."""
    if threat_type == "No threat detected":
        return "safe"
    return "threat"     # Suspicious or Malicious


def _domain_age(vectors: dict) -> str:
    block = vectors.get("WHOIS")
    if not block:
        return "Not checked"
    data = block["data"]
    if block["status"] == "skipped":
        if "IP address" in data.get("note", ""):
            return "Not used for an IP address"
        return "Not used: the page is on a shared hosting platform"
    age = data.get("domain_age_days")
    if age is None:
        return "Unknown"
    years = f" (about {age // 365} years)" if age >= 365 else ""
    return f"{age:,} days{years}"


def _certificate(vectors: dict) -> str:
    block = vectors.get("SSL/TLS")
    if not block:
        return "Not checked"
    if block["status"] == "skipped":
        return "Not checked (private address)"
    if block["status"] == "error":
        return "No HTTPS certificate"
    data = block["data"]
    issuer = data.get("issuer_org") or data.get("issuer_cn") or "unknown issuer"
    return f"Trusted, issued by {issuer}" if data.get("trusted_by_system_store") else "Not trusted"


def _virustotal(vectors: dict) -> str:
    block = vectors.get("Threat intel")
    if not block:
        return "Not checked"
    data = block["data"]
    if block["status"] != "ok":
        return "Not checked: " + (data.get("error") or data.get("note") or "turned off")
    stats = data.get("stats")
    if not stats:
        return data.get("note", "No result yet")
    return f"{stats.get('malicious', 0)} of {data.get('engines_total', 0)} vendors flag it as malicious"


def _rows_for(block: dict) -> pd.DataFrame:
    rows = []
    for key, value in block["data"].items():
        if key in ("note", "error"):
            continue
        if isinstance(value, dict):
            value = ", ".join(f"{k}: {v}" for k, v in value.items())
        elif isinstance(value, (list, tuple)):
            value = ", ".join(map(str, value))
        rows.append({"Field": key.replace("_", " ").capitalize(),
                     "Value": "-" if value in (None, "") else str(value)})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- Dark mode
# Extra CSS layered on top of the light theme in .streamlit/config.toml when the
# "Dark mode" switch is on. Each visitor has their own switch.
DARK_CSS = """
<style>
[data-testid="stApp"], [data-testid="stHeader"], [data-testid="stBottomBlockContainer"]
    {background: #0E1117 !important; color: #E6EDF3;}
[data-testid="stApp"] h1, [data-testid="stApp"] h2, [data-testid="stApp"] h3,
[data-testid="stApp"] p, [data-testid="stApp"] label, [data-testid="stApp"] li,
[data-testid="stApp"] summary, [data-testid="stApp"] summary span,
[data-testid="stWidgetLabel"] p, [data-testid="stMarkdownContainer"] {color: #E6EDF3;}
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p {color: #8B949E !important;}
[data-baseweb="input"], [data-baseweb="input"] > div, [data-baseweb="input"] input,
[data-baseweb="base-input"] {background: #161B22 !important; color: #E6EDF3 !important;
    border-color: #30363D !important;}
[data-baseweb="input"] input::placeholder {color: #6E7681 !important;}
[data-testid="stExpander"] details {background: #161B22; border-color: #30363D;}
[data-testid="stExpander"] summary:hover {background: #1C2128;}
[data-testid="stBaseButton-secondary"] {background: #21262D !important; color: #E6EDF3 !important;
    border-color: #30363D !important;}
[data-testid="stBaseButton-secondary"]:hover {border-color: #8B949E !important;}
[data-baseweb="tab-list"] button p {color: #8B949E;}
[data-baseweb="tab-list"] button[aria-selected="true"] p {color: #E6EDF3;}
[data-baseweb="tab-border"] {background: #30363D !important;}
[data-testid="stCode"] pre, [data-testid="stCode"] code {background: #161B22 !important;
    color: #E6EDF3 !important;}
[data-testid="stJson"] {background: #161B22 !important; filter: invert(0.88) hue-rotate(180deg);}
[data-testid="stDataFrame"], [data-testid="stTable"] {filter: invert(0.9) hue-rotate(180deg);}
[data-testid="stStatusWidget"], [data-testid="stExpanderDetails"] {color: #E6EDF3;}
[data-testid="stCheckbox"] span {border-color: #6E7681;}
/* Result card */
.result {background: #161B22 !important; border-color: #30363D !important;}
.result .kicker, .result .row .k, .result .note {color: #8B949E !important;}
.result .desc, .result .row .v, .result h4, .result li {color: #E6EDF3 !important;}
.result .row {border-top-color: #30363D !important;}
.result.safe {border-top-color: #3FB950 !important;}
.result.safe .verdict {color: #3FB950 !important;}
.result.threat {border-top-color: #FF4D4D !important;}
.result.threat .verdict {color: #FF4D4D !important;}
</style>
"""

_, toggle_col = st.columns([3, 1])
dark_mode = toggle_col.toggle("Dark mode", value=True, key="dark_mode")
if dark_mode:
    st.markdown(DARK_CSS, unsafe_allow_html=True)


if "history" not in st.session_state:
    st.session_state.history = []
if "case_ref" not in st.session_state:
    st.session_state.case_ref = f"CASE-{datetime.now():%Y%m%d-%H%M}"

# ---------------------------------------------------------------- Input
st.title("Phishing and Malicious URL Forensic Analyzer")
st.write("Check a suspicious link for phishing or malware. The page itself is never opened.")

with st.form("scan", border=False):
    col_url, col_btn = st.columns([5, 1], vertical_alignment="bottom")
    raw_url = col_url.text_input("Link to check", placeholder="https://example.com/login")
    submitted = col_btn.form_submit_button("Analyze", type="primary", use_container_width=True)

stored_key = _secret_key()
with st.expander("Settings and case details", expanded=False):
    c1, c2 = st.columns(2)
    case_ref = c1.text_input("Case reference", key="case_ref")
    examiner = c2.text_input("Examiner", placeholder="Your name")
    st.write("Checks to run")
    k1, k2 = st.columns(2)
    use_whois = k1.checkbox("WHOIS domain age", value=True)
    use_ssl = k1.checkbox("SSL/TLS certificate", value=True)
    use_ti = k2.checkbox("VirusTotal", value=True)
    use_expand = k2.checkbox("Reveal short-link destination", value=True)
    if stored_key:
        vt_key = stored_key
        st.caption("VirusTotal API key loaded from .streamlit/secrets.toml.")
    else:
        vt_key = st.text_input("VirusTotal API key", type="password",
                               help="Free key from virustotal.com, under your profile > API key.")

if submitted:
    url_text = raw_url.strip()
    if not url_text or " " in url_text:
        st.error("Enter one link without spaces, for example https://example.com.")
    else:
        with st.status("Analyzing...", expanded=False) as status:
            record = run_analysis(url_text, vt_key=vt_key, case_ref=case_ref, examiner=examiner,
                                  enable_whois=use_whois, enable_ssl=use_ssl, enable_ti=use_ti,
                                  expand_short_links=use_expand, progress=st.write)
            status.update(label="Analysis complete", state="complete")
        st.session_state.record = record
        st.session_state.history.insert(0, {
            "Time (UTC)": record["case"]["finished_utc"][11:19],
            "Link (defanged)": record["target"]["defanged_url"],
            "Result": record["assessment"]["threat_type"],
            "Risk": f"{record['assessment']['verdict']} ({record['assessment']['score']})",
        })

record = st.session_state.get("record")

# ---------------------------------------------------------------- Result
if record:
    a = record["assessment"]
    cls = a["classification"]
    vectors = record["vectors"]
    target = record["target"]
    colour = _colour(cls["threat_type"], a["verdict"])

    rows = [_row("Risk level", f"{a['verdict']} ({a['score']} out of 100)")]
    if cls["confidence"] != "-":
        rows.append(_row("Confidence", cls["confidence"]))
    rows.append(_row("Link checked", target["defanged_url"], mono=True))
    if len(target.get("redirect_chain") or []) > 1:
        rows.append(_row("Short link leads to", target["analyzed_url"], mono=True))
    elif target.get("redirect_note"):
        rows.append(_row("Short link", target["redirect_note"]))
    rows.append(_row("Domain age", _domain_age(vectors)))
    rows.append(_row("Certificate", _certificate(vectors)))
    rows.append(_row("VirusTotal", _virustotal(vectors)))

    reasons = [f for f in a["indicators"] if f["points"] > 0][:5]
    if reasons:
        reason_html = "<h4>Main reasons</h4><ul>" + "".join(
            f"<li><b>{escape(f['check'])}.</b> {escape(f['detail'])}</li>" for f in reasons) + "</ul>"
    else:
        reason_html = ""

    description = cls["description"]
    if cls["threat_type"] == "No threat detected":
        description = "No phishing or malware signs were found in this link."
    notes = []
    if a.get("override"):
        notes.append(a["override"])
    if vectors.get("Threat intel", {}).get("status") != "ok":
        notes.append("VirusTotal was not used, so this result relies on the link's structure, domain and "
                     "certificate only. A brand-new scam link can still look clean.")
    elif cls["threat_type"] == "No threat detected":
        notes.append("This is not a guarantee. Stay careful with links you did not expect.")
    note_html = "".join(f'<p class="note">{escape(n)}</p>' for n in notes)

    st.markdown(
        f'<div class="result {colour}">'
        f'<p class="kicker">Result</p>'
        f'<p class="verdict">{escape(HEADLINE[cls["threat_type"]])}</p>'
        f'<p class="desc">{escape(description)}</p>'
        + "".join(rows) + reason_html + note_html + "</div>",
        unsafe_allow_html=True)

    stamp = record["case"]["examination_id"][:8]
    d1, d2 = st.columns(2)
    d1.download_button("Download PDF report", build_pdf(record), file_name=f"url-report-{stamp}.pdf",
                       mime="application/pdf", use_container_width=True)
    d2.download_button("Download JSON evidence", json.dumps(record, indent=2, default=str).encode(),
                       file_name=f"url-evidence-{stamp}.json", mime="application/json",
                       use_container_width=True)

    st.subheader("Details")
    tabs = st.tabs(["All indicators"] + [TAB_NAMES.get(n, n) for n in vectors] + ["Evidence"])

    with tabs[0]:
        if a["indicators"]:
            df = pd.DataFrame(a["indicators"])[["check", "detail", "points", "vector"]]
            df.columns = ["Indicator", "Detail", "Points", "Check"]
            st.dataframe(df, hide_index=True, use_container_width=True,
                         column_config={"Detail": st.column_config.TextColumn(width="large")})
        else:
            st.write("No indicators were raised.")
        st.write(f"Phishing evidence score: {cls['phishing_score']} out of 100. "
                 f"Malware evidence score: {cls['malware_score']} out of 100.")
        if cls["evidence"]:
            ev = pd.DataFrame(cls["evidence"])[["type", "reason", "points"]]
            ev.columns = ["Points to", "Evidence", "Weight"]
            st.dataframe(ev, hide_index=True, use_container_width=True)
        st.caption(f"Score bands: 0 to {BENIGN_MAX} benign, {BENIGN_MAX + 1} to {SUSPICIOUS_MAX} suspicious, "
                   f"{SUSPICIOUS_MAX + 1} to 100 malicious.")

    for tab, (name, block) in zip(tabs[1:-1], vectors.items()):
        with tab:
            if block["status"] == "skipped":
                st.write("Skipped. " + block["data"].get("note", ""))
            elif block["status"] == "error":
                st.write("Could not complete. " + block["data"].get("error", ""))
            table = _rows_for(block)
            if not table.empty:
                st.dataframe(table, hide_index=True, use_container_width=True)
            if name == "Threat intel" and block["data"].get("permalink"):
                st.link_button("Open the full VirusTotal report", block["data"]["permalink"])

    with tabs[-1]:
        st.write("SHA-256 hash of the evidence record. Hashing the JSON file again must give the same value.")
        st.code(record["integrity"]["evidence_hash"], language=None)
        st.json(record, expanded=False)
else:
    st.caption("Example to try: http://paypa1-secure-login.xyz/verify/account")

if st.session_state.history:
    with st.expander(f"Links checked this session ({len(st.session_state.history)})"):
        st.dataframe(pd.DataFrame(st.session_state.history), hide_index=True, use_container_width=True)

st.caption(f"{TOOL_NAME}, version {TOOL_VERSION}. Checks the link text, WHOIS, the TLS certificate, "
           "short-link redirects and VirusTotal without loading the page.")
