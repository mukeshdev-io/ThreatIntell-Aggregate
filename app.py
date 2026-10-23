"""
app.py
──────
Streamlit dashboard for ThreatIntel Aggregator.

Features
────────
- Search box for single IoC lookup
- Coloured verdict card with score and per-source breakdown
- Bulk lookup via .txt file upload (one IoC per line)
- History table of past lookups
- Pie chart of verdict distribution
- CSV export of history

Run with:
    streamlit run app.py
"""

import io
import logging
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from config import VIRUSTOTAL_API_KEY, OTX_API_KEY
from database import get_cached, get_history, get_verdict_counts, init_db, save_lookup
from scoring import compute_score
from validators import validate_indicator
import vt_client
import otx_client

logger = logging.getLogger(__name__)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatIntel Aggregator",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Initialise DB on first run ────────────────────────────────────────────────
init_db()

# ── Colour palette ────────────────────────────────────────────────────────────
_VERDICT_BG = {
    "Low":    "#d4edda",
    "Medium": "#fff3cd",
    "High":   "#f8d7da",
}
_VERDICT_BORDER = {
    "Low":    "#28a745",
    "Medium": "#ffc107",
    "High":   "#dc3545",
}
_VERDICT_TEXT = {
    "Low":    "#155724",
    "Medium": "#856404",
    "High":   "#721c24",
}
_VERDICT_PIE_COLOURS = {
    "Low":    "#28a745",
    "Medium": "#ffc107",
    "High":   "#dc3545",
}


# ── Helper: run a single lookup ───────────────────────────────────────────────

def _run_lookup(indicator: str) -> dict[str, Any]:
    """Validate → cache-check → API → score → save. Returns result dict."""
    try:
        normalised, ioc_type = validate_indicator(indicator)
    except ValueError as exc:
        return {"error": str(exc), "indicator": indicator}

    # Cache check
    cached = get_cached(normalised)
    if cached:
        cached["from_cache"] = True
        return cached

    dispatch = {
        "ipv4":   (vt_client.lookup_ip,     otx_client.lookup_ip),
        "domain": (vt_client.lookup_domain, otx_client.lookup_domain),
        "md5":    (vt_client.lookup_hash,   otx_client.lookup_hash),
        "sha1":   (vt_client.lookup_hash,   otx_client.lookup_hash),
        "sha256": (vt_client.lookup_hash,   otx_client.lookup_hash),
    }
    vt_fn, otx_fn = dispatch[ioc_type]

    with st.spinner(f"Querying VirusTotal for {normalised}…"):
        vt_result = vt_fn(normalised)
    with st.spinner(f"Querying AlienVault OTX for {normalised}…"):
        otx_result = otx_fn(normalised)

    score, verdict = compute_score(vt_result, otx_result)
    save_lookup(normalised, ioc_type, vt_result, otx_result, score, verdict)

    return {
        "indicator":  normalised,
        "ioc_type":   ioc_type,
        "vt_result":  vt_result,
        "otx_result": otx_result,
        "score":      score,
        "verdict":    verdict,
        "from_cache": False,
    }


# ── Helper: render a result card ──────────────────────────────────────────────

def _render_result_card(result: dict[str, Any]) -> None:
    """Render a coloured verdict card plus source breakdown."""
    if "error" in result:
        st.error(f"⚠️ {result['error']}")
        return

    indicator  = result["indicator"]
    ioc_type   = result["ioc_type"]
    score      = result["score"]
    verdict    = result["verdict"]
    from_cache = result.get("from_cache", False)
    vt         = result.get("vt_result") or {}
    otx        = result.get("otx_result") or {}

    bg     = _VERDICT_BG[verdict]
    border = _VERDICT_BORDER[verdict]
    colour = _VERDICT_TEXT[verdict]
    cache_badge = " &nbsp;<small>(cached)</small>" if from_cache else ""

    # Verdict card
    st.markdown(
        f"""
        <div style="
            background:{bg};
            border-left:6px solid {border};
            border-radius:6px;
            padding:20px 24px;
            margin-bottom:16px;
        ">
            <h2 style="color:{colour};margin:0 0 4px 0;">
                {verdict} Risk{cache_badge}
            </h2>
            <p style="margin:0;font-size:1.05rem;">
                <strong>{indicator}</strong>
                &nbsp;·&nbsp; type: <code>{ioc_type}</code>
                &nbsp;·&nbsp; score: <strong>{score:.1f} / 100</strong>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Source breakdown
    col_vt, col_otx = st.columns(2)

    with col_vt:
        st.subheader("🔬 VirusTotal")
        if "error" in vt:
            st.warning(f"Error: {vt['error']}")
        elif vt:
            st.metric("Malicious engines",  vt.get("malicious", 0))
            st.metric("Suspicious engines", vt.get("suspicious", 0))
            st.metric("Total engines",      vt.get("total", 0))
        else:
            st.info("No VirusTotal data available.")

    with col_otx:
        st.subheader("🛸 AlienVault OTX")
        if "error" in otx:
            st.warning(f"Error: {otx['error']}")
        elif otx:
            st.metric("Pulse count", otx.get("pulse_count", 0))
            families = otx.get("malware_families", [])
            if families:
                st.write("**Malware families:**")
                st.write(", ".join(families[:10]))
            else:
                st.write("No malware families identified.")
        else:
            st.info("No OTX data available.")


# ── Helper: verdict pie chart ─────────────────────────────────────────────────

def _render_pie_chart(counts: dict[str, int]) -> None:
    """Render a Plotly pie chart of verdict distribution."""
    if not counts:
        st.info("No lookups recorded yet.")
        return

    labels = list(counts.keys())
    values = list(counts.values())
    colours = [_VERDICT_PIE_COLOURS.get(lbl, "#999") for lbl in labels]

    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            marker=dict(colors=colours, line=dict(color="#ffffff", width=2)),
            textinfo="label+percent+value",
            hole=0.35,
        )
    )
    fig.update_layout(
        showlegend=True,
        margin=dict(t=0, b=0, l=0, r=0),
        height=320,
    )
    st.plotly_chart(fig, use_container_width=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🔍 ThreatIntel")
    st.caption("VirusTotal + AlienVault OTX aggregator")
    st.divider()

    vt_ok  = bool(VIRUSTOTAL_API_KEY)
    otx_ok = bool(OTX_API_KEY)
    st.markdown("**API Key Status**")
    st.write(f"{'✅' if vt_ok  else '❌'} VirusTotal")
    st.write(f"{'✅' if otx_ok else '❌'} AlienVault OTX")

    if not vt_ok or not otx_ok:
        st.warning("Add missing API keys to your `.env` file and restart.")

    st.divider()
    st.markdown(
        "**Supported indicators**\n"
        "- IPv4 address\n"
        "- Domain / hostname\n"
        "- MD5 / SHA-1 / SHA-256 hash\n"
    )
    st.caption("Results are cached for 24 hours.")


# ── Main tabs ─────────────────────────────────────────────────────────────────

tab_single, tab_bulk, tab_history = st.tabs(
    ["🔎 Single Lookup", "📋 Bulk Lookup", "📂 History"]
)

# ──────────────────────────────────────────────────────────────────────────────
# Tab 1 – Single Lookup
# ──────────────────────────────────────────────────────────────────────────────
with tab_single:
    st.header("Single IoC Lookup")

    with st.form("single_lookup_form", clear_on_submit=False):
        indicator_input = st.text_input(
            "Enter an IP, domain, or file hash",
            placeholder="e.g.  8.8.8.8 · evil.com · 44d88612fea8a8f36de82e1278abb02f",
        )
        submitted = st.form_submit_button("🔍 Look Up", use_container_width=True)

    if submitted:
        if not indicator_input.strip():
            st.error("Please enter an indicator.")
        else:
            result = _run_lookup(indicator_input.strip())
            _render_result_card(result)

# ──────────────────────────────────────────────────────────────────────────────
# Tab 2 – Bulk Lookup
# ──────────────────────────────────────────────────────────────────────────────
with tab_bulk:
    st.header("Bulk IoC Lookup")
    st.write(
        "Upload a `.txt` file with one indicator per line.  "
        "Lines starting with `#` are treated as comments."
    )

    uploaded_file = st.file_uploader(
        "Choose a .txt file", type=["txt"], key="bulk_upload"
    )

    if uploaded_file is not None:
        content = uploaded_file.read().decode("utf-8", errors="replace")
        lines = [
            ln.strip()
            for ln in content.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]

        if not lines:
            st.warning("The uploaded file contains no valid indicators.")
        else:
            st.write(f"**{len(lines)} indicator(s) found.**")
            run_bulk = st.button("▶ Run Bulk Lookup", use_container_width=True)

            if run_bulk:
                bulk_results: list[dict[str, Any]] = []
                progress = st.progress(0, text="Starting…")

                for idx, line in enumerate(lines):
                    progress.progress(
                        (idx + 1) / len(lines),
                        text=f"Processing {idx + 1}/{len(lines)}: {line}",
                    )
                    res = _run_lookup(line)
                    bulk_results.append(res)

                progress.empty()
                st.success(f"Completed {len(bulk_results)} lookup(s).")

                # Display individual results
                for res in bulk_results:
                    with st.expander(
                        f"{res.get('indicator', res.get('indicator', '?'))}  "
                        f"— {res.get('verdict', 'error')}",
                        expanded=False,
                    ):
                        _render_result_card(res)

# ──────────────────────────────────────────────────────────────────────────────
# Tab 3 – History
# ──────────────────────────────────────────────────────────────────────────────
with tab_history:
    st.header("Lookup History")

    col_table, col_chart = st.columns([2, 1])

    with col_table:
        history = get_history(limit=200)

        if not history:
            st.info("No lookups recorded yet.  Run a lookup to see history here.")
        else:
            df = pd.DataFrame(history)
            # Rename for display
            df.rename(
                columns={
                    "id":         "ID",
                    "indicator":  "Indicator",
                    "ioc_type":   "Type",
                    "score":      "Score",
                    "verdict":    "Verdict",
                    "created_at": "Timestamp",
                },
                inplace=True,
            )
            df["Score"] = df["Score"].apply(lambda x: f"{x:.1f}")

            st.dataframe(df, use_container_width=True, hide_index=True)

            # CSV export
            csv_buf = io.StringIO()
            df.to_csv(csv_buf, index=False)
            st.download_button(
                label="⬇ Export as CSV",
                data=csv_buf.getvalue(),
                file_name="threatintel_history.csv",
                mime="text/csv",
            )

    with col_chart:
        st.subheader("Verdict Distribution")
        counts = get_verdict_counts()
        _render_pie_chart(counts)
