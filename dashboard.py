#!/usr/bin/env python3

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import os
import pycountry
import numpy as np
from importlib import util
import requests
from io import BytesIO
import glob

# -------------------------------
# CONFIG
# -------------------------------
st.set_page_config(page_title="Weekly Threat Intelligence", layout="wide")

GITHUB_USER = "CyberSwoldier"
GITHUB_REPO = "Threat-Intelligence-NIMBLR"
GITHUB_BRANCH = "main"
REPORTS_FOLDER = "reports"
API_URL = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/contents/{REPORTS_FOLDER}?ref={GITHUB_BRANCH}"

# -------------------------------
# FETCH threat_intel.py (optional)
# -------------------------------
GITHUB_RAW_URL = "https://raw.githubusercontent.com/CyberSwoldier/Threat-Intelligence-Report/main/threat_intel.py"
try:
    r = requests.get(GITHUB_RAW_URL)
    r.raise_for_status()
    with open("threat_intel.py", "w", encoding="utf-8") as f:
        f.write(r.text)
except Exception as e:
    st.warning(f"Could not fetch threat_intel.py: {e}")

try:
    spec = util.spec_from_file_location("threat_intel", "threat_intel.py")
    threat_intel = util.module_from_spec(spec)
    spec.loader.exec_module(threat_intel)
except Exception:
    threat_intel = None

# -------------------------------
# FETCH REPORTS FROM GITHUB
# -------------------------------
def fetch_reports_from_github(local_folder="reports"):
    os.makedirs(local_folder, exist_ok=True)
    try:
        r = requests.get(API_URL)
        r.raise_for_status()
        files = r.json()
    except Exception as e:
        st.error(f"Failed to list files from GitHub: {e}")
        return []

    downloaded_files = []
    for file in files:
        name = file.get("name", "")
        download_url = file.get("download_url", "")
        if name.startswith("ttp_reports_") and name.endswith(".xlsx"):
            local_path = os.path.join(local_folder, name)
            if not os.path.exists(local_path):
                try:
                    fr = requests.get(download_url)
                    fr.raise_for_status()
                    with open(local_path, "wb") as f:
                        f.write(fr.content)
                    st.sidebar.success(f"Fetched {name} from GitHub")
                except Exception as e:
                    st.sidebar.warning(f"Could not fetch {name}: {e}")
                    continue
            downloaded_files.append(local_path)
    return downloaded_files

# -------------------------------
# LOAD ALL REPORTS LOCALLY
# -------------------------------
def load_all_reports(folder="reports"):
    files = glob.glob(f"{folder}/ttp_reports_*.xlsx")
    all_data = []
    for f in files:
        try:
            xls = pd.ExcelFile(f)
            sheet_name = "items" if "items" in xls.sheet_names else xls.sheet_names[0]
            if "items" not in xls.sheet_names:
                st.warning(f"'items' sheet not found in {f}, using '{sheet_name}' instead.")
            df = pd.read_excel(xls, sheet_name=sheet_name)

            # Extract date from filename
            basename = os.path.basename(f)
            date_str = basename.replace("ttp_reports_", "").replace(".xlsx", "")
            try:
                report_date = pd.to_datetime(date_str, format="%d%m%y", errors="coerce")
            except Exception:
                report_date = pd.NaT
            df["report_date"] = report_date

            all_data.append(df)
        except Exception as e:
            st.warning(f"Could not read {f}: {e}")
            continue

    if all_data:
        combined = pd.concat(all_data, ignore_index=True)
        combined = combined.dropna(subset=["report_date"])
        if combined.empty:
            st.error("No valid data after combining all reports.")
            st.stop()
        return combined
    else:
        st.error("No report files found.")
        st.stop()

# -------------------------------
# FETCH & LOAD DATA
# -------------------------------
fetch_reports_from_github(REPORTS_FOLDER)
items = load_all_reports(REPORTS_FOLDER)

# -------------------------------
# DETECT COLUMNS
# -------------------------------
ttp_columns = [col for col in items.columns if col.lower().startswith("ttp_desc")]
country_columns = [col for col in items.columns if col.lower().startswith("country_")]

# -------------------------------
# DASHBOARD HEADER & METRICS
# -------------------------------
st.title("Weekly Threat Intelligence Report")
col1, col2, col3 = st.columns(3)

# MITRE TTPs metric
if ttp_columns:
    all_ttps = pd.Series(pd.concat([items[col] for col in ttp_columns], ignore_index=True))
    all_ttps_flat = []
    for val in all_ttps:
        if isinstance(val, (list, tuple, set)):
            all_ttps_flat.extend([str(x) for x in val if x not in [None, "None"]])
        elif val not in [None, "None", float('nan')]:
            all_ttps_flat.append(str(val))
    unique_ttps_count = len(set(all_ttps_flat))
else:
    unique_ttps_count = 0
with col2:
    st.metric("MITRE TTPs", unique_ttps_count)

# Sources metric
sources_count = items['source'].nunique() if 'source' in items.columns else 0
with col3:
    st.metric("Sources", sources_count)

# -------------------------------
# HELPER FUNCTIONS
# -------------------------------
def country_to_iso3(name):
    try:
        return pycountry.countries.lookup(name).alpha_3
    except LookupError:
        return None

def plot_heatmap(df, x_col, y_col, title, x_order=None, y_order=None, height=600):
    pivot = df.pivot(index=y_col, columns=x_col, values="count").fillna(0)
    if y_order:
        pivot = pivot.reindex(index=y_order, fill_value=0)
    if x_order:
        pivot = pivot.reindex(columns=x_order, fill_value=0)
    z_values = pivot.values
    text_values = np.where(z_values > 0, z_values, "")
    fig = go.Figure(go.Heatmap(
        z=z_values, x=list(pivot.columns), y=list(pivot.index),
        colorscale="YlOrBr", text=text_values, texttemplate="%{text}",
        hovertemplate=f"{x_col}: %{{x}}<br>{y_col}: %{{y}}<br>Count: %{{z}}<extra></extra>"
    ))
    fig.update_layout(
        title=title,
        paper_bgcolor="#0E1117", plot_bgcolor="#0E1117",
        font=dict(color="white"), height=height
    )
    st.plotly_chart(fig, use_container_width=True)

# -------------------------------
# 3D WORLD MAP
# -------------------------------
if country_columns:
    all_countries = pd.Series(pd.concat([items[col] for col in country_columns], ignore_index=True))
    all_countries = all_countries.dropna()[all_countries != "None"]
    if not all_countries.empty:
        iso_codes = all_countries.map(country_to_iso3).dropna().unique()
        all_iso = [c.alpha_3 for c in pycountry.countries]
        z_values = [1 if code in iso_codes else 0 for code in all_iso]
        fig_globe = go.Figure(go.Choropleth(
            locations=all_iso, z=z_values,
            colorscale=[[0, 'rgba(30,30,30,1)'], [1, 'yellow']],
            showscale=False, marker_line_color='lightblue', marker_line_width=0.5
        ))
        fig_globe.update_geos(projection_type="orthographic",
                              showcoastlines=True, coastlinecolor="lightblue",
                              showland=True, landcolor="#0E1117",
                              showocean=True, oceancolor="#0E1117",
                              showframe=False, bgcolor="#0E1117")
        fig_globe.update_layout(title="Countries affected by cyber incidents (highlighted in yellow)",
                                paper_bgcolor="#0E1117", plot_bgcolor="#0E1117",
                                font=dict(color="white"), margin=dict(l=0,r=0,t=40,b=0),
                                height=700)
        st.plotly_chart(fig_globe, use_container_width=True)
    else:
        st.info("No valid country data for globe.")
else:
    st.info("No country columns found.")

# -------------------------------
# RAW DATA SEARCH + DOWNLOAD
# -------------------------------
st.subheader("Raw Excel Data (Searchable)")
search_term = st.text_input("Search in table", "")
if search_term:
    mask = items.apply(lambda row: row.astype(str).str.contains(search_term, case=False, na=False).any(), axis=1)
    filtered_items = items[mask]
    if not filtered_items.empty:
        st.dataframe(filtered_items, use_container_width=True)
        output = BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            filtered_items.to_excel(writer, index=False, sheet_name="Filtered Data")
            worksheet = writer.sheets["Filtered Data"]
            worksheet.write(len(filtered_items)+2, 0, "Content created by Ricardo Mendes Pinto. Unauthorized distribution is not allowed")
        st.download_button("📥 Download Filtered Results (Excel)", data=output.getvalue(),
                           file_name="filtered_results.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    else:
        st.info("No results found.")
else:
    st.info("Enter a search term to view results.")

# -------------------------------
# FOOTER
# -------------------------------
st.markdown(
    """
    <hr style="margin-top:50px; margin-bottom:10px">
    <p style="text-align:center; color:grey; font-size:12px;">
    @ Content created by <a href="https://www.linkedin.com/in/ricardopinto110993/" target="_blank">Ricardo Mendes Pinto</a>. Unauthorized distribution is not allowed
    </p>
    """,
    unsafe_allow_html=True
)
