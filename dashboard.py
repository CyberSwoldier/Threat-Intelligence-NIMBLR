#!/usr/bin/env python3
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import pycountry
import os
import requests
from io import BytesIO
import glob
from importlib import util

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
except Exception:
    pass

try:
    spec = util.spec_from_file_location("threat_intel", "threat_intel.py")
    threat_intel = util.module_from_spec(spec)
    spec.loader.exec_module(threat_intel)
except Exception:
    threat_intel = None

# -------------------------------
# FETCH REPORTS
# -------------------------------
def fetch_reports(local_folder="reports"):
    os.makedirs(local_folder, exist_ok=True)
    try:
        r = requests.get(API_URL)
        r.raise_for_status()
        files = r.json()
    except Exception as e:
        st.error(f"Failed to list files from GitHub: {e}")
        return []

    downloaded = []
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
                    st.sidebar.success(f"Fetched {name}")
                except Exception as e:
                    st.sidebar.warning(f"Failed {name}: {e}")
                    continue
            downloaded.append(local_path)
    return downloaded

# -------------------------------
# LOAD REPORTS
# -------------------------------
def load_reports(folder="reports"):
    files = glob.glob(f"{folder}/ttp_reports_*.xlsx")
    all_data = []
    for f in files:
        try:
            xls = pd.ExcelFile(f)
            sheet_name = "Human_Attacks" if "Human_Attacks" in xls.sheet_names else xls.sheet_names[0]
            if "Human_Attacks" not in xls.sheet_names:
                st.warning(f"'Human_Attacks' sheet not found in {f}, using '{sheet_name}' instead.")
            df = pd.read_excel(xls, sheet_name=sheet_name)
            date_str = os.path.basename(f).replace("ttp_reports_","").replace(".xlsx","")
            df["report_date"] = pd.to_datetime(date_str, format="%d%m%y", errors="coerce")
            all_data.append(df)
        except Exception as e:
            st.warning(f"Could not read {f}: {e}")
            continue
    if all_data:
        combined = pd.concat(all_data, ignore_index=True)
        combined = combined.dropna(subset=["report_date"])
        if combined.empty:
            st.error("No valid data after combining reports.")
            st.stop()
        return combined
    else:
        st.error("No report files found.")
        st.stop()

# -------------------------------
# FETCH & LOAD
# -------------------------------
fetch_reports(REPORTS_FOLDER)
items = load_reports(REPORTS_FOLDER)

# -------------------------------
# DETECT COLUMNS
# -------------------------------
ttp_columns = [c for c in items.columns if c.lower().startswith("ttp_desc")]
country_columns = [c for c in items.columns if c.lower().startswith("country_")]

# -------------------------------
# HELPER FUNCTIONS
# -------------------------------
def country_to_iso3(name):
    try:
        return pycountry.countries.lookup(name).alpha_3
    except LookupError:
        return None

def plot_heatmap(df, x_col, y_col, title, x_order=None, y_order=None, height=600):
    if df.empty:
        st.info("No data available to display heatmap.")
        return
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
# SIDEBAR NAVIGATION
# -------------------------------
st.sidebar.title("Navigation")
page = st.sidebar.radio("Select a page:", ["Dashboard", "About"])

if page == "About":
    st.title("About This Dashboard")
    st.markdown("""
    This dashboard provides insights into threat intelligence reports:
    - **Select a report date** to view metrics, globe, charts, and heatmaps.
    - **Filter by country** with the search bar on top.
    - **Search and download** filtered data as Excel.
    """)
    st.markdown("For more info, talk to [Ricardo Mendes Pinto](https://www.linkedin.com/in/ricardopinto110993/).")
    st.stop()

# -------------------------------
# DASHBOARD HEADER
# -------------------------------
st.title("Weekly Threat Intelligence Report")

# -------------------------------
# REPORT SELECTION
# -------------------------------
report_dates = sorted(items['report_date'].dt.date.unique(), reverse=True)
selected_date = st.selectbox("Select a report to view", report_dates, index=0)
selected_report = items[items['report_date'].dt.date == selected_date]

# -------------------------------
# MULTI-COUNTRY FILTER (search bar)
# -------------------------------
all_countries = []
if country_columns:
    all_countries = pd.Series(pd.concat([selected_report[col] for col in country_columns], ignore_index=True))
    all_countries = sorted(all_countries.dropna().unique().tolist())
selected_countries = st.multiselect(
    "🌍 Filter by Country (leave empty to show all)",
    options=all_countries,
    default=[]
)

if selected_countries:
    selected_report = selected_report[
        selected_report[country_columns].apply(lambda row: row.isin(selected_countries).any(), axis=1)
    ]

if selected_report.empty:
    st.warning("No data available for the selected country filter.")
    st.stop()

# -------------------------------
# METRICS FOR SELECTED REPORT
# -------------------------------
col1, col2 = st.columns(2)

# MITRE TTPs
if ttp_columns:
    all_ttps = pd.Series(pd.concat([selected_report[col] for col in ttp_columns], ignore_index=True))
    all_ttps_flat = []
    for val in all_ttps:
        if isinstance(val, (list, tuple, set)):
            all_ttps_flat.extend([str(x) for x in val if x not in [None, "None"]])
        elif pd.notna(val) and str(val) != "None":
            all_ttps_flat.append(str(val))
    unique_ttps_count = len(set(all_ttps_flat))
else:
    unique_ttps_count = 0
with col1:
    st.metric("MITRE TTPs", unique_ttps_count)

# Sources
sources_count = selected_report['source'].nunique() if 'source' in selected_report.columns else 0
with col2:
    st.metric("Sources", sources_count)

# -------------------------------
# GLOBE
# -------------------------------
if country_columns:
    all_countries_series = pd.Series(pd.concat([selected_report[col] for col in country_columns], ignore_index=True))
    all_countries_series = all_countries_series.dropna()[all_countries_series != "None"]
    if not all_countries_series.empty:
        iso_codes = all_countries_series.map(country_to_iso3).dropna().unique()
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
        fig_globe.update_layout(title=f"Countries affected in {selected_date}",
                                paper_bgcolor="#0E1117", plot_bgcolor="#0E1117",
                                font=dict(color="white"), margin=dict(l=0,r=0,t=40,b=0),
                                height=700)
        st.plotly_chart(fig_globe, use_container_width=True)

# -------------------------------
# BAR CHARTS & HEATMAPS
# -------------------------------
if country_columns and ttp_columns:
    melted = selected_report.melt(id_vars=country_columns, value_vars=ttp_columns,
                                  var_name="ttp_col", value_name="TTP")
    if any(melted["TTP"].apply(lambda x: isinstance(x, (list, tuple, set)))):
        melted = melted.explode("TTP")
    melted = melted.dropna(subset=["TTP"])
    melted = melted[melted["TTP"] != "None"]
    melted = melted.melt(id_vars=["TTP"], value_vars=country_columns,
                         var_name="country_col", value_name="country")
    melted = melted.dropna(subset=["country"])
    melted = melted[melted["country"] != "None"]

    if not melted.empty:
        # Top countries
        country_counts = melted.groupby("country").size().reset_index(name="count").sort_values("count", ascending=False)
        st.subheader("Top Affected Countries")
        fig_country = go.Figure(go.Bar(
            x=country_counts["country"], y=country_counts["count"],
            text=country_counts["count"], textposition="auto",
            marker=dict(color=country_counts["count"], colorscale="YlOrBr")
        ))
        fig_country.update_layout(paper_bgcolor="#0E1117", plot_bgcolor="#0E1117",
                                  font=dict(color="white"), showlegend=False, height=500)
        st.plotly_chart(fig_country, use_container_width=True)

        # Top TTPs
        ttp_counts = melted.groupby("TTP").size().reset_index(name="count").sort_values("count", ascending=False)
        st.subheader("Top MITRE Techniques")
        fig_ttp = go.Figure(go.Bar(
            x=ttp_counts["TTP"], y=ttp_counts["count"],
            text=ttp_counts["count"], textposition="auto",
            marker=dict(color=ttp_counts["count"], colorscale="YlOrBr")
        ))
        fig_ttp.update_layout(paper_bgcolor="#0E1117", plot_bgcolor="#0E1117",
                              font=dict(color="white"), showlegend=False, height=500)
        st.plotly_chart(fig_ttp, use_container_width=True)

        # Heatmap: TTP per Country
        st.subheader("MITRE Techniques per Country")
        heat_data = melted.groupby(["country", "TTP"]).size().reset_index(name="count")
        plot_heatmap(heat_data, x_col="country", y_col="TTP",
                     title=f"TTP occurrences per country ({selected_date})", height=700)

# -------------------------------
# SEARCHABLE TABLE + DOWNLOAD
# -------------------------------
st.subheader("Raw Data Search & Download")
search_term = st.text_input("Search in table", "")

if search_term:
    mask = items.apply(lambda row: row.astype(str).str.contains(search_term, case=False, na=False).any(), axis=1)
    filtered_items = items[mask]

    if not filtered_items.empty:
        st.dataframe(filtered_items, use_container_width=True)
        output = BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            filtered_items.to_excel(writer, index=False, sheet_name="Filtered Data")
        output.seek(0)
        st.download_button(
            label="📥 Download Filtered Results",
            data=output,
            file_name="filtered_results.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
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
    @ Content created by <a href="https://www.linkedin.com/in/ricardopinto110993/" target="_blank">Ricardo Mendes Pinto</a>.
    </p>
    """,
    unsafe_allow_html=True
)
