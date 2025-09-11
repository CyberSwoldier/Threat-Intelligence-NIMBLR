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

# GitHub Repo Config
GITHUB_USER = "CyberSwoldier"
GITHUB_REPO = "Threat-Intelligence-NIMBLR"
GITHUB_BRANCH = "main"
REPORTS_FOLDER = "reports"

# URL for GitHub API to list reports folder
API_URL = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/contents/{REPORTS_FOLDER}?ref={GITHUB_BRANCH}"

# -------------------------------
# LOAD threat_intel.py FROM GITHUB (if you still need this part)
# -------------------------------
GITHUB_RAW_URL = "https://raw.githubusercontent.com/CyberSwoldier/Threat-Intelligence-Report/main/threat_intel.py"

try:
    r = requests.get(GITHUB_RAW_URL)
    r.raise_for_status()
    with open("threat_intel.py", "w", encoding="utf-8") as f:
        f.write(r.text)
except Exception as e:
    st.error(f"Failed to fetch threat_intel.py from GitHub: {e}")
    # not stopping the app here, unless it's essential
    # st.stop()

spec = util.spec_from_file_location("threat_intel", "threat_intel.py")
try:
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
        # The JSON items have fields like "name", "download_url"
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
            df = pd.read_excel(f, sheet_name="items")
            # Extract date from filename: ttp_reports_ddmmyy.xlsx
            basename = os.path.basename(f)
            date_str = basename.replace("ttp_reports_", "").replace(".xlsx", "")
            # try parsing ddmmyy
            try:
                report_date = pd.to_datetime(date_str, format="%d%m%y", errors="coerce")
            except Exception:
                report_date = pd.NaT
            df["report_date"] = report_date
            all_data.append(df)
        except Exception as e:
            st.warning(f"Could not read {f}: {e}")
    if all_data:
        combined = pd.concat(all_data, ignore_index=True)
        # optionally drop rows where report_date is NaT
        combined = combined.dropna(subset=["report_date"])
        return combined
    else:
        st.error(f"No report files found in {folder}.")
        st.stop()

# Fetch from GitHub, then load
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
        else:
            if val not in [None, "None", float('nan')]:
                all_ttps_flat.append(str(val))
    unique_ttps_count = len(set(all_ttps_flat))
else:
    unique_ttps_count = 0

with col2:
    st.metric("MITRE TTPs", unique_ttps_count)

# Sources metric
if "source" in items.columns:
    sources_count = items['source'].nunique()
else:
    sources_count = 0
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
    if y_order is not None:
        pivot = pivot.reindex(index=y_order, fill_value=0)
    if x_order is not None:
        pivot = pivot.reindex(columns=x_order, fill_value=0)
    z_values = pivot.values
    text_values = np.where(z_values > 0, z_values, "")
    fig = go.Figure(go.Heatmap(
        z=z_values,
        x=list(pivot.columns),
        y=list(pivot.index),
        colorscale="YlOrBr",
        text=text_values,
        texttemplate="%{text}",
        hovertemplate=f"{x_col}: %{{x}}<br>{y_col}: %{{y}}<br>Count: %{{z}}<extra></extra>"
    ))
    fig.update_layout(
        title=title,
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        font=dict(color="white"),
        height=height
    )
    st.plotly_chart(fig, use_container_width=True)

# -------------------------------
# 3D WORLD MAP (GLOBE)
# -------------------------------
if country_columns:
    all_countries_series = pd.Series(pd.concat([items[col] for col in country_columns], ignore_index=True))
    valid_countries = all_countries_series.dropna()[all_countries_series != "None"]
    if not valid_countries.empty:
        iso_codes = valid_countries.map(country_to_iso3).dropna().unique()
        all_iso = [c.alpha_3 for c in pycountry.countries]
        z_values = [1 if code in iso_codes else 0 for code in all_iso]
        colorscale = [[0, 'rgba(30,30,30,1)'], [1, 'yellow']]
        fig_globe = go.Figure(go.Choropleth(
            locations=all_iso,
            z=z_values,
            colorscale=colorscale,
            showscale=False,
            marker_line_color='lightblue',
            marker_line_width=0.5,
            hoverinfo='location'
        ))
        fig_globe.update_geos(
            projection_type="orthographic",
            showcoastlines=True,
            coastlinecolor="lightblue",
            showland=True,
            landcolor="#0E1117",
            showocean=True,
            oceancolor="#0E1117",
            showframe=False,
            bgcolor="#0E1117"
        )
        fig_globe.update_layout(
            title="Countries affected by cyber incidents (highlighted in yellow)",
            paper_bgcolor="#0E1117",
            plot_bgcolor="#0E1117",
            font=dict(color="white"),
            margin=dict(l=0, r=0, t=40, b=0),
            height=700
        )
        st.plotly_chart(fig_globe, use_container_width=True)
    else:
        st.info("No valid country data for globe.")
else:
    st.info("No country_* columns found in this dataset.")

# -------------------------------
# TOP COUNTRIES & TECHNIQUES
# -------------------------------
if country_columns and ttp_columns:
    # Melt TTPs
    melted = items.melt(id_vars=country_columns, value_vars=ttp_columns, var_name="ttp_col", value_name="TTP")
    # explode lists if needed
    if any(melted["TTP"].apply(lambda x: isinstance(x, (list, tuple, set)))):
        melted = melted.explode("TTP")
    melted = melted.dropna(subset=["TTP"])
    melted = melted[melted["TTP"] != "None"]
    # then country side
    melted = melted.melt(id_vars=["TTP"], value_vars=country_columns, var_name="country_col", value_name="country")
    melted = melted.dropna(subset=["country"])
    melted = melted[melted["country"] != "None"]

    if not melted.empty:
        # Top countries
        country_counts = (melted.groupby("country")
                          .size()
                          .reset_index(name="count")
                          .sort_values("count", ascending=False))
        st.subheader("Affected Countries")
        fig_country = go.Figure(go.Bar(
            x=country_counts["country"],
            y=country_counts["count"],
            text=country_counts["count"],
            textposition="auto",
            marker=dict(color=country_counts["count"], colorscale="YlOrBr")
        ))
        fig_country.update_layout(
            xaxis_title="Country",
            yaxis_title="Nº of Incidents",
            paper_bgcolor="#0E1117",
            plot_bgcolor="#0E1117",
            font=dict(color="white"),
            showlegend=False,
            height=600
        )
        st.plotly_chart(fig_country, use_container_width=True)

        # Top TTPs
        ttp_counts = (melted.groupby("TTP")
                      .size()
                      .reset_index(name="count")
                      .sort_values("count", ascending=False))
        st.subheader("MITRE Techniques")
        fig_ttp = go.Figure(go.Bar(
            x=ttp_counts["TTP"],
            y=ttp_counts["count"],
            text=ttp_counts["count"],
            textposition="auto",
            marker=dict(color=ttp_counts["count"], colorscale="YlOrBr")
        ))
        fig_ttp.update_layout(
            xaxis_title="Technique",
            yaxis_title="Nº of Incidents",
            paper_bgcolor="#0E1117",
            plot_bgcolor="#0E1117",
            font=dict(color="white"),
            showlegend=False,
            height=600
        )
        st.plotly_chart(fig_ttp, use_container_width=True)
    else:
        st.info("No TTP / Country intersections found.")

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

        # Prepare Excel file with signature
        output = BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            filtered_items.to_excel(writer, index=False, sheet_name="Filtered Data")
            worksheet = writer.sheets["Filtered Data"]
            worksheet.write(len(filtered_items) + 2, 0, "Content created by Ricardo Mendes Pinto. Unauthorized distribution is not allowed")

        st.download_button(
            label="📥 Download Filtered Results (Excel)",
            data=output.getvalue(),
            file_name="filtered_results.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    else:
        st.info("No results found for your search.")
else:
    st.info("Please enter a search term to view results.")

# -------------------------------
# TREND ANALYSIS (Dynamic + Comparison)
# -------------------------------
st.subheader("📊 Trend Analysis")

# Build list of unique TTPs
all_ttps = []
if ttp_columns:
    for col in ttp_columns:
        # flatten
        vals = items[col].dropna().tolist()
        for v in vals:
            if isinstance(v, (list, tuple, set)):
                all_ttps.extend([str(x) for x in v])
            else:
                all_ttps.append(str(v))
unique_ttps = sorted(set([t for t in all_ttps if t not in ["None", "nan"]]))

# Build list of unique countries
all_countries = []
if country_columns:
    for col in country_columns:
        all_countries.extend(items[col].dropna().astype(str).tolist())
unique_countries = sorted(set([c for c in all_countries if c not in ["None", "nan"]]))

tab1, tab2 = st.tabs(["TTP Trends", "Country Trends"])

with tab1:
    if unique_ttps:
        ttp_choice = st.selectbox("Select a MITRE Technique (TTP)", unique_ttps)
        ttp_trend = items.copy()
        ttp_trend["has_ttp"] = ttp_trend[ttp_columns].apply(
            lambda row: any(str(ttp_choice).lower() in str(v).lower() for v in row if pd.notna(v)), axis=1
        )
        trend_df = ttp_trend.groupby("report_date")["has_ttp"].sum().reset_index()

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=trend_df["report_date"], y=trend_df["has_ttp"],
                                mode="lines+markers", name=ttp_choice))

        ttp_compare = st.multiselect("Compare with other TTPs", [t for t in unique_ttps if t != ttp_choice], max_selections=2)
        for comp in ttp_compare:
            tmp = items.copy()
            tmp["has_ttp"] = tmp[ttp_columns].apply(
                lambda row: any(str(comp).lower() in str(v).lower() for v in row if pd.notna(v)), axis=1
            )
            tmp_df = tmp.groupby("report_date")["has_ttp"].sum().reset_index()
            fig.add_trace(go.Scatter(x=tmp_df["report_date"], y=tmp_df["has_ttp"],
                                    mode="lines+markers", name=comp))

        fig.update_layout(title="TTP Trends Over Time", xaxis_title="Date", yaxis_title="Occurrences")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No TTP data available for trend analysis.")

with tab2:
    if unique_countries:
        country_choice = st.selectbox("Select a Country", unique_countries)
        country_trend = items.copy()
        country_trend["has_country"] = country_trend[country_columns].apply(
            lambda row: any(str(country_choice).lower() in str(v).lower() for v in row if pd.notna(v)), axis=1
        )
        trend_df = country_trend.groupby("report_date")["has_country"].sum().reset_index()

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=trend_df["report_date"], y=trend_df["has_country"],
                                mode="lines+markers", name=country_choice))

        country_compare = st.multiselect("Compare with other Countries", [c for c in unique_countries if c != country_choice], max_selections=2)
        for comp in country_compare:
            tmp = items.copy()
            tmp["has_country"] = tmp[country_columns].apply(
                lambda row: any(str(comp).lower() in str(v).lower() for v in row if pd.notna(v)), axis=1
            )
            tmp_df = tmp.groupby("report_date")["has_country"].sum().reset_index()
            fig.add_trace(go.Scatter(x=tmp_df["report_date"], y=tmp_df["has_country"],
                                    mode="lines+markers", name=comp))

        fig.update_layout(title="Country Trends Over Time", xaxis_title="Date", yaxis_title="Occurrences")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No country data available for trend analysis.")

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
