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
            sheet_name = "Human_Attacks" if "Human_Attacks" in xls.sheet_names else xls.sheet_names[0]
            if "Human_Attacks" not in xls.sheet_names:
                st.warning(f"'Human_Attacks' sheet not found in {f}, using '{sheet_name}' instead.")
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
Human_Attacks = load_all_reports(REPORTS_FOLDER)

# -------------------------------
# DETECT COLUMNS
# -------------------------------
ttp_columns = [col for col in Human_Attacks.columns if col.lower().startswith("ttp_desc")]
country_columns = [col for col in Human_Attacks.columns if col.lower().startswith("country_")]

# -------------------------------
# DASHBOARD HEADER & METRICS
# -------------------------------
st.title("Weekly Threat Intelligence Report")
col1, col2, col3 = st.columns(3)

# MITRE TTPs metric
if ttp_columns:
    all_ttps = pd.Series(pd.concat([Human_Attacks[col] for col in ttp_columns], ignore_index=True))
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
sources_count = Human_Attacks['source'].nunique() if 'source' in Human_Attacks.columns else 0
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
    all_countries = pd.Series(pd.concat([Human_Attacks[col] for col in country_columns], ignore_index=True))
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
# HELPER FUNCTION: HEATMAP
# -------------------------------
def plot_heatmap(df, x_col, y_col, title, x_order=None, y_order=None, height=600):
    pivot = df.pivot(index=y_col, columns=x_col, values="count").fillna(0)
    if y_order is not None:
        pivot = pivot.reindex(index=y_order, fill_value=0)
    if x_order is not None:
        pivot = pivot.reindex(columns=x_order, fill_value=0)
    z_values = pivot.values
    text_values = np.where(z_values > 0, z_values, "")
    fig = go.Figure(data=go.Heatmap(
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
# TOP COUNTRIES & TECHNIQUES
# -------------------------------
if country_columns and ttp_columns:
    melted = items.melt(id_vars=country_columns, value_vars=ttp_columns, var_name="ttp_col", value_name="TTP")
    melted = melted.explode("TTP") if melted["TTP"].apply(lambda x: isinstance(x, list)).any() else melted
    melted = melted.dropna(subset=["TTP"])
    melted = melted[melted["TTP"] != "None"]
    melted = melted.melt(id_vars=["TTP"], value_vars=country_columns, var_name="country_col", value_name="country")
    melted = melted.dropna(subset=["country"])
    melted = melted[melted["country"] != "None"]

    if not melted.empty:
        # Top countries
        country_counts = melted.groupby("country").size().reset_index(name="count")
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
        ttp_counts = melted.groupby("TTP").size().reset_index(name="count")
        ttp_counts = ttp_counts.sort_values("count", ascending=False)
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

# -------------------------------
# TECHNIQUES PER COUNTRY
# -------------------------------
if country_columns and ttp_columns:
    st.subheader("MITRE Techniques per Country")
    long_rows = []
    for idx, row in items.iterrows():
        ttps = [row[col] for col in ttp_columns if pd.notna(row[col]) and row[col] != "None"]
        countries = [row[col] for col in country_columns if pd.notna(row[col]) and row[col] != "None"]
        for country in countries:
            for ttp in ttps:
                if isinstance(ttp, list):
                    for t in ttp:
                        long_rows.append({"country": country, "TTP": str(t)})
                else:
                    long_rows.append({"country": country, "TTP": str(ttp)})
    melted = pd.DataFrame(long_rows)

    if not melted.empty:
        relation = melted.groupby(["country", "TTP"]).size().reset_index(name="count")
        all_countries = sorted(melted["country"].unique())
        all_ttps = melted["TTP"].unique()
        full_index = pd.MultiIndex.from_product([all_countries, all_ttps], names=["country", "TTP"])
        relation_full = relation.set_index(["country", "TTP"]).reindex(full_index, fill_value=0).reset_index()
        plot_heatmap(
            relation_full,
            x_col="country",
            y_col="TTP",
            title="Number of occurrences of each MITRE technique correlated to each country",
            x_order=all_countries,
            y_order=None,
            height=900
        )
    else:
        st.info("No TTP–country relationships available to plot.")

# -------------------------------
# THREAT ACTORS
# -------------------------------
if country_columns and "threat_actor" in items.columns:
    st.subheader("Threat Actor's Activity by Country")
    melted = items.melt(id_vars=["threat_actor"], value_vars=country_columns, var_name="country_col", value_name="country")
    melted = melted.dropna(subset=["country", "threat_actor"])
    melted = melted[(melted["country"] != "None") & (melted["threat_actor"] != "None")]
    if not melted.empty:
        heatmap_data = melted.groupby(["country", "threat_actor"]).size().reset_index(name="count")
        countries = sorted(heatmap_data["country"].unique())
        plot_heatmap(heatmap_data, "country", "threat_actor", "Threat Actor Activity", x_order=countries, height=700)
# -------------------------------
# RAW DATA SEARCH + DOWNLOAD
# -------------------------------
st.subheader("Raw Excel Data (Searchable)")
search_term = st.text_input("Search in table", "")
if search_term:
    mask = Human_Attacks.apply(lambda row: row.astype(str).str.contains(search_term, case=False, na=False).any(), axis=1)
    filtered_Human_Attacks = Human_Attacks[mask]
    if not filtered_Human_Attacks.empty:
        st.dataframe(filtered_Human_Attacks, use_container_width=True)
        output = BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            filtered_Human_Attacks.to_excel(writer, index=False, sheet_name="Filtered Data")
            worksheet = writer.sheets["Filtered Data"]
            worksheet.write(len(filtered_Human_Attacks)+2, 0, "Content created by Ricardo Mendes Pinto. Unauthorized distribution is not allowed")
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
