#!/usr/bin/env python3
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import os
import pycountry
import numpy as np
from difflib import get_close_matches
from importlib import util
import requests

# -------------------------------
# CONFIG
# -------------------------------
st.set_page_config(page_title="Weekly Security Report", layout="wide")

# -------------------------------
# LOAD threat_intel.py FROM GITHUB
# -------------------------------
GITHUB_RAW_URL = "https://raw.githubusercontent.com/CyberSwoldier/Threat-Intelligence-Report/main/threat_intel.py"

try:
    r = requests.get(GITHUB_RAW_URL)
    r.raise_for_status()
    with open("threat_intel.py", "w", encoding="utf-8") as f:
        f.write(r.text)
except Exception as e:
    st.error(f"Failed to fetch threat_intel.py from GitHub: {e}")
    st.stop()

spec = util.spec_from_file_location("threat_intel", "threat_intel.py")
threat_intel = util.module_from_spec(spec)
spec.loader.exec_module(threat_intel)

# -------------------------------
# LOAD EXCEL REPORT
# -------------------------------
latest_file = "ttp_reports.xlsx"
if not os.path.exists(latest_file):
    if hasattr(threat_intel, "fetch_news"):
        st.info("Fetching latest report via threat_intel...")
        threat_intel.fetch_news()
    if not os.path.exists(latest_file):
        st.error(f"No Excel file found: {latest_file}. Run the tracker first.")
        st.stop()

st.sidebar.success(f"Using report: {os.path.basename(latest_file)}")
xls = pd.ExcelFile(latest_file)
st.sidebar.write("Available sheets:", xls.sheet_names)

# -------------------------------
# FUZZY SHEET LOADER
# -------------------------------
def fuzzy_read(sheet_name, fallback=None):
    match = get_close_matches(sheet_name, xls.sheet_names, n=1, cutoff=0.5)
    if match:
        st.sidebar.info(f"Using sheet '{match[0]}' for '{sheet_name}'")
        return pd.read_excel(xls, sheet_name=match[0])
    elif fallback:
        st.sidebar.warning(f"No close match for '{sheet_name}', using fallback '{fallback}'")
        return pd.read_excel(xls, sheet_name=fallback)
    else:
        st.sidebar.error(f"No sheet found for '{sheet_name}' and no fallback provided")
        return pd.DataFrame()

# Load sheets
items = fuzzy_read("items", fallback=xls.sheet_names[0])
counts = fuzzy_read("technique_counts")

# -------------------------------
# DEFINE COLUMNS
# -------------------------------
country_columns = [col for col in items.columns if col.lower().startswith("country_")]
ttp_columns = [col for col in items.columns if col.lower().startswith("ttp_desc")]

# -------------------------------
# DASHBOARD HEADER
# -------------------------------
st.title("Weekly Security Report")
st.caption(f"Report source: **{os.path.basename(latest_file)}**")

# -------------------------------
# METRICS
# -------------------------------
col1, col2, col3 = st.columns(3)

with col2:
    if ttp_columns:
        all_ttps = pd.Series(pd.concat([items[col] for col in ttp_columns], ignore_index=True))
        all_ttps_flat = []
        for val in all_ttps:
            if isinstance(val, list):
                all_ttps_flat.extend([str(x) for x in val if x not in [None, "None"]])
            elif val not in [None, "None"]:
                all_ttps_flat.append(str(val))
        unique_ttps = len(set(all_ttps_flat))
    else:
        unique_ttps = 0
    st.metric("MITRE TTPs", unique_ttps)

with col3:
    st.metric("Sources", items['source'].nunique() if 'source' in items.columns else 0)

# -------------------------------
# COUNTRY COORDINATES
# -------------------------------
# Country coordinates dataset
country_coords = {
    "Afghanistan": {"lat": 33.0, "lon": 65.0},
    "Albania": {"lat": 41.0, "lon": 20.0},
    "Algeria": {"lat": 28.0, "lon": 3.0},
    "Andorra": {"lat": 42.5, "lon": 1.6},
    "Angola": {"lat": -12.5, "lon": 18.5},
    "Antigua and Barbuda": {"lat": 17.05, "lon": -61.8},
    "Argentina": {"lat": -34.0, "lon": -64.0},
    "Armenia": {"lat": 40.0, "lon": 45.0},
    "Australia": {"lat": -27.0, "lon": 133.0},
    "Austria": {"lat": 47.3333, "lon": 13.3333},
    # Add more countries as needed
}

# -------------------------------
# 3D DARK GLOBE HIGHLIGHTING AFFECTED COUNTRIES
# -------------------------------
if country_columns and ttp_columns:
    # Build melted dataframe for bar chart
    melted = items.melt(
        id_vars=country_columns, 
        value_vars=ttp_columns, 
        var_name="ttp_col", 
        value_name="TTP"
    )
    melted = melted.explode("TTP") if melted["TTP"].apply(lambda x: isinstance(x, list)).any() else melted
    melted = melted.dropna(subset=["TTP"])
    melted = melted[melted["TTP"] != "None"]
    melted = melted.melt(
        id_vars=["TTP"], 
        value_vars=country_columns, 
        var_name="country_col", 
        value_name="country"
    )
    melted = melted.dropna(subset=["country"])
    melted = melted[melted["country"] != "None"]

    if not melted.empty:
        # Get list of countries actually shown in the bar chart
        affected_countries = melted["country"].unique()

        # Filter only countries with known coordinates
        valid_countries = [c for c in affected_countries if c in country_coords]
        valid_coords = [country_coords[c] for c in valid_countries]
        lats = [coord["lat"] for coord in valid_coords]
        lons = [coord["lon"] for coord in valid_coords]

        # Plot globe
        fig_globe = go.Figure()

        fig_globe.update_geos(
            showland=True, landcolor="#0E1117",
            showocean=True, oceancolor="#0E1117",
            showcountries=True, countrycolor="lightblue",
            projection_type="orthographic"
        )

        # Highlight exactly the countries from the bar chart
        fig_globe.add_trace(go.Scattergeo(
            lat=lats,
            lon=lons,
            text=valid_countries,
            mode="markers",
            marker=dict(size=12, color="yellow", opacity=0.9),
            hoverinfo="text"
        ))

        fig_globe.update_layout(
            title="Affected Countries (3D Globe)",
            paper_bgcolor="#0E1117",
            font=dict(color="white"),
            height=600
        )

        st.plotly_chart(fig_globe, use_container_width=True)
    else:
        st.info("No affected countries to display on the globe.")
else:
    st.info("No country_* columns or TTP columns found in this report.")

# -------------------------------
# HELPER FUNCTION: HEATMAP
# -------------------------------
def plot_heatmap(df, x_col, y_col, title, x_order=None, y_order=None, height=600):
    if df.empty:
        st.info(f"No data available to plot {title}")
        return
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
