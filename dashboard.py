#!/usr/bin/env python3
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import os
import pycountry
from difflib import get_close_matches
import numpy as np
import threat_intel  # your GitHub threat_intel.py script

st.set_page_config(page_title="Weekly Security Report", layout="wide")

latest_file = "ttp_reports.xlsx"

# -------------------------------
# Sidebar: Refresh Report
# -------------------------------
st.sidebar.title("Controls")
if st.sidebar.button("Fetch Latest Threat Report"):
    try:
        st.sidebar.info("Fetching latest threat intelligence report...")
        threat_intel.fetch_and_save_report(latest_file)
        st.sidebar.success("Report updated successfully!")
    except Exception as e:
        st.sidebar.error(f"Failed to fetch report: {e}")

# -------------------------------
# Load Excel report
# -------------------------------
if not os.path.exists(latest_file):
    st.error(f"No Excel file found: {latest_file}. Run the tracker first or hit refresh.")
    st.stop()

st.sidebar.success(f"Using report: {os.path.basename(latest_file)}")

xls = pd.ExcelFile(latest_file)
st.sidebar.write("Available sheets:", xls.sheet_names)

# -------------------------------
# Fuzzy sheet loader
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
# Dashboard Layout
# -------------------------------
st.title("Weekly Security Report")
st.caption(f"Report source: **{os.path.basename(latest_file)}**")

# --- Metrics ---
col1, col2, col3 = st.columns(3)

with col2:
    ttp_columns = [col for col in items.columns if col.lower().startswith("ttp_desc")]
    if ttp_columns:
        all_ttps = pd.Series(pd.concat([items[col] for col in ttp_columns], ignore_index=True))
        unique_ttps = all_ttps[all_ttps.notna() & (all_ttps != "None")].nunique()
    else:
        unique_ttps = 0
    st.metric("MITRE TTPs", unique_ttps)
with col3:
    st.metric("Sources", items['source'].nunique() if 'source' in items.columns else 0)

# -------------------------------
# WORLD MAP (Enhanced)
# -------------------------------
if country_columns:
    all_countries_series = pd.Series(pd.concat([items[col] for col in country_columns], ignore_index=True))
    all_countries_series = all_countries_series[all_countries_series.notna() & (all_countries_series != "None")]

    if not all_countries_series.empty:
        def country_to_iso3(name):
            try:
                return pycountry.countries.lookup(name).alpha_3
            except LookupError:
                return None

        iso_codes = all_countries_series.map(country_to_iso3)
        country_counts = pd.DataFrame({"country": all_countries_series, "iso_alpha": iso_codes})
        country_counts = country_counts.dropna(subset=["iso_alpha"])
        country_counts = country_counts.groupby("iso_alpha").size().reset_index(name="count")

        fig_map = go.Figure(go.Choropleth(
            locations=country_counts["iso_alpha"],
            z=country_counts["count"],
            colorscale="Viridis",
            colorbar_title="Reports",
            marker_line_color='black',  # add borders
            marker_line_width=0.5,
            hovertemplate='<b>%{location}</b><br>Reports: %{z}<extra></extra>'
        ))

        fig_map.update_geos(
            projection_type="natural earth",
            showcountries=True,
            showcoastlines=True,
            coastlinecolor="white",
            landcolor="#1a1a1a",
            oceancolor="#0e1117",
            showocean=True,
            lakecolor="#0e1117"
        )

        fig_map.update_layout(
            title="Reported Incidents by Country",
            paper_bgcolor="#0E1117",
            plot_bgcolor="#0E1117",
            font=dict(color="white"),
            margin={"r":0,"t":50,"l":0,"b":0},
            height=600
        )

        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("No valid affected country data found in this report.")
else:
    st.info("No country_* columns found in this report.")
# -------------------------------
# Helper function for heatmaps
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
# Row 3: Top Affected Countries + Top Techniques
# -------------------------------
if country_columns and ttp_columns:
    melted = items.melt(id_vars=country_columns, value_vars=ttp_columns, var_name="ttp_col", value_name="TTP")
    melted = melted.dropna(subset=["TTP"])
    melted = melted[melted["TTP"] != "None"]
    melted = melted.melt(id_vars=["TTP"], value_vars=country_columns, var_name="country_col", value_name="country")
    melted = melted.dropna(subset=["country"])
    melted = melted[melted["country"] != "None"]

    if not melted.empty:
        # Top Countries
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
# Row 2: Techniques by Country
# -------------------------------
if country_columns and ttp_columns:
    st.subheader("MITRE Techniques per Country")
    long_rows = []
    for idx, row in items.iterrows():
        ttps = [row[col] for col in ttp_columns if pd.notna(row[col]) and row[col] != "None"]
        countries = [row[col] for col in country_columns if pd.notna(row[col]) and row[col] != "None"]
        for country in countries:
            for ttp in ttps:
                long_rows.append({"country": country, "TTP": ttp})

    melted = pd.DataFrame(long_rows)
    if not melted.empty:
        relation = melted.groupby(["country", "TTP"]).size().reset_index(name="count")
        all_countries = sorted(melted["country"].unique())
        all_ttps = melted["TTP"].unique()
        full_index = pd.MultiIndex.from_product([all_countries, all_ttps], names=["country", "TTP"])
        relation_full = relation.set_index(["country", "TTP"]).reindex(full_index, fill_value=0).reset_index()
        plot_heatmap(relation_full, "country", "TTP",
                     "Number of occurrences of each MITRE technique correlated to each country",
                     x_order=all_countries, height=900)
    else:
        st.info("No TTP–country relationships available to plot.")

# -------------------------------
# Row 4: Threat Actors by Country
# -------------------------------
if country_columns and "threat_actor" in items.columns:
    st.subheader("Threat Actor's Activity by Country")
    melted = items.melt(id_vars=["threat_actor"], value_vars=country_columns, var_name="country_col", value_name="country")
    melted = melted.dropna(subset=["country", "threat_actor"])
    melted = melted[(melted["country"] != "None") & (melted["threat_actor"] != "None")]
    if not melted.empty:
        heatmap_data = melted.groupby(["country", "threat_actor"]).size().reset_index(name="count")
        countries = sorted(heatmap_data["country"].unique())
        plot_heatmap(heatmap_data, "country", "threat_actor", "", x_order=countries, height=700)

# -------------------------------
# Row 5: Techniques by Threat Actor
# -------------------------------
if "threat_actor" in items.columns and ttp_columns:
    st.subheader("MITRE Techniques Employed by Threat Actor")
    melted = items.melt(id_vars=["threat_actor"], value_vars=ttp_columns, var_name="ttp_col", value_name="TTP")
    melted = melted.dropna(subset=["TTP", "threat_actor"])
    melted = melted[(melted["TTP"] != "None") & (melted["threat_actor"] != "None")]
    if not melted.empty:
        relation = melted.groupby(["threat_actor", "TTP"]).size().reset_index(name="count")
        plot_heatmap(relation, "threat_actor", "TTP", "", height=700)
