#!/usr/bin/env python3
"""
MITRE TTP Streamlit Dashboard
Displays Techniques per Country and per Threat Actor as full-width heatmaps.
Uses fetch_news() from threat_intel.py.
"""
import streamlit as st
import pandas as pd
import plotly.express as px

# ------------------ Import fetch_news safely ------------------
try:
    from threat_intel import fetch_news
except Exception as e:
    st.error(f"Error importing fetch_news: {e}")
    fetch_news = None

st.set_page_config(page_title="MITRE TTP Dashboard", layout="wide")

st.title("MITRE TTP Web Tracker Dashboard")
st.write("Visualizing techniques and threat actors from the latest cyber threat news.")

# ------------------ Fetch data ------------------
@st.cache_data(show_spinner=True)
def load_data(days=7):
    if fetch_news:
        df = fetch_news(days)
        if df.empty:
            st.warning("No articles found in the last 7 days.")
        return df
    return pd.DataFrame()

df = load_data()

if df.empty:
    st.stop()

# ------------------ Prepare data for heatmaps ------------------
# Explode TTPs if stored as lists
if "ttp_desc" in df.columns:
    df_exploded = df.explode("ttp_desc")
else:
    df_exploded = df.copy()

# Explode affected_countries if exists
if "affected_countries" in df_exploded.columns:
    df_exploded = df_exploded.explode("affected_countries")

# --- Heatmap: Techniques by Country ---
if "affected_countries" in df_exploded.columns and "ttp_desc" in df_exploded.columns:
    country_data = (
        df_exploded.groupby(["affected_countries", "ttp_desc"])
        .size()
        .reset_index(name="count")
    )
    if not country_data.empty:
        heatmap_country = country_data.pivot(
            index="ttp_desc", columns="affected_countries", values="count"
        ).fillna(0)
        fig_country = px.imshow(
            heatmap_country,
            text_auto=True,
            color_continuous_scale="YlOrRd",
            aspect="auto",
        )
        fig_country.update_layout(
            title="Techniques by Affected Country",
            xaxis_title="Country",
            yaxis_title="Technique",
            margin=dict(l=100, r=50, t=80, b=150),
        )
        st.plotly_chart(fig_country, use_container_width=True)

# --- Heatmap: Techniques by Threat Actor ---
if "threat_actor" in df_exploded.columns and "ttp_desc" in df_exploded.columns:
    actor_data = (
        df_exploded.groupby(["threat_actor", "ttp_desc"])
        .size()
        .reset_index(name="count")
    )
    if not actor_data.empty:
        heatmap_actor = actor_data.pivot(
            index="ttp_desc", columns="threat_actor", values="count"
        ).fillna(0)
        fig_actor = px.imshow(
            heatmap_actor,
            text_auto=True,
            color_continuous_scale="YlOrRd",
            aspect="auto",
        )
        fig_actor.update_layout(
            title="Techniques by Threat Actor",
            xaxis_title="Threat Actor",
            yaxis_title="Technique",
            margin=dict(l=100, r=50, t=80, b=150),
        )
        st.plotly_chart(fig_actor, use_container_width=True)

# --- Optional: Show raw data ---
with st.expander("Show raw data"):
    st.dataframe(df)
