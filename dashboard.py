#!/usr/bin/env python3
import streamlit as st
import pandas as pd
import plotly.express as px
import os
import itertools
from plotly.colors import sequential
import numpy as np

# Import news fetcher from your repo
from threat_intel import fetch_news

st.set_page_config(page_title="Threat Intel Dashboard", layout="wide")

# -------------------------------
# Fetch Threat Intelligence News
# -------------------------------
st.sidebar.header("📰 Latest Threat Intel News")
try:
    news_items = fetch_news()  # make sure threat_intel.py defines this
    if news_items:
        for item in news_items:
            title = item.get("title", "Untitled")
            url = item.get("url", "#")
            st.sidebar.markdown(f"- [{title}]({url})")
    else:
        st.sidebar.write("No news available.")
except Exception as e:
    st.sidebar.error(f"Failed to fetch news: {e}")

# -------------------------------
# Load Excel Data
# -------------------------------
latest_file = "ttp_reports.xlsx"
if not os.path.exists(latest_file):
    st.error(f"❌ No Excel file found: {latest_file}. Run the tracker first.")
    st.stop()

st.sidebar.success(f"Using report: {os.path.basename(latest_file)}")
xls = pd.ExcelFile(latest_file)

# Pick sheets
items = pd.read_excel(xls, sheet_name=xls.sheet_names[0])
counts = pd.read_excel(xls, sheet_name=xls.sheet_names[1]) if len(xls.sheet_names) > 1 else pd.DataFrame()

# -------------------------------
# Helper: heatmap builder
# -------------------------------
def plot_heatmap(df, x_col, y_col, title):
    x_vals, y_vals = df[x_col].unique(), df[y_col].unique()
    full = pd.DataFrame(list(itertools.product(x_vals, y_vals)), columns=[x_col, y_col])
    df_full = pd.merge(full,
                       df.groupby([x_col, y_col]).size().reset_index(name="count"),
                       on=[x_col, y_col], how="left")
    hm = df_full.pivot(index=y_col, columns=x_col, values="count")
    hm_filled = hm.fillna(-1)

    # Colors: black for missing, smooth yellow gradient otherwise
    colorscale = [[0, "black"]] + [
        [i / (len(sequential.YlOrBr) - 1), c] for i, c in enumerate(sequential.YlOrBr)
    ]

    fig = px.imshow(hm_filled, color_continuous_scale=colorscale, text_auto=False)
    fig.update_layout(
        title=title,
        autosize=True,
        height=700,
        margin=dict(l=30, r=30, t=50, b=30),
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        font=dict(color="white")
    )
    return fig

# -------------------------------
# Dashboard Layout
# -------------------------------
st.title("Threat Intelligence Dashboard")
st.caption(f"Source: **{os.path.basename(latest_file)}**")

# Top metrics
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Articles", len(items))
with col2:
    ttp_cols = [c for c in items.columns if c.lower().startswith("ttp_desc")]
    if ttp_cols:
        all_ttps = pd.concat([items[c] for c in ttp_cols]).dropna()
        unique_ttps = all_ttps[all_ttps != "None"].nunique()
    else:
        unique_ttps = 0
    st.metric("Unique MITRE TTPs", unique_ttps)
with col3:
    st.metric("Sources", items['source'].nunique() if 'source' in items else 0)

# Techniques by Country
country_cols = [c for c in items.columns if c.lower().startswith("country_")]
if country_cols and ttp_cols:
    st.subheader("Techniques by Country")
    melted = (
        items.melt(id_vars=country_cols, value_vars=ttp_cols, var_name="ttp_col", value_name="TTP")
             .dropna(subset=["TTP"])
             .loc[lambda df: df["TTP"] != "None"]
             .melt(id_vars=["TTP"], value_vars=country_cols, var_name="country_col", value_name="country")
             .dropna(subset=["country"])
             .loc[lambda df: df["country"] != "None"]
    )
    if not melted.empty:
        fig_ct = plot_heatmap(melted.assign(count=1), x_col="country", y_col="TTP", title="MITRE Techniques per Country")
        st.plotly_chart(fig_ct, use_container_width=True)

# Techniques by Threat Actor
if "threat_actor" in items.columns and ttp_cols:
    st.subheader("Techniques by Threat Actor")
    melted = (
        items.melt(id_vars=["threat_actor"], value_vars=ttp_cols, var_name="ttp_col", value_name="TTP")
             .dropna(subset=["TTP", "threat_actor"])
             .loc[lambda df: (df["TTP"] != "None") & (df["threat_actor"] != "None")]
    )
    if not melted.empty:
        fig_at = plot_heatmap(melted.assign(count=1), x_col="threat_actor", y_col="TTP", title="MITRE Techniques by Threat Actor")
        st.plotly_chart(fig_at, use_container_width=True)
