import streamlit as st
import pandas as pd
import plotly.express as px
import json
from scanner import scan_file
from mosca_engine import evaluate_asset_risk
from cbom_formatter import export_cyclonedx_cbom, get_recommendation

st.set_page_config(page_title="PQC Readiness Scanner (PS-164)", layout="wide")

st.title("🛡️ PQC Discovery & Quantum Risk Assessment Platform (PS-164)")
st.caption("Standardized Cryptographic Bill of Materials (CBOM) & Mosca Inequality Risk Engine")

# --- SIDEBAR CONFIGURATION ---
st.sidebar.header("Mosca's Inequality Configuration")
st.sidebar.markdown("**Formula:** $X + Y > Z \\implies \\text{CRITICAL}$")

z_crqc = st.sidebar.slider("Years until CRQC Arrival (Z)", min_value=1, max_value=30, value=10)
x_life = st.sidebar.number_input("Data Shelf-Life (X years)", min_value=1, max_value=50, value=20)
y_mig = st.sidebar.number_input("Migration Time (Y years)", min_value=1, max_value=10, value=3)

total_exposure = x_life + y_mig
st.sidebar.info(f"Exposure Window ($X+Y$): **{total_exposure} years**\n\nCRQC Horizon ($Z$): **{z_crqc} years**")

# --- MAIN FILE UPLOADER ---
uploaded_files = st.file_uploader(
    "Upload Assets (C/C++ Source, Java, Python, Go, Certificates, Manifests)", 
    accept_multiple_files=True,
    type=['c', 'cpp', 'h', 'java', 'py', 'go', 'pem', 'crt', 'txt', 'xml', 'json']
)

if uploaded_files:
    all_findings = []
    
    for uploaded_file in uploaded_files:
        content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
        findings = scan_file(content, uploaded_file.name)
        all_findings.extend(findings)
        
    if all_findings:
        df = pd.DataFrame(all_findings)
        
        # Calculate Per-Asset Mosca Risk
        risk_results = df.apply(
            lambda row: evaluate_asset_risk(row['quantum_status'], x_life, y_mig, z_crqc), 
            axis=1
        )
        
        df['Risk Tier'] = [r['tier'] for r in risk_results]
        df['Action'] = [r['action'] for r in risk_results]
        
        # Recommendations Mapping
        recs = df['algorithm'].apply(get_recommendation).apply(pd.Series)
        df['PQC Replacement'] = recs['replacement']
        df['Latency Impact'] = recs['latency']
        df['Migration Cost'] = recs['cost']

        # --- TOP METRIC CARDS ---
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Scanned Files", len(uploaded_files))
        col2.metric("Crypto Assets Found", len(df))
        col3.metric("Critical Risk Assets", len(df[df['Risk Tier'] == 'CRITICAL']))
        col4.metric("Quantum Safe Assets", len(df[df['Risk Tier'] == 'LOW']))

        st.markdown("---")

        # --- VISUAL DASHBOARD CHARTS ---
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Risk Distribution")
            fig_risk = px.pie(
                df, names='Risk Tier', title="Assets by Risk Level",
                color='Risk Tier',
                color_discrete_map={'CRITICAL': '#ff4b4b', 'HIGH': '#ffa500', 'MEDIUM': '#faca2b', 'LOW': '#28a745'}
            )
            st.plotly_chart(fig_risk, use_container_width=True)

        with c2:
            st.subheader("Detected Cryptographic Algorithms")
            fig_algo = px.bar(
                df['algorithm'].value_counts().reset_index(), 
                x='algorithm', y='count', 
                labels={'algorithm': 'Algorithm', 'count': 'Occurrences'},
                color_discrete_sequence=['#0083B0']
            )
            st.plotly_chart(fig_algo, use_container_width=True)

        # --- CBOM TABLE & INLINE COLUMN FILTERS ---
        st.subheader("Cryptographic Bill of Materials (CBOM) & Vulnerability Report")
        
        # Inline column-aligned filter row
        f_col1, f_col2, f_col3, f_col4 = st.columns(4)
        with f_col1:
            file_search = st.text_input("🔍 Filter by File Name", placeholder="e.g. PatientRecords.java")
        with f_col2:
            algo_search = st.text_input("🔍 Filter by Algorithm", placeholder="e.g. RSA, MD5, SHA-3")
        with f_col3:
            risk_select = st.selectbox(
                "⚡ Filter by Risk Tier", 
                options=["ALL"] + df['Risk Tier'].unique().tolist()
            )
        with f_col4:
            status_select = st.selectbox(
                "🛡️ Filter by Quantum Status", 
                options=["ALL"] + df['quantum_status'].unique().tolist()
            )

        # Apply inline filters
        filtered_df = df.copy()
        if file_search:
            filtered_df = filtered_df[filtered_df['file'].str.contains(file_search, case=False, na=False)]
        if algo_search:
            filtered_df = filtered_df[filtered_df['algorithm'].str.contains(algo_search, case=False, na=False)]
        if risk_select != "ALL":
            filtered_df = filtered_df[filtered_df['Risk Tier'] == risk_select]
        if status_select != "ALL":
            filtered_df = filtered_df[filtered_df['quantum_status'] == status_select]

        display_df = filtered_df[[
            'file', 'line', 'asset_type', 'algorithm', 'quantum_status', 
            'Risk Tier', 'Action', 'PQC Replacement', 'snippet'
        ]]
        
        st.dataframe(display_df, use_container_width=True)

        # --- EXPORT BUTTONS ---
        st.subheader("Export Standardized CBOM Reports")
        col_exp1, col_exp2 = st.columns(2)
        
        cbom_json = export_cyclonedx_cbom(df)
        col_exp1.download_button(
            label="Download CycloneDX v1.6 CBOM (JSON)",
            data=json.dumps(cbom_json, indent=2),
            file_name="cyclonedx_cbom_1.6.json",
            mime="application/json"
        )
        
        csv_data = df.to_csv(index=False)
        col_exp2.download_button(
            label="Download CBOM Executive Summary (CSV)",
            data=csv_data,
            file_name="cbom_summary.csv",
            mime="text/csv"
        )

    else:
        st.success("No cryptographic algorithms or certificates detected in the uploaded files.")