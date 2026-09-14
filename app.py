import streamlit as st
import pandas as pd
import plotly.express as px
import json
from scanner import scan_file
from mosca_engine import derive_asset_context, evaluate_asset_risk
from cbom_formatter import export_cyclonedx_cbom, get_recommendation

st.set_page_config(page_title="Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)", layout="wide")

st.title("🛡️ Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)")
st.caption("Standardized Cryptographic Bill of Materials (CBOM) & Per-Asset Quantum Risk Engine")

# --- SIDEBAR CONFIGURATION ---
st.sidebar.header("Risk Calculation & Scenario Settings")
calc_method = st.sidebar.radio(
    "Select Assessment Technique:",
    options=[
        "Standard Mosca Inequality (X + Y > Z)",
        "Sensitivity-Weighted QPS (W × max(1, (X+Y)/Z))",
        "Data Shelf-Life Ratio (X / Z)"
    ]
)

st.sidebar.markdown("---")
st.sidebar.subheader("CRQC Horizon Assumption ($Z$)")
z_crqc = st.sidebar.slider(
    "Assumed Years until CRQC Arrival ($Z$):",
    min_value=5, max_value=25, value=10, step=1
)
st.sidebar.caption("📌 Note: Z is a global scenario horizon assumption, whereas X (Shelf-Life) and Y (Migration Time) are dynamically evaluated per-asset.")

st.sidebar.markdown("---")
st.sidebar.subheader("Global Environment & Defaults Override")
default_env = st.sidebar.selectbox("Default Deployment Environment:", ["Production", "Staging", "Testing", "Development", "Cloud", "Edge"])
enable_simulation = st.sidebar.toggle("🔬 Enable PQC Migration Simulation Mode", value=False)

# Ignore generated output files so they are never re-scanned (P0 Fix #3)
IGNORE_FILES = {"cbom_report.json", "cyclonedx_cbom_1.6.json", "cbom.json", "cbom_summary.csv"}

# --- MAIN FILE UPLOADER ---
uploaded_files = st.file_uploader(
    "Upload Assets (C/C++ Source, Java, Python, Go, Certificates, Manifests, Binaries)", 
    accept_multiple_files=True,
    type=['c', 'cpp', 'h', 'java', 'py', 'go', 'pem', 'crt', 'txt', 'xml', 'json', 'jar', 'so', 'dll']
)

if uploaded_files:
    all_findings = []
    
    for uploaded_file in uploaded_files:
        if uploaded_file.name in IGNORE_FILES:
            continue
            
        content = uploaded_file.getvalue()
        findings = scan_file(content, uploaded_file.name)
        
        for f in findings:
            ctx = derive_asset_context(f)
            f.update(ctx)  # Merges 'quantum_status', 'purpose', 'risk_score', etc.
            f['file'] = uploaded_file.name
            f['line'] = f.get('line', 1)
            f['environment'] = f.get('environment', default_env)
            f['classical_status'] = f.get('classical_status', 'SECURE')
            f['confidence'] = f.get('confidence', 0.98)
            
        all_findings.extend(findings)
        
    if all_findings:
        df = pd.DataFrame(all_findings)
        
        # Apply Simulation mode if toggled on
        if enable_simulation:
            def simulate_pqc(row):
                algo = str(row.get('algorithm', '')).upper()
                purpose = str(row.get('purpose', ''))
                q_status = str(row.get('quantum_status', ''))
                if q_status == 'QUANTUM-VULNERABLE':
                    if purpose == 'key_establishment' or 'RSA' in algo or 'ECDH' in algo:
                        row['algorithm'] = 'ML-KEM-768'
                        row['quantum_status'] = 'PQC-STANDARDIZED'
                    elif purpose == 'digital_signature' or 'ECDSA' in algo:
                        row['algorithm'] = 'ML-DSA-65'
                        row['quantum_status'] = 'PQC-STANDARDIZED'
                    elif 'SHA-1' in algo:
                        row['algorithm'] = 'SHA-256'
                        row['quantum_status'] = 'QUANTUM-RESISTANT'
                    elif '3DES' in algo:
                        row['algorithm'] = 'AES-256'
                        row['quantum_status'] = 'QUANTUM-RESISTANT'
                return row
            df = df.apply(simulate_pqc, axis=1)

        # Evaluate per-asset risk
        risk_results = df.apply(
            lambda row: evaluate_asset_risk(
                algorithm=row.get('algorithm', 'UNKNOWN'),
                purpose=row.get('purpose', 'unknown'),
                quantum_status=row.get('quantum_status', 'QUANTUM-VULNERABLE'),
                classical_status=row.get('classical_status', 'SECURE'),
                x_shelf_life=float(row.get('x_shelf_life', 5.0)),
                y_migration_time=float(row.get('y_migration_time', 2.0)),
                z_crqc_horizon=z_crqc,
                data_sensitivity=int(row.get('data_sensitivity', 3)),
                business_criticality=int(row.get('business_criticality', 3)),
                method=calc_method
            ), 
            axis=1
        )
        
        df['X (Shelf-Life yrs)'] = [r['X'] for r in risk_results]
        df['Y (Migration yrs)'] = [r['Y'] for r in risk_results]
        df['Z (CRQC Horizon yrs)'] = [r['Z'] for r in risk_results]
        df['Risk Tier'] = [r['tier'] for r in risk_results]
        df['Priority'] = [r['priority'] for r in risk_results]
        df['Action'] = [r['action'] for r in risk_results]
        df['Metric Value'] = [r['metric_value'] for r in risk_results]
        df['Metric Label'] = [r['metric_label'] for r in risk_results]
        df['Risk Explanation'] = [r['explanation'] for r in risk_results]
        
        recs = df['algorithm'].apply(get_recommendation).apply(pd.Series)
        df['PQC Replacement'] = recs['replacement']
        df['Latency Impact'] = recs['latency']
        df['Migration Cost'] = recs['cost']

        if enable_simulation:
            st.warning("🔬 **SIMULATION ACTIVE:** Displaying post-migration inventory state. Vulnerable assets have been mapped to NIST PQC recommendations.")

        # --- TOP EXECUTIVE METRIC CARDS ---
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Scanned Files", len(uploaded_files))
        col2.metric("Crypto Assets Found", len(df))
        col3.metric("Critical Risk (CRITICAL)", len(df[df['Risk Tier'] == 'CRITICAL']))
        col4.metric("P0 Immediate Priority", len(df[df['Priority'] == 'P0'])) 
        col5.metric("Avg Exposure Score", round(df['Metric Value'].mean(), 2))

        st.markdown("---")

        # --- VISUAL DASHBOARD CHARTS ---
        c1, c2, c3 = st.columns(3)
        with c1:
            st.subheader("Risk Distribution")
            fig_risk = px.pie(
                df, names='Risk Tier',
                color='Risk Tier',
                color_discrete_map={'CRITICAL': '#ff4b4b', 'HIGH': '#ffa500', 'MEDIUM': '#faca2b', 'LOW': '#28a745'}
            )
            st.plotly_chart(fig_risk, use_container_width=True)

        with c2:
            st.subheader("Migration Priority Breakdown")
            fig_prio = px.bar(
                df['Priority'].value_counts().reset_index(),
                x='Priority', y='count',
                color='Priority',
                color_discrete_map={'P0': '#ff4b4b', 'P1': '#ffa500', 'P2': '#faca2b', 'P3': '#28a745'}
            )
            st.plotly_chart(fig_prio, use_container_width=True)

        with c3:
            st.subheader("Unique Algorithms Breakdown")
            fig_algo = px.bar(
                df['algorithm'].value_counts().reset_index(),
                x='algorithm', y='count',
                color='algorithm',
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            st.plotly_chart(fig_algo, use_container_width=True)

        # --- CBOM TABLE & INLINE COLUMN FILTERS ---
        st.subheader("Cryptographic Bill of Materials (CBOM) & Risk Report")
        st.info(f"Active Formula: **{calc_method}** | Displaying per-asset X, Y, Z, purpose, and migration priorities.")
        
        f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns(5)
        with f_col1:
            file_search = st.text_input("🔍 Filter by File Name", placeholder="e.g. PaymentService.java")
        with f_col2:
            algo_search = st.text_input("🔍 Filter by Algorithm", placeholder="e.g. RSA, MD5, SHA-3")
        with f_col3:
            risk_select = st.selectbox(
                "⚡ Filter by Risk Tier", 
                options=["ALL"] + df['Risk Tier'].unique().tolist()
            )
        with f_col4:
            prio_select = st.selectbox(
                "🚨 Filter by Priority", 
                options=["ALL", "P0", "P1", "P2", "P3"]
            )
        with f_col5:
            env_select = st.selectbox(
                "🏢 Filter Environment",
                options=["ALL"] + df['environment'].unique().tolist()
            )

        filtered_df = df.copy()
        if file_search:
            filtered_df = filtered_df[filtered_df['file'].str.contains(file_search, case=False, na=False)]
        if algo_search:
            filtered_df = filtered_df[filtered_df['algorithm'].str.contains(algo_search, case=False, na=False)]
        if risk_select != "ALL":
            filtered_df = filtered_df[filtered_df['Risk Tier'] == risk_select]
        if prio_select != "ALL":
            filtered_df = filtered_df[filtered_df['Priority'] == prio_select]
        if env_select != "ALL":
            filtered_df = filtered_df[filtered_df['environment'] == env_select]

        display_cols = [
            'file', 'line', 'environment', 'asset_type', 'algorithm', 'purpose', 'quantum_status', 
            'X (Shelf-Life yrs)', 'Y (Migration yrs)', 'Z (CRQC Horizon yrs)',
            'Priority', 'Risk Tier', 'PQC Replacement', 'Risk Explanation'
        ]
        
        valid_display_cols = [c for c in display_cols if c in filtered_df.columns]
        st.dataframe(filtered_df[valid_display_cols], use_container_width=True)

        # --- INTERACTIVE ASSET DRILL-DOWN INSPECTOR ---
        st.subheader("🔎 Deep-Dive Asset Inspector")
        asset_options = [f"{row['file']} (Line {row['line']}) - {row['algorithm']} [{row['Risk Tier']}]" for _, row in df.iterrows()]
        selected_asset_label = st.selectbox("Select specific asset to inspect provenance & recommendation logic:", options=asset_options)
        
        if selected_asset_label:
            selected_idx = asset_options.index(selected_asset_label)
            selected_row = df.iloc[selected_idx]
            
            with st.expander(f"Detailed Analysis: {selected_row['algorithm']} in {selected_row['file']}", expanded=True):
                col_d1, col_d2, col_d3 = st.columns(3)
                with col_d1:
                    st.markdown(f"**Source File:** `{selected_row['file']}` (Line {selected_row['line']})")
                    st.markdown(f"**Asset Type:** {selected_row['asset_type']}")
                    st.markdown(f"**Cryptographic Purpose:** `{selected_row.get('purpose', 'unknown')}`")
                    st.markdown(f"**Detection Confidence:** `{int(selected_row.get('confidence', 0.98)*100)}%`")
                with col_d2:
                    st.markdown(f"**Quantum Status:** `{selected_row.get('quantum_status', 'QUANTUM-VULNERABLE')}`")
                    st.markdown(f"**Classical Status:** `{selected_row.get('classical_status', 'SECURE')}`")
                    st.markdown(f"**Data Sensitivity (W):** `{selected_row.get('data_sensitivity', 3)}/5`")
                    st.markdown(f"**Business Criticality:** `{selected_row.get('business_criticality', 3)}/5`")
                with col_d3:
                    st.markdown(f"**Shelf-Life ($X$):** `{selected_row.get('X (Shelf-Life yrs', selected_row.get('X (Shelf-Life yrs)', 0))} yrs`")
                    st.markdown(f"**Migration Time ($Y$):** `{selected_row.get('Y (Migration yrs)', 0)} yrs`")
                    st.markdown(f"**CRQC Horizon ($Z$):** `{selected_row.get('Z (CRQC Horizon yrs)', 0)} yrs`")
                    st.markdown(f"**Assigned Priority:** `🔴 {selected_row['Priority']}`")
                
                st.info(f"**Why is this risky?** {selected_row['Risk Explanation']}")
                st.success(f"**Recommended Action / PQC Target:** Switch to **{selected_row['PQC Replacement']}** (Latency Impact: `{selected_row['Latency Impact']}`, Migration Cost: `{selected_row['Migration Cost']}`).")

        # --- EXPORT BUTTONS ---
        st.subheader("Export Standardized CBOM Reports")
        col_exp1, col_exp2, col_exp3 = st.columns(3)
        
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

        exec_report = {
            "total_files": len(uploaded_files),
            "total_assets": len(df),
            "critical_risks": len(df[df['Risk Tier'] == 'CRITICAL']),
            "p0_priorities": len(df[df['Priority'] == 'P0']),
            "average_exposure_score": round(df['Metric Value'].mean(), 2),
            "findings": df.to_dict(orient="records")
        }
        col_exp3.download_button(
            label="Download Executive Report (JSON)",
            data=json.dumps(exec_report, indent=2),
            file_name="executive_report.json",
            mime="application/json"
        )

    else:
        st.success("No cryptographic algorithms or certificates detected in the uploaded files.")