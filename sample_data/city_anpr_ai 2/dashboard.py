import streamlit as st
import pandas as pd
import plotly.express as px

from src.config import load_config
from src.database import Database
from src.analytics import traffic_summary, density_by_camera, hourly_flow

st.set_page_config(
    page_title="City ANPR AI Engine",
    layout="wide"
)

cfg = load_config("config.yaml")
db = Database(cfg["app"]["db_path"])

st.title("City-Wide ANPR & Traffic Intelligence")

events = db.all_events()
summary = traffic_summary(events)

c1, c2, c3 = st.columns(3)
c1.metric("Unique plates", summary["vehicles"])
c2.metric("Plate events", summary["events"])
c3.metric("Cameras", summary["cameras"])

st.divider()

tab1, tab2, tab3, tab4 = st.tabs([
    "Live Events", "Vehicle Trajectory", "Traffic Analytics", "Alerts"
])

with tab1:
    st.subheader("Recent ANPR events")
    st.dataframe(db.recent_events(300), use_container_width=True)

with tab2:
    st.subheader("Search vehicle trajectory")
    plates = sorted(events["plate"].dropna().unique().tolist()) if not events.empty else []
    plate = st.selectbox("Plate", [""] + plates)

    if plate:
        traj = db.all_trajectories(plate)
        st.dataframe(traj, use_container_width=True)

        if not traj.empty and {"latitude", "longitude"}.issubset(traj.columns):
            traj = traj.dropna(subset=["latitude", "longitude"])
            if not traj.empty:
                fig = px.line_map(
                    traj,
                    lat="latitude",
                    lon="longitude",
                    hover_name="camera_id",
                    hover_data=["timestamp", "direction"],
                    zoom=12,
                    height=550
                )
                st.plotly_chart(fig, use_container_width=True)

with tab3:
    st.subheader("City traffic analytics")

    density = density_by_camera(events)
    if not density.empty:
        fig = px.bar(
            density,
            x="camera_id",
            y="events",
            title="Vehicle/plate event density by camera"
        )
        st.plotly_chart(fig, use_container_width=True)

    flow = hourly_flow(events)
    if not flow.empty:
        fig = px.line(
            flow,
            x="hour",
            y="events",
            markers=True,
            title="Hourly traffic event flow"
        )
        st.plotly_chart(fig, use_container_width=True)

with tab4:
    st.subheader("Alerts")
    st.dataframe(db.alerts(), use_container_width=True)
