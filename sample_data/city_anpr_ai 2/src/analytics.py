import pandas as pd

def traffic_summary(df):
    if df is None or df.empty:
        return {
            "vehicles": 0,
            "events": 0,
            "cameras": 0
        }

    return {
        "vehicles": int(df["plate"].nunique()),
        "events": int(len(df)),
        "cameras": int(df["camera_id"].nunique())
    }

def density_by_camera(df):
    if df.empty:
        return pd.DataFrame(columns=["camera_id", "events"])
    out = df.groupby("camera_id").size().reset_index(name="events")
    return out.sort_values("events", ascending=False)

def hourly_flow(df):
    if df.empty:
        return pd.DataFrame(columns=["hour", "events"])
    x = df.copy()
    x["timestamp"] = pd.to_datetime(x["timestamp"], errors="coerce")
    x["hour"] = x["timestamp"].dt.floor("h")
    return x.groupby("hour").size().reset_index(name="events")
