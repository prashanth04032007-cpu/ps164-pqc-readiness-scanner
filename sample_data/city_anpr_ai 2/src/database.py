import sqlite3
from pathlib import Path
from datetime import datetime

class Database:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._init()

    def conn(self):
        return sqlite3.connect(self.path)

    def _init(self):
        with self.conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS cameras (
                camera_id TEXT PRIMARY KEY,
                latitude REAL,
                longitude REAL,
                road TEXT,
                direction TEXT,
                status TEXT DEFAULT 'ONLINE'
            );

            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                camera_id TEXT,
                timestamp TEXT,
                vehicle_id INTEGER,
                vehicle_type TEXT,
                vehicle_confidence REAL,
                x1 INTEGER, y1 INTEGER, x2 INTEGER, y2 INTEGER
            );

            CREATE TABLE IF NOT EXISTS plate_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                camera_id TEXT,
                timestamp TEXT,
                vehicle_id INTEGER,
                plate TEXT,
                ocr_confidence REAL,
                latitude REAL,
                longitude REAL,
                direction TEXT
            );

            CREATE TABLE IF NOT EXISTS trajectories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plate TEXT,
                camera_id TEXT,
                timestamp TEXT,
                latitude REAL,
                longitude REAL,
                direction TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plate TEXT,
                alert_type TEXT,
                camera_id TEXT,
                timestamp TEXT,
                severity TEXT,
                details TEXT
            );
            """)

    def upsert_camera(self, camera_id, meta):
        with self.conn() as c:
            c.execute("""
            INSERT INTO cameras(camera_id, latitude, longitude, road, direction, status)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(camera_id) DO UPDATE SET
                latitude=excluded.latitude,
                longitude=excluded.longitude,
                road=excluded.road,
                direction=excluded.direction,
                status='ONLINE'
            """, (
                camera_id, meta.get("latitude"), meta.get("longitude"),
                meta.get("road"), meta.get("direction")
            ))

    def add_detection(self, camera_id, timestamp, vehicle_id, vehicle_type,
                      conf, box):
        with self.conn() as c:
            c.execute("""
            INSERT INTO detections
            (camera_id,timestamp,vehicle_id,vehicle_type,vehicle_confidence,
             x1,y1,x2,y2)
            VALUES(?,?,?,?,?,?,?,?,?)
            """, (camera_id, timestamp, vehicle_id, vehicle_type, conf, *box))

    def add_plate_event(self, camera_id, timestamp, vehicle_id, plate,
                        conf, meta):
        with self.conn() as c:
            c.execute("""
            INSERT INTO plate_events
            (camera_id,timestamp,vehicle_id,plate,ocr_confidence,
             latitude,longitude,direction)
            VALUES(?,?,?,?,?,?,?,?)
            """, (
                camera_id, timestamp, vehicle_id, plate, conf,
                meta.get("latitude"), meta.get("longitude"),
                meta.get("direction")
            ))

    def add_trajectory_point(self, plate, camera_id, timestamp, meta):
        with self.conn() as c:
            c.execute("""
            INSERT INTO trajectories
            (plate,camera_id,timestamp,latitude,longitude,direction)
            VALUES(?,?,?,?,?,?)
            """, (
                plate, camera_id, timestamp,
                meta.get("latitude"), meta.get("longitude"),
                meta.get("direction")
            ))

    def add_alert(self, plate, alert_type, camera_id, timestamp,
                  severity, details):
        with self.conn() as c:
            c.execute("""
            INSERT INTO alerts
            (plate,alert_type,camera_id,timestamp,severity,details)
            VALUES(?,?,?,?,?,?)
            """, (plate, alert_type, camera_id, timestamp, severity, details))

    def recent_events(self, limit=500):
        import pandas as pd
        with self.conn() as c:
            return pd.read_sql_query(
                "SELECT * FROM plate_events ORDER BY id DESC LIMIT ?",
                c, params=(limit,)
            )

    def all_events(self):
        import pandas as pd
        with self.conn() as c:
            return pd.read_sql_query(
                "SELECT * FROM plate_events ORDER BY timestamp", c
            )

    def all_trajectories(self, plate=None):
        import pandas as pd
        with self.conn() as c:
            if plate:
                return pd.read_sql_query(
                    "SELECT * FROM trajectories WHERE plate=? ORDER BY timestamp",
                    c, params=(plate,)
                )
            return pd.read_sql_query(
                "SELECT * FROM trajectories ORDER BY timestamp", c
            )

    def alerts(self):
        import pandas as pd
        with self.conn() as c:
            return pd.read_sql_query(
                "SELECT * FROM alerts ORDER BY id DESC", c
            )

    def cameras(self):
        import pandas as pd
        with self.conn() as c:
            return pd.read_sql_query("SELECT * FROM cameras", c)
