from datetime import datetime

def record_trajectory(db, plate, camera_id, timestamp, camera_meta):
    if not plate:
        return
    db.add_trajectory_point(plate, camera_id, timestamp, camera_meta)
