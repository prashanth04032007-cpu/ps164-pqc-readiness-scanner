from pathlib import Path
from datetime import datetime

class AlertEngine:
    def __init__(self, db, blacklist_path="data/blacklist.txt"):
        self.db = db
        self.blacklist_path = blacklist_path
        self.blacklist = self._load()

    def _load(self):
        p = Path(self.blacklist_path)
        if not p.exists():
            return set()
        return {
            line.strip().upper().replace(" ", "")
            for line in p.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }

    def check(self, plate, camera_id, timestamp):
        plate = plate.upper().replace(" ", "")
        if plate in self.blacklist:
            self.db.add_alert(
                plate=plate,
                alert_type="BLACKLIST_MATCH",
                camera_id=camera_id,
                timestamp=timestamp,
                severity="HIGH",
                details="Plate matched the configured blacklist."
            )
            return True
        return False
