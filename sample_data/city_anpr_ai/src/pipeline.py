import cv2
import os
from datetime import datetime
from pathlib import Path
from ultralytics import YOLO

from .plate_detector import PlateDetector
from .preprocessing import preprocess_plate
from .ocr import PlateOCR, TemporalPlateFusion
from .tracker import CentroidTracker
from .alerts import AlertEngine
from .trajectory import record_trajectory

VEHICLE_CLASSES = {
    2: "car",
    3: "motorcycle",
    5: "bus",
    7: "truck",
}

class ANPRPipeline:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db

        model_name = cfg["models"]["vehicle_model"]
        self.vehicle_model = YOLO(model_name)

        self.plate_detector = PlateDetector(cfg)
        self.ocr = PlateOCR(["en"])
        self.fusion = TemporalPlateFusion()

        self.alerts = AlertEngine(db)

        self.trackers = {}

    def _camera_meta(self, camera_id):
        return self.cfg.get("cameras", {}).get(camera_id, {
            "latitude": None,
            "longitude": None,
            "road": "",
            "direction": ""
        })

    def process_video(self, source, camera_id, display=False, max_frames=0):
        self.db.upsert_camera(camera_id, self._camera_meta(camera_id))
        self.trackers[camera_id] = CentroidTracker(
            max_distance=self.cfg["tracking"]["max_distance"],
            max_disappeared=self.cfg["tracking"]["max_disappeared"]
        )

        cap = cv2.VideoCapture(source)
        if not cap.isOpened():
            raise RuntimeError(f"Cannot open video/camera: {source}")

        frame_index = 0
        processed = 0
        ocr_interval = self.cfg["video"]["ocr_every_n_vehicle_frames"]

        while True:
            ok, frame = cap.read()
            if not ok:
                break

            frame_index += 1
            if frame_index % self.cfg["video"]["frame_skip"] != 0:
                continue

            processed += 1
            if max_frames and processed > max_frames:
                break

            timestamp = datetime.now().isoformat(timespec="seconds")

            result = self.vehicle_model.predict(
                frame,
                verbose=False,
                conf=self.cfg["video"]["min_vehicle_confidence"]
            )[0]

            boxes = []
            types = []
            confs = []

            for b in result.boxes:
                cls_id = int(b.cls[0])
                if cls_id not in VEHICLE_CLASSES:
                    continue
                box = tuple(map(int, b.xyxy[0].tolist()))
                conf = float(b.conf[0])
                boxes.append(box)
                types.append(VEHICLE_CLASSES[cls_id])
                confs.append(conf)

            assignment = self.trackers[camera_id].update(boxes)

            for i, box in enumerate(boxes):
                vehicle_id = assignment.get(i)
                self.db.add_detection(
                    camera_id, timestamp, vehicle_id, types[i],
                    confs[i], box
                )

                # OCR only periodically for speed.
                if frame_index % ocr_interval != 0:
                    continue

                x1, y1, x2, y2 = box
                x1, y1 = max(0, x1), max(0, y1)
                x2, y2 = min(frame.shape[1], x2), min(frame.shape[0], y2)
                vehicle_crop = frame[y1:y2, x1:x2]

                plate_candidates = self.plate_detector.detect(vehicle_crop)
                for px1, py1, px2, py2, pconf in plate_candidates[:1]:
                    px1 = max(0, px1)
                    py1 = max(0, py1)
                    px2 = min(vehicle_crop.shape[1], px2)
                    py2 = min(vehicle_crop.shape[0], py2)

                    plate_img = vehicle_crop[py1:py2, px1:px2]
                    processed_plate = preprocess_plate(plate_img)
                    text, ocr_conf = self.ocr.read(processed_plate)

                    if not text or ocr_conf < self.cfg["video"]["ocr_confidence_threshold"]:
                        continue

                    self.fusion.add(vehicle_id, text, ocr_conf)
                    final_plate, final_conf = self.fusion.best(vehicle_id)

                    meta = self._camera_meta(camera_id)
                    self.db.add_plate_event(
                        camera_id, timestamp, vehicle_id,
                        final_plate, final_conf, meta
                    )
                    record_trajectory(
                        self.db, final_plate, camera_id, timestamp, meta
                    )
                    self.alerts.check(final_plate, camera_id, timestamp)

                    Path("output/plates").mkdir(parents=True, exist_ok=True)
                    cv2.imwrite(
                        f"output/plates/{camera_id}_{vehicle_id}_{frame_index}.jpg",
                        plate_img
                    )

                    if display:
                        cv2.rectangle(
                            frame, (x1, y1), (x2, y2), (0,255,0), 2
                        )
                        cv2.putText(
                            frame, f"{final_plate} {final_conf:.2f}",
                            (x1, max(20, y1-8)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,255,0), 2
                        )

            if display:
                cv2.imshow("City ANPR", frame)
                if cv2.waitKey(1) & 0xFF == 27:
                    break

        cap.release()
        cv2.destroyAllWindows()
