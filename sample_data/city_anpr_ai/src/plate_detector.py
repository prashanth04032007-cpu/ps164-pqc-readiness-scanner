import cv2
import numpy as np

class PlateDetector:
    def __init__(self, cfg):
        self.cfg = cfg
        self.use_model = bool(cfg["models"].get("use_plate_model", False))
        self.model = None

        if self.use_model:
            from ultralytics import YOLO
            self.model = YOLO(cfg["models"]["plate_model"])

    def detect(self, vehicle_crop):
        if vehicle_crop is None or vehicle_crop.size == 0:
            return []

        if self.use_model and self.model is not None:
            result = self.model.predict(vehicle_crop, verbose=False)[0]
            output = []
            for b in result.boxes:
                conf = float(b.conf[0])
                if conf < self.cfg["video"]["min_plate_confidence"]:
                    continue
                x1, y1, x2, y2 = map(int, b.xyxy[0].tolist())
                output.append((x1, y1, x2, y2, conf))
            return output

        return self._contour_fallback(vehicle_crop)

    def _contour_fallback(self, img):
        # Quick MVP fallback. It searches for rectangular, plate-like regions.
        # Production accuracy requires a trained plate detector.
        h, w = img.shape[:2]
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        blur = cv2.bilateralFilter(gray, 7, 50, 50)
        edges = cv2.Canny(blur, 70, 180)

        contours, _ = cv2.findContours(
            edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE
        )

        candidates = []
        min_area = self.cfg["plate"]["min_area_ratio"] * w * h
        max_area = self.cfg["plate"]["max_area_ratio"] * w * h

        for c in contours:
            x, y, cw, ch = cv2.boundingRect(c)
            area = cw * ch
            if area < min_area or area > max_area or ch == 0:
                continue
            ratio = cw / float(ch)
            if not (self.cfg["plate"]["min_aspect_ratio"] <= ratio <=
                    self.cfg["plate"]["max_aspect_ratio"]):
                continue

            score = min(ratio / 6.0, 1.0)
            candidates.append((x, y, x+cw, y+ch, score))

        candidates.sort(key=lambda x: x[-1], reverse=True)
        return candidates[:3]
