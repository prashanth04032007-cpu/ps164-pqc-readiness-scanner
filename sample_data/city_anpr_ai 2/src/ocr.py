import re
from collections import defaultdict
import easyocr

class PlateOCR:
    def __init__(self, languages=None):
        languages = languages or ["en"]
        self.reader = easyocr.Reader(languages, gpu=False)

    @staticmethod
    def normalize(text):
        text = text.upper().replace(" ", "").replace("-", "")
        text = re.sub(r"[^A-Z0-9]", "", text)
        return text

    def read(self, image):
        if image is None:
            return "", 0.0

        results = self.reader.readtext(image, detail=1, paragraph=False)
        if not results:
            return "", 0.0

        best = max(results, key=lambda x: float(x[2]))
        text = self.normalize(best[1])
        conf = float(best[2])
        return text, conf


class TemporalPlateFusion:
    """Collect OCR observations for one tracked vehicle and choose the
    strongest temporally consistent plate string."""
    def __init__(self, max_items=12):
        self.max_items = max_items
        self.history = defaultdict(list)

    def add(self, vehicle_id, text, confidence):
        if not text:
            return
        self.history[vehicle_id].append((text, confidence))
        self.history[vehicle_id] = self.history[vehicle_id][-self.max_items:]

    def best(self, vehicle_id):
        items = self.history.get(vehicle_id, [])
        if not items:
            return "", 0.0

        # Weighted vote by normalized string.
        scores = defaultdict(float)
        for text, conf in items:
            scores[text] += conf

        winner = max(scores, key=scores.get)
        confs = [c for t, c in items if t == winner]
        return winner, sum(confs) / len(confs)
