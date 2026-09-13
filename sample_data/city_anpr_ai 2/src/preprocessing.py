import cv2
import numpy as np

def preprocess_plate(img):
    if img is None or img.size == 0:
        return None

    # Resize for OCR consistency
    h, w = img.shape[:2]
    target_w = max(160, w * 3)
    target_h = max(48, h * 3)
    img = cv2.resize(img, (target_w, target_h), interpolation=cv2.INTER_CUBIC)

    # Mild denoise + contrast enhancement
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    gray = cv2.bilateralFilter(gray, 7, 50, 50)

    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)

    # OCR benefits from a clean grayscale image
    return enhanced
