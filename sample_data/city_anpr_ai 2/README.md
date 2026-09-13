# City-Wide ANPR AI Engine — MVP

This project is a runnable prototype for PS 26127:
"City-Wide AI Engine for Multi-Camera ANPR Trajectory Tracking and Urban Traffic Analytics."

## What is included

1. Video/camera ingestion
2. Vehicle detection with Ultralytics YOLO
3. Per-camera vehicle tracking using centroid association
4. License-plate detection:
   - optional custom YOLO plate detector, or
   - OpenCV contour-based fallback for a quick MVP
5. Plate image preprocessing
6. OCR using EasyOCR
7. Multi-frame OCR aggregation
8. Vehicle event storage in SQLite
9. Multi-camera trajectory reconstruction
10. Blacklist alerts
11. Traffic density and average-speed analytics
12. Streamlit dashboard
13. YOLO plate-model training starter

## Important

The repository does NOT contain model weights. On first run, Ultralytics can download the vehicle model automatically if internet access is available.

For high-accuracy production ANPR, train a dedicated license-plate detector and use `models/license_plate.pt`. The contour fallback is intended only for a prototype and is not a substitute for a trained plate detector.

## Windows setup

```powershell
cd city_anpr_ai
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Put a traffic video at:

```text
input\traffic.mp4
```

Run:

```powershell
python app.py --input input/traffic.mp4 --camera CAM_001
```

Then start the dashboard in another terminal:

```powershell
streamlit run dashboard.py
```

Open the URL shown by Streamlit.

## Process multiple cameras

Create a folder:

```text
input/
  cam001.mp4
  cam002.mp4
  cam003.mp4
```

Then:

```powershell
python multi_camera.py --folder input
```

Camera IDs are taken from filenames (`cam001` -> `CAM001`) unless overridden in the script.

## Blacklist

Edit:

```text
data/blacklist.txt
```

One plate per line.

Example:

```text
AP39XX1234
KA01AB1234
```

## Database

SQLite database:

```text
data/anpr.db
```

Tables:
- cameras
- detections
- plate_events
- trajectories
- alerts

## Accuracy improvements

For the intended system, use:
- a dedicated Indian license-plate detector
- perspective rectification
- multi-frame OCR fusion
- character-level confidence
- plate-format validation
- vehicle appearance embeddings/re-identification
- road-network constraints
- camera calibration
- diverse day/night/rain/blur training data

## Speed improvements

- frame skipping
- vehicle tracking instead of detecting/OCR every frame
- OCR only on selected high-quality frames
- ROI processing
- GPU inference
- asynchronous camera workers
- edge inference
- event-based central processing

## Training a plate detector

Organize a YOLO dataset:

```text
data/plate_dataset/
  images/train/
  images/val/
  labels/train/
  labels/val/
```

Then update `data/plate.yaml` and run:

```powershell
python train_plate_detector.py
```

The resulting weights can be copied to:

```text
models/license_plate.pt
```

and enabled in `config.yaml`.

## Architecture

```text
Camera
  -> Frame sampling
  -> Vehicle detection
  -> Vehicle tracking
  -> Plate detection
  -> Plate preprocessing
  -> OCR
  -> Multi-frame fusion
  -> Vehicle event
  -> SQLite/event store
       |-> Trajectory engine
       |-> Traffic analytics
       |-> Alert engine
       -> GIS/dashboard
```

## Production warning

This MVP is intended for controlled testing and development. Real-world deployment requires representative data, model validation, camera calibration, privacy/access controls, audit logging, security hardening, and accuracy testing before operational use.
