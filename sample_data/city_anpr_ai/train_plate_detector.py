from ultralytics import YOLO

# Start with a small model for development.
# Prepare a YOLO-format dataset using data/plate.yaml.
#
# images/train/*.jpg
# labels/train/*.txt
# images/val/*.jpg
# labels/val/*.txt
#
# Each label:
# class_id x_center y_center width height
#
# Example:
# 0 0.512 0.633 0.210 0.065

model = YOLO("yolo11n.pt")

model.train(
    data="data/plate.yaml",
    epochs=80,
    imgsz=640,
    batch=16,
    workers=4,
    project="runs/plate",
    name="license_plate_detector"
)

print("Training finished.")
print("Copy the best.pt file to models/license_plate.pt")
print("Then set use_plate_model: true in config.yaml")
