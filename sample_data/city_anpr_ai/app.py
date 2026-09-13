import argparse
import cv2
from src.config import load_config
from src.database import Database
from src.pipeline import ANPRPipeline

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=None, help="Video path or camera URL")
    parser.add_argument("--camera", default="CAM_001")
    parser.add_argument("--display", action="store_true")
    parser.add_argument("--max-frames", type=int, default=0)
    args = parser.parse_args()

    cfg = load_config("config.yaml")
    db = Database(cfg["app"]["db_path"])
    pipeline = ANPRPipeline(cfg, db)

    source = args.input or cfg["video"]["input"]
    pipeline.process_video(
        source=source,
        camera_id=args.camera,
        display=args.display,
        max_frames=args.max_frames
    )

if __name__ == "__main__":
    main()
