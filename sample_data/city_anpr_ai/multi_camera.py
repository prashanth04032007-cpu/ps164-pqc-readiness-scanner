import argparse
from pathlib import Path
from src.config import load_config
from src.database import Database
from src.pipeline import ANPRPipeline

VIDEO_EXTS = {".mp4", ".avi", ".mov", ".mkv"}

def camera_id_from_path(p):
    return p.stem.upper()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", default="input")
    parser.add_argument("--display", action="store_true")
    args = parser.parse_args()

    cfg = load_config("config.yaml")
    db = Database(cfg["app"]["db_path"])
    pipeline = ANPRPipeline(cfg, db)

    videos = [
        p for p in Path(args.folder).iterdir()
        if p.suffix.lower() in VIDEO_EXTS
    ]

    if not videos:
        raise RuntimeError("No videos found in input folder.")

    for video in sorted(videos):
        camera_id = camera_id_from_path(video)
        print(f"Processing {video} as {camera_id}")
        pipeline.process_video(
            str(video), camera_id=camera_id, display=args.display
        )

if __name__ == "__main__":
    main()
