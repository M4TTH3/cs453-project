"""
score_dataset.py writes the Shannon entropy and DAA score of every file in a data directory to a
CSV, one row per file

The encrypted samples are 7z archives, which start with a fixed 32-byte header that is not
encrypted. DAA skips that header on any file with the 7z signature so those samples are scored on
their encrypted content. calculate_daa itself always scores from byte 0.
"""

import argparse
import csv
from pathlib import Path

from loguru import logger

from entropy_analysis import calculate_daa, calculate_shannon

FIELDS = ["category", "file", "size", "shannon", "daa", "daa_offset"]

SEVEN_ZIP_SIGNATURE = b"7z\xbc\xaf\x27\x1c"
SEVEN_ZIP_HEADER = 32


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="score_dataset", description="Score files with Shannon entropy and DAA"
    )
    parser.add_argument(
        "--data-dir", type=Path, default=Path("data/"), help="Directory of files to score"
    )
    parser.add_argument(
        "--out", type=Path, default=Path("results/entropy_scores.csv"), help="CSV to write"
    )

    return parser.parse_args()


def score(fp: Path) -> dict[str, object]:
    data = fp.read_bytes()
    skip = SEVEN_ZIP_HEADER if data.startswith(SEVEN_ZIP_SIGNATURE) else 0
    return {
        "category": fp.parent.name,
        "file": fp.name,
        "size": len(data),
        "shannon": calculate_shannon(data),
        "daa": calculate_daa(data[skip:]),
        "daa_offset": skip,
    }


@logger.catch(reraise=True)
def main():
    args = parse_args()
    if not args.data_dir.is_dir():
        raise FileNotFoundError(f"no directory at {args.data_dir}")

    files = sorted(
        p for p in args.data_dir.rglob("*") if p.is_file() and not p.name.startswith(".")
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for fp in files:
            writer.writerow(score(fp))

    logger.info(f"scored {len(files)} files from {args.data_dir} into {args.out}")


if __name__ == "__main__":
    main()
