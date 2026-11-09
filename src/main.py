import argparse
from loguru import logger


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="entropy-detector", description="Entropy detector and utilities for CS453"
    )

    return parser.parse_args()


@logger.catch(reraise=True)
def main():
    pass


if __name__ == "__main__":
    main()
