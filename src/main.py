import argparse
from pathlib import Path
from loguru import logger

from exception import FileNotInDataError
from encrypt import Encrypter


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="detector", description="Entropy detector and utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    key_gen = subparsers.add_parser("key-gen", help="Generate an encryption key and save it")
    key_gen.add_argument("fp", type=Path, help="Path to write the key to")
    key_gen.add_argument("-f", "--force", action="store_true", help="Overwrite the key file")

    return parser.parse_args()


def allowed_files(data_dir: Path) -> set[Path]:
    if not data_dir.is_dir():
        raise FileNotInDataError()

    return {p for p in data_dir.rglob("*") if p.is_file()}


def key_gen(fp: Path, force: bool):
    if fp.exists() and not force:
        raise FileExistsError(f"{fp} already exists, pass --force to overwrite it")

    # Create dir
    fp.parent.mkdir(parents=True, exist_ok=True)

    # Generate key
    key = Encrypter.generate_key()
    Encrypter.save_key(fp, key)
    logger.info(f"Saved key to {fp}")


@logger.catch(reraise=True)
def main():
    args = parse_args()

    # data_dir = Path("data/")
    # allowed = allowed_files(data_dir)

    # e_opts = Encrypter.Options(every_kb=None, allowed=allowed)
    # key = Encrypter.generate_key()
    # encrypter = Encrypter(key, e_opts)

    # print(encrypter.key)

    match args.command:
        case "key-gen":
            key_gen(args.fp, args.force)


if __name__ == "__main__":
    main()
