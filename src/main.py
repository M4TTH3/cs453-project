import argparse
import asyncio
import os
from pathlib import Path
from loguru import logger

from exception import FileNotInDataError, NotInDockerError
from encrypt import Encrypter
from simulation import Detector, FileMutator, Simulator
from detectors import WriteBurstDetector
from file_mutator import NoMutation, ReadOnlyMutator, ReverseMutator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="detector", description="Entropy detector and utilities")
    parser.add_argument(
        "--data-dir", type=Path, default=Path("data/"), help="Directory to run simulations on"
    )
    parser.add_argument(
        "--results-dir", type=Path, default=Path("results/"), help="Directory to save run logs to"
    )

    return parser.parse_args()


def allowed_files(data_dir: Path) -> set[Path]:
    if not data_dir.is_dir():
        raise FileNotInDataError()

    return {p for p in data_dir.rglob("*") if p.is_file()}

async def run_simulations(
    simulator: Simulator, simulations: list[tuple[Detector, FileMutator]], results_dir: Path
) -> None:
    for detector, mutator in simulations:
        name = f"{type(detector).__name__}-with-{type(mutator).__name__}"
        result = await simulator.run(detector, mutator, log_path=results_dir / f"{name}.log")
        logger.info(f"{name}: {result}")


@logger.catch(reraise=True)
def main():
    if os.environ.get("DOCKER_ENV") != "true":
        raise NotInDockerError()

    args = parse_args()

    simulations: list[tuple[Detector, FileMutator]] = [
        (WriteBurstDetector(), ReverseMutator()),
        (WriteBurstDetector(), ReadOnlyMutator()),
        (WriteBurstDetector(), NoMutation()),
    ]

    simulator = Simulator(args.data_dir)
    asyncio.run(run_simulations(simulator, simulations, args.results_dir))


if __name__ == "__main__":
    main()
