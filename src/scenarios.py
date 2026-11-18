"""Default detector and workload pairings."""

from detectors import FineTunedHoneyPotDetector, HoneyPotDetector, WriteBurstDetector
from file_mutator import (
    BasicSymmetricEncryptionOverwrite,
    NoMutation,
    PaddedEncryption,
    PartialEncryption,
    PypdfReaderMutator,
    ReadOnlyMutator,
    ReverseMutator,
    SplitProcessEncryption,
)
from running_entropy_detector import RunningEntropyDetector
from simulation import Detector, FileMutator

SCENARIOS: dict[type[Detector], tuple[type[FileMutator], ...]] = {
    WriteBurstDetector: (ReverseMutator, ReadOnlyMutator, NoMutation),
    HoneyPotDetector: (PypdfReaderMutator, BasicSymmetricEncryptionOverwrite),
    FineTunedHoneyPotDetector: (
        PypdfReaderMutator,
        BasicSymmetricEncryptionOverwrite,
        PartialEncryption,
    ),
    RunningEntropyDetector: (
        ReadOnlyMutator,
        ReverseMutator,
        NoMutation,
        BasicSymmetricEncryptionOverwrite,
        SplitProcessEncryption,
        PartialEncryption,
        PaddedEncryption,
    ),
}


def default_simulations(detector_name: str | None = None) -> list[tuple[Detector, FileMutator]]:
    return [
        (detector(), mutator())
        for detector, mutators in SCENARIOS.items()
        if detector_name is None or detector.__name__ == detector_name
        for mutator in mutators
    ]
