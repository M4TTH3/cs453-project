"""Default detector and workload pairings."""

from detectors import (
    CompositeDetector,
    FileTypeChangeDetector,
    FileVelocityDetector,
    FineTunedHoneyPotDetector,
    HoneyPotDetector,
    WriteBurstDetector,
)
from file_mutator import (
    ArchiveMutator,
    BasicSymmetricEncryptionOverwrite,
    NoMutation,
    PaddedEncryption,
    PartialEncryption,
    PypdfReaderMutator,
    ReadOnlyMutator,
    ReverseMutator,
    SplitProcessEncryption,
    UserEditMutator,
)
from running_entropy_detector import RunningEntropyDetector
from context_detectors.fileType import EnglTxtDetector
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
    FileVelocityDetector: (
        BasicSymmetricEncryptionOverwrite,
        ReverseMutator,
        ReadOnlyMutator,
        ArchiveMutator,
        UserEditMutator,
    ),
    FileTypeChangeDetector: (
        BasicSymmetricEncryptionOverwrite,
        ReverseMutator,
        PartialEncryption,
        PaddedEncryption,
        ReadOnlyMutator,
        ArchiveMutator,
        UserEditMutator,
    ),
    CompositeDetector: (
        BasicSymmetricEncryptionOverwrite,
        PartialEncryption,
        ReadOnlyMutator,
        ArchiveMutator,
        UserEditMutator,
    ),
    EnglTxtDetector: (
        ArchiveMutator,
        BasicSymmetricEncryptionOverwrite,
        PaddedEncryption,
        PartialEncryption,
        ReadOnlyMutator,
        ReverseMutator,
        SplitProcessEncryption,
        UserEditMutator,
        NoMutation,
        )
}


def default_simulations(detector_name: str | None = None) -> list[tuple[Detector, FileMutator]]:
    return [
        (detector(), mutator())
        for detector, mutators in SCENARIOS.items()
        if detector_name is None or detector.__name__ == detector_name
        for mutator in mutators
    ]
