"""Default detector and workload pairings."""

from detectors import (
    CompositeDetector,
    EarlyFineTunedHoneyPotDetector,
    EarlyHoneyPotDetector,
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
    StagedEncryption,
    UserEditMutator,
)
from running_entropy_detector import RunningEntropyDetector
from simulation import Detector, FileMutator

SCENARIOS: dict[type[Detector], tuple[type[FileMutator], ...]] = {
    WriteBurstDetector: (
        ReverseMutator,
        ReadOnlyMutator,
        NoMutation,
        BasicSymmetricEncryptionOverwrite,
        StagedEncryption,
    ),
    HoneyPotDetector: (
        PypdfReaderMutator,
        ReadOnlyMutator,
        ArchiveMutator,
        UserEditMutator,
        BasicSymmetricEncryptionOverwrite,
        PartialEncryption,
        StagedEncryption,
    ),
    FineTunedHoneyPotDetector: (
        PypdfReaderMutator,
        ReadOnlyMutator,
        ArchiveMutator,
        UserEditMutator,
        BasicSymmetricEncryptionOverwrite,
        PartialEncryption,
        StagedEncryption,
    ),
    # Same two detectors with the decoy moved to the front of the traversal. Comparing each
    # against its pair above separates the trigger from the placement
    EarlyHoneyPotDetector: (
        PypdfReaderMutator,
        ReadOnlyMutator,
        ArchiveMutator,
        UserEditMutator,
        BasicSymmetricEncryptionOverwrite,
        PartialEncryption,
        StagedEncryption,
    ),
    EarlyFineTunedHoneyPotDetector: (
        PypdfReaderMutator,
        ReadOnlyMutator,
        ArchiveMutator,
        UserEditMutator,
        BasicSymmetricEncryptionOverwrite,
        PartialEncryption,
        StagedEncryption,
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
}


def default_simulations(detector_name: str | None = None) -> list[tuple[Detector, FileMutator]]:
    return [
        (detector(), mutator())
        for detector, mutators in SCENARIOS.items()
        if detector_name is None or detector.__name__ == detector_name
        for mutator in mutators
    ]
