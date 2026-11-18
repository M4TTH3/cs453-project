"""
shannon.py computes the Shannon entropy of byte sequences
"""

import numpy as np


def calculate_shannon(data: bytes) -> float:
    """
    Shannon entropy of `data` in bits per byte: -sum(p_i * log2(p_i)) over the byte values i
    present, where p_i is the fraction of bytes equal to i.

    0 for empty input or a single repeated value, 8 when all 256 values occur equally often.
    """
    n = len(data)
    if n == 0:
        return 0.0

    counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
    counts = counts[counts > 0]
    return float(np.sum(counts / n * np.log2(n / counts)))
