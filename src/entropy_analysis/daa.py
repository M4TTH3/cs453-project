"""
daa.py implements Differential Area Analysis (DAA) from Davies, Macfarlane & Buchanan (2021),
"Differential area analysis for ransomware attack detection within mixed file datasets",
Computers & Security 108, 102377. https://doi.org/10.1016/j.cose.2021.102377

The Shannon entropy of the first step, 2 * step, ..., max_length bytes of the data is subtracted
from the expected entropy of that many random bytes, and the area under this derived curve is
found with the composite trapezoidal rule. The score is in Bit-Bytes: the lower it is, the closer
the header is to random (encrypted) data. It can go negative where the header is more varied
than random bytes on average.

This is a reimplementation of the method, not an exact reproduction of the paper's results:
- As in the paper: 8-byte steps, reference minus data (signed), the composite trapezoidal rule
  with h = step, and Bit-Byte units. Given the entropy values of the paper's worked example
  (Tables 2 and 3), the area calculation gives its 26.912 Bit-Bytes.
- The paper measured its reference curve from random files and only publishes it up to 40 bytes.
  Here it is the exact expected entropy of uniformly random bytes, which agrees with those
  published values to within 0.004 bits.
- The paper also skips large blocks of zeros in Phobos-encrypted headers but does not say how,
  so that is not implemented.
- The paper only scores full-length headers. Data shorter than max_length is scored here over
  the prefixes it has, which the paper does not cover.
Scores should be close to the paper's, but its thresholds need re-checking on our data.
"""

import math
from functools import cache

from .shannon import calculate_shannon

STEP = 8
"Bytes between sample points, as in the paper"

MAX_LENGTH = 192
"Longest prefix sampled. The paper tested 32 to 256 bytes"


def calculate_daa(data: bytes, step: int = STEP, max_length: int = MAX_LENGTH) -> float:
    """
    Bit-Byte area between the expected entropy of random bytes and the entropy of the first
    step, 2 * step, ..., max_length bytes of `data`. A max_length that is not a multiple of step
    is rounded down to one.

    Data shorter than max_length is scored up to the largest multiple of step it contains. That
    area covers fewer bytes, so it is not comparable with full-length scores and needs its own
    threshold. With fewer than two sample points (data or max_length under 2 * step) there is
    no area and the result is NaN.

    Raises ValueError if step is not positive.
    """
    if step <= 0:
        raise ValueError(f"step must be positive, got {step}")

    length = min(max_length, len(data)) // step * step
    if length < 2 * step:
        return math.nan

    lengths = range(step, length + 1, step)
    derived = [random_entropy(n) - calculate_shannon(data[:n]) for n in lengths]
    return _trapezoid(derived, step)


@cache
def random_entropy(n: int) -> float:
    """
    Expected Shannon entropy of n uniformly random bytes, in bits per byte.

    A given byte value occurs k times with probability C(n, k) * 255^(n - k) / 256^n and then
    contributes (k / n) * log2(n / k). All 256 values have the same distribution.
    """
    total = 256**n
    return 256 * sum(
        math.comb(n, k) * 255 ** (n - k) / total * (k / n) * math.log2(n / k)
        for k in range(1, n + 1)
    )


def _trapezoid(values: list[float], h: float) -> float:
    "Composite trapezoidal rule for points h apart: h / 2 * (f(a) + 2 * sum(middle) + f(b))"
    return h / 2 * (values[0] + 2 * sum(values[1:-1]) + values[-1])
