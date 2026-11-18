"""
entropy_analysis scores byte sequences by entropy: Shannon entropy and Differential Area Analysis
"""

from .daa import calculate_daa
from .shannon import calculate_shannon

__all__ = ["calculate_daa", "calculate_shannon"]
