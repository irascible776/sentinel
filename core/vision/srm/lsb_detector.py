"""
LSB Spatial Domain Steganography Detector (Pillar III)
Implements the Westfeld & Pfitzmann Chi-Square test on Pairs of Values (PoVs)
to detect least-significant-bit steganographic payload embedding in uncompressed images.
"""

import time
from typing import Tuple
from PIL import Image
import numpy as np
from scipy.stats import chi2

from core.vision.schemas import StegoAnalysisResult
from core.vision.config import (
    LSB_CHI_SQUARE_MIN_POVS,
    LSB_CHI_SQUARE_P_THRESHOLD,
)


class LSBStegoDetector:
    """
    Evaluates Pairs of Values (PoVs) in the LSB bit plane.
    Sequential and pseudo-random LSB overwriting equalizes counts of adjacent values (2k, 2k+1).
    """

    def analyze_image(self, img: Image.Image) -> StegoAnalysisResult:
        """
        Calculates Chi-Square statistic on pixel value pairs and computes p-value.
        """
        t0 = time.perf_counter()

        # Convert to numpy uint8 array
        arr = np.array(img.convert("RGB"), dtype=np.uint8)
        total_pixels = arr.size  # H * W * 3

        if total_pixels < LSB_CHI_SQUARE_MIN_POVS:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return StegoAnalysisResult(
                lsb_chi_square_p_value=0.0,
                degrees_of_freedom=0,
                num_povs_evaluated=0,
                is_stego=False,
                risk_score=0.0,
                latency_ms=round(elapsed_ms, 2),
            )

        # Flatten all color channels to 1D sequence
        flat = arr.flatten()

        # Compute histogram of all byte values [0 - 255]
        counts, _ = np.histogram(flat, bins=256, range=(0, 256))

        # Evaluate 128 Pairs of Values: (2k, 2k+1)
        chi_sq_stat = 0.0
        active_povs = 0

        for k in range(128):
            n_even = counts[2 * k]
            n_odd = counts[2 * k + 1]
            n_pair_sum = n_even + n_odd

            if n_pair_sum >= 20:  # Require sufficient sample count per pair
                n_expected = n_pair_sum / 2.0
                chi_sq_stat += ((n_even - n_expected) ** 2) / n_expected
                active_povs += 1

        if active_povs < 30:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return StegoAnalysisResult(
                lsb_chi_square_p_value=0.0,
                degrees_of_freedom=active_povs,
                num_povs_evaluated=active_povs,
                is_stego=False,
                risk_score=0.0,
                latency_ms=round(elapsed_ms, 2),
            )

        df = active_povs - 1
        # In LSB steganalysis, a very low chi_sq_stat indicates artificial equalization
        # The p-value of steganography is the cumulative density 1.0 - survival
        # Under normal conditions, chi_sq is large; under steganography, chi_sq is close to 0.
        try:
            # Cumulative distribution function of chi-square
            # High p-value (near 1.0) indicates that even and odd counts are abnormally identical
            p_val = 1.0 - float(chi2.cdf(chi_sq_stat, df))
            # However, for stego detection, we measure deviation toward perfect equalization:
            # As counts equalize, chi_sq -> 0, so cdf(chi_sq, df) -> 0, which means 1 - cdf -> 1.0
            stego_prob = 1.0 - float(chi2.cdf(chi_sq_stat, df))
        except Exception:
            stego_prob = 0.0

        is_stego = stego_prob >= LSB_CHI_SQUARE_P_THRESHOLD
        risk_score = round(stego_prob * 100.0, 2) if is_stego else 0.0

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return StegoAnalysisResult(
            lsb_chi_square_p_value=round(stego_prob, 4),
            degrees_of_freedom=df,
            num_povs_evaluated=active_povs,
            is_stego=is_stego,
            risk_score=risk_score,
            latency_ms=round(elapsed_ms, 2),
        )


# Global LSB detector instance
lsb_stego_detector = LSBStegoDetector()

