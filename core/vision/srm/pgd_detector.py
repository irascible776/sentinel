"""
PGD & Adversarial Perturbation Detector (Pillar III)
Distinguishes natural enterprise textures (code screenshots, financial tables, scanned receipts)
from adversarial PGD/FGSM noise using Edge-Residual Correlation and Flat-Region Leakage.
"""

import time
from typing import Tuple
from PIL import Image
import numpy as np
import torch
import torch.nn.functional as F

from core.vision.schemas import NoiseAnalysisResult
from core.vision.srm.kernels import SRMFilterBank
from core.vision.config import (
    DEVICE,
    EDGE_RESIDUAL_CORRELATION_THRESHOLD,
    FLAT_REGION_LEAKAGE_THRESHOLD,
)


class PGDNoiseDetector:
    """
    Evaluates high-frequency spatial noise patterns to detect adversarial perturbations.
    Uses edge-residual cross-correlation and whitespace leakage analysis.
    """

    def __init__(self, device: torch.device = DEVICE):
        self.device = device
        self.filter_bank = SRMFilterBank().to(self.device)
        self.filter_bank.eval()

    def _compute_sobel_gradient(self, x: torch.Tensor) -> torch.Tensor:
        """
        Computes Sobel gradient magnitude on (1, 1, H, W) tensor.
        """
        sobel_x = (
            torch.tensor([[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]], dtype=torch.float32)
            .view(1, 1, 3, 3)
            .to(self.device)
        )
        sobel_y = (
            torch.tensor([[-1, -2, -1], [0, 0, 0], [1, 2, 1]], dtype=torch.float32)
            .view(1, 1, 3, 3)
            .to(self.device)
        )

        gx = F.conv2d(x, sobel_x, padding=1)
        gy = F.conv2d(x, sobel_y, padding=1)
        return torch.sqrt(gx**2 + gy**2 + 1e-6)

    def analyze_image(self, img: Image.Image) -> NoiseAnalysisResult:
        """
        Executes SRM filtering, edge-residual correlation, and flat-region leakage analysis.
        """
        t0 = time.perf_counter()

        # Step 0: Downsample large images to max 1024 for fast inference
        w, h = img.size
        max_dim = max(w, h)
        if max_dim > 1024:
            scale = 1024.0 / max_dim
            thumb = img.resize((int(w * scale), int(h * scale)), Image.Resampling.BILINEAR)
        else:
            thumb = img

        # Step 1: Prepare single-channel luminance tensor [0, 255]
        gray_arr = np.array(thumb.convert("L"), dtype=np.float32)
        tensor = torch.from_numpy(gray_arr).unsqueeze(0).unsqueeze(0).to(self.device)

        with torch.inference_mode():
            # Step 2: Content gradient
            grad = self._compute_sobel_gradient(tensor)

            # Step 3: SRM 10-channel residual maps
            residuals = self.filter_bank(tensor)  # (1, 10, H, W)
            res_mag = torch.mean(torch.abs(residuals), dim=1, keepdim=True)  # (1, 1, H, W)

            # Flatten to 1D vectors for statistical metrics
            g_flat = grad.view(-1)
            r_flat = res_mag.view(-1)

            # Step 4: Edge-Residual Correlation (Pearson Correlation)
            g_mean = torch.mean(g_flat)
            r_mean = torch.mean(r_flat)
            g_diff = g_flat - g_mean
            r_diff = r_flat - r_mean

            denom = torch.sqrt(torch.sum(g_diff**2) * torch.sum(r_diff**2) + 1e-8)
            correlation = float((torch.sum(g_diff * r_diff) / denom).cpu().numpy())

            # Step 5: Flat-Region Residual Leakage
            # Identify flat regions (content gradient < 18.0)
            flat_mask = g_flat < 18.0
            num_flat_pixels = int(torch.sum(flat_mask).cpu().numpy())

            if num_flat_pixels > 100:
                flat_leakage = float(torch.mean(r_flat[flat_mask]).cpu().numpy())
            else:
                flat_leakage = 0.0

            total_srm_energy = float(torch.mean(r_flat).cpu().numpy())

        # Step 6: Risk Calibration
        # Natural enterprise text: high correlation (>= 0.45) AND low flat leakage (< 3.0)
        # Adversarial noise: low correlation (< 0.40) OR high flat leakage (>= 3.2)
        is_adversarial = False
        risk_score = 0.0

        if flat_leakage >= FLAT_REGION_LEAKAGE_THRESHOLD:
            # Leakage in empty space is the definitive PGD signature
            is_adversarial = True
            leak_ratio = min(1.0, (flat_leakage - FLAT_REGION_LEAKAGE_THRESHOLD) / 2.0)
            risk_score = 75.0 + leak_ratio * 25.0
        elif correlation < EDGE_RESIDUAL_CORRELATION_THRESHOLD and total_srm_energy > 1.8:
            # Noise present without edge co-location
            is_adversarial = True
            risk_score = 65.0
        else:
            # Clean document / natural image
            risk_score = max(0.0, (flat_leakage / FLAT_REGION_LEAKAGE_THRESHOLD) * 30.0)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return NoiseAnalysisResult(
            srm_energy=round(total_srm_energy, 4),
            edge_residual_correlation=round(correlation, 4),
            flat_region_leakage=round(flat_leakage, 4),
            is_adversarial_noise=is_adversarial,
            risk_score=round(risk_score, 2),
            latency_ms=round(elapsed_ms, 2),
        )


# Global PGD detector instance
pgd_noise_detector = PGDNoiseDetector()

