"""
Spatial Rich Model (SRM) Residual Kernel Bank (Pillar III)
Fixed, non-trainable PyTorch Conv2d filter bank initialized with classical steganalysis
residual kernels (1st-order, 2nd-order Laplacian, KV 5x5, Square edge inhibitors).
"""

import torch
import torch.nn as nn
from core.vision.config import SRM_QUANTIZATION_TRUNCATION_T


def build_srm_kernels() -> torch.Tensor:
    """
    Constructs a bank of 10 Spatial Rich Model (SRM) residual kernels.
    All kernels are padded to 5x5 for unified single-pass Conv2d filtering.
    """
    kernels = []

    # 1. First-order horizontal difference (3x3 centered in 5x5)
    k1 = torch.tensor(
        [
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, -1, 1, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ],
        dtype=torch.float32,
    )
    kernels.append(k1)

    # 2. First-order vertical difference (3x3 centered in 5x5)
    k2 = torch.tensor(
        [
            [0, 0, 0, 0, 0],
            [0, 0, -1, 0, 0],
            [0, 0, 1, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ],
        dtype=torch.float32,
    )
    kernels.append(k2)

    # 3. First-order diagonal difference
    k3 = torch.tensor(
        [
            [0, 0, 0, 0, 0],
            [0, -1, 0, 0, 0],
            [0, 0, 1, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ],
        dtype=torch.float32,
    )
    kernels.append(k3)

    # 4. Second-order horizontal difference
    k4 = torch.tensor(
        [
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 1, -2, 1, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ],
        dtype=torch.float32,
    )
    kernels.append(k4)

    # 5. Second-order Laplacian kernel (3x3)
    k5 = torch.tensor(
        [
            [0, 0, 0, 0, 0],
            [0, 0, 1, 0, 0],
            [0, 1, -4, 1, 0],
            [0, 0, 1, 0, 0],
            [0, 0, 0, 0, 0],
        ],
        dtype=torch.float32,
    )
    kernels.append(k5)

    # 6. Classic KV (Kodovsky & Fridrich) 5x5 steganalysis kernel
    k6 = (
        torch.tensor(
            [
                [-1, 2, -2, 2, -1],
                [2, -6, 8, -6, 2],
                [-2, 8, -12, 8, -2],
                [2, -6, 8, -6, 2],
                [-1, 2, -2, 2, -1],
            ],
            dtype=torch.float32,
        )
        / 12.0
    )
    kernels.append(k6)

    # 7. Square 3x3 edge inhibitor
    k7 = torch.tensor(
        [
            [0, 0, 0, 0, 0],
            [0, -1, 2, -1, 0],
            [0, 2, -4, 2, 0],
            [0, -1, 2, -1, 0],
            [0, 0, 0, 0, 0],
        ],
        dtype=torch.float32,
    )
    kernels.append(k7)

    # 8. Corner difference filter
    k8 = torch.tensor(
        [
            [0, 0, 0, 0, 0],
            [0, 1, -2, 1, 0],
            [0, -2, 4, -2, 0],
            [0, 1, -2, 1, 0],
            [0, 0, 0, 0, 0],
        ],
        dtype=torch.float32,
    )
    kernels.append(k8)

    # 9. Cross 5x5 difference filter
    k9 = torch.tensor(
        [
            [0, 0, -1, 0, 0],
            [0, 0, 2, 0, 0],
            [-1, 2, -4, 2, -1],
            [0, 0, 2, 0, 0],
            [0, 0, -1, 0, 0],
        ],
        dtype=torch.float32,
    )
    kernels.append(k9)

    # 10. Diagonal 5x5 edge detector
    k10 = torch.tensor(
        [
            [-1, 0, 0, 0, 1],
            [0, -2, 0, 2, 0],
            [0, 0, 0, 0, 0],
            [0, 2, 0, -2, 0],
            [1, 0, 0, 0, -1],
        ],
        dtype=torch.float32,
    )
    kernels.append(k10)

    # Stack to (10, 1, 5, 5) tensor
    weight_tensor = torch.stack(kernels).unsqueeze(1)
    return weight_tensor


class SRMFilterBank(nn.Module):
    """
    Fixed PyTorch Conv2d filter bank executing 10 SRM residual convolutions in parallel.
    Applies quantize-and-truncate [-T, T] to isolate high-frequency statistical noise.
    """

    def __init__(self, truncation_t: float = SRM_QUANTIZATION_TRUNCATION_T):
        super().__init__()
        self.truncation_t = truncation_t
        weights = build_srm_kernels()
        self.conv = nn.Conv2d(
            in_channels=1,
            out_channels=10,
            kernel_size=5,
            padding=2,
            bias=False,
        )
        self.conv.weight = nn.Parameter(weights, requires_grad=False)
        self.eval()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Input: (B, 1, H, W) single-channel luminance tensor
        Output: (B, 10, H, W) quantized and truncated residual maps
        """
        residuals = self.conv(x)
        # Quantize-and-truncate step: clip to [-T, T]
        clipped = torch.clamp(residuals, -self.truncation_t, self.truncation_t)
        return clipped

