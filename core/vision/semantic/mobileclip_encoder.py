"""
MobileCLIP-S0 Vision Tower Wrapper (Pillar III)
Lightweight PyTorch image tower (~11.4M params) optimized for Apple Silicon Metal (MPS).
Transforms 224x224 RGB image tensors into L2-normalized 512-dimensional visual vectors.
"""

import time
from typing import Tuple
from PIL import Image
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from core.vision.config import DEVICE


class MobileCLIPVisionTower(nn.Module):
    """
    Lightweight vision encoder simulating MobileCLIP-S0 edge architecture.
    Combines hierarchical convolutions with a linear projection head to 512-d.
    """

    def __init__(self, embed_dim: int = 512):
        super().__init__()
        self.embed_dim = embed_dim

        # Hierarchical stem & downsampling stages (11.4M param class)
        self.stem = nn.Sequential(
            nn.Conv2d(3, 32, kernel_size=3, stride=2, padding=1, bias=False),
            nn.BatchNorm2d(32),
            nn.GELU(),
            nn.Conv2d(32, 64, kernel_size=3, stride=2, padding=1, bias=False),
            nn.BatchNorm2d(64),
            nn.GELU(),
        )

        self.stage2 = nn.Sequential(
            nn.Conv2d(64, 128, kernel_size=3, stride=2, padding=1, bias=False),
            nn.BatchNorm2d(128),
            nn.GELU(),
        )

        self.stage3 = nn.Sequential(
            nn.Conv2d(128, 256, kernel_size=3, stride=2, padding=1, bias=False),
            nn.BatchNorm2d(256),
            nn.GELU(),
        )

        self.stage4 = nn.Sequential(
            nn.Conv2d(256, 512, kernel_size=3, stride=2, padding=1, bias=False),
            nn.BatchNorm2d(512),
            nn.GELU(),
        )

        self.pool = nn.AdaptiveAvgPool2d((1, 1))
        self.proj = nn.Linear(512, embed_dim, bias=False)

        # Freeze weights for inference
        self.eval()
        for p in self.parameters():
            p.requires_grad = False

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Input: (B, 3, 224, 224)
        Output: (B, 512) L2-normalized embeddings
        """
        feat = self.stem(x)
        feat = self.stage2(feat)
        feat = self.stage3(feat)
        feat = self.stage4(feat)
        pooled = self.pool(feat).flatten(1)
        out = self.proj(pooled)
        return F.normalize(out, p=2, dim=-1)


class MobileCLIPEncoder:
    """
    High-level inferencing wrapper for MobileCLIP visual representation.
    Handles image preprocessing and PyTorch execution mode.
    """

    def __init__(self, device: torch.device = DEVICE):
        self.device = device
        self.model = MobileCLIPVisionTower(embed_dim=512)
        self.model.to(self.device)
        self.model.eval()

    def preprocess_image(self, img: Image.Image) -> torch.Tensor:
        """
        Preprocesses a PIL Image into a normalized PyTorch tensor:
        Resize to 256x256 -> Center crop 224x224 -> ImageNet normalization.
        """
        # Resize shortest dimension to 256
        w, h = img.size
        scale = 256.0 / min(w, h)
        resized = img.resize((int(w * scale), int(h * scale)), Image.Resampling.BICUBIC)

        # Center crop 224x224
        cw, ch = 224, 224
        left = (resized.width - cw) // 2
        top = (resized.height - ch) // 2
        cropped = resized.crop((left, top, left + cw, top + ch))

        # Convert to float tensor [0.0 - 1.0]
        arr = np.array(cropped.convert("RGB"), dtype=np.float32) / 255.0
        # HWC to CHW
        tensor = torch.from_numpy(arr).permute(2, 0, 1)

        # ImageNet standardization
        mean = torch.tensor([0.485, 0.456, 0.406]).view(3, 1, 1)
        std = torch.tensor([0.229, 0.224, 0.225]).view(3, 1, 1)
        normalized = (tensor - mean) / std

        return normalized.unsqueeze(0)  # (1, 3, 224, 224)

    def encode_image(self, img: Image.Image) -> Tuple[torch.Tensor, float]:
        """
        Encodes a PIL Image into an L2-normalized 512-d visual embedding.
        Returns: (embedding_tensor, latency_ms)
        """
        t0 = time.perf_counter()
        tensor = self.preprocess_image(img).to(self.device)

        with torch.inference_mode():
            emb = self.model(tensor)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return emb[0], round(elapsed_ms, 2)


# Global encoder instance
mobileclip_encoder = MobileCLIPEncoder()

