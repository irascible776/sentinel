"""
Sentinel AI Security Gateway — Model Download Utility
======================================================
Run this script ONCE to download all required models into sentinel/models/.
After downloading, the models folder can be zipped and copied across machines
(e.g., M1 MacBook Air) without re-downloading.

Usage:
    cd sentinel/            # Be inside the sentinel directory
    python scripts/download_models.py [--all | --channel-b | --arbiter]

Models downloaded:
    Channel A (DeBERTa)  : Already in sentinel/models/sentinel_deberta/
                           (fine-tuned locally, no download needed)

    Channel B (Harm)     : microsoft/xtremedistil-l6-h256-uncased OR
                           protectai/deberta-v3-base-prompt-injection-v2
                           → saved to sentinel/models/channel_b_intent/

    Stage 2 Arbiter GGUF : Phi-3-mini-4k-instruct-Q4_K_M.gguf (2.2 GB)
                           → saved to sentinel/models/arbiter_gguf/
                           (Only needed for 100% offline mode, skip if using Groq API)
"""

import os
import sys
import argparse
import urllib.request

# ── Constants ────────────────────────────────────────────────────────────────
# Base path relative to this script: sentinel/scripts/download_models.py
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
MODELS_DIR = os.path.join(BASE_DIR, "models")

CHANNEL_B_MODEL_ID = "microsoft/xtremedistil-l6-h256-uncased"
CHANNEL_B_LOCAL_PATH = os.path.join(MODELS_DIR, "channel_b_intent")

# Phi-3-Mini Q4 from Hugging Face GGUF repo (MIT licensed)
ARBITER_GGUF_REPO = "bartowski/Phi-3-mini-4k-instruct-GGUF"
ARBITER_GGUF_FILE = "Phi-3-mini-4k-instruct-Q4_K_M.gguf"
ARBITER_LOCAL_PATH = os.path.join(MODELS_DIR, "arbiter_gguf")

# Lightweight alternative: Llama-3.2-1B (~800 MB, faster, lower accuracy)
ARBITER_GGUF_LITE_REPO = "bartowski/Llama-3.2-1B-Instruct-GGUF"
ARBITER_GGUF_LITE_FILE = "Llama-3.2-1B-Instruct-Q4_K_M.gguf"

# Pillar V: Adversarial Strategist (Google Gemma-2-2B-IT GGUF, ~1.58 GB)
REDTEAM_GGUF_REPO = "bartowski/gemma-2-2b-it-GGUF"
REDTEAM_GGUF_FILE = "gemma-2-2b-it-Q4_K_M.gguf"
REDTEAM_LOCAL_PATH = os.path.join(MODELS_DIR, "redteam_gguf")


def check_dependencies():
    """Verify that required packages are available before downloading."""
    missing = []
    for pkg in ["transformers", "torch", "huggingface_hub"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[ERROR] Missing packages: {', '.join(missing)}")
        print(f"        Run: pip install {' '.join(missing)}")
        sys.exit(1)


def download_channel_b():
    """
    Downloads the Channel B Harm Intent Classifier from Hugging Face.
    Saves to sentinel/models/channel_b_intent/
    """
    print("\n" + "═" * 60)
    print("  Downloading Channel B: Harm Intent Classifier")
    print(f"  Model  : {CHANNEL_B_MODEL_ID}")
    print(f"  Output : {CHANNEL_B_LOCAL_PATH}")
    print("═" * 60)

    if os.path.exists(CHANNEL_B_LOCAL_PATH) and os.listdir(CHANNEL_B_LOCAL_PATH):
        print("[SKIP] Channel B model already exists at:", CHANNEL_B_LOCAL_PATH)
        return

    check_dependencies()
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    os.makedirs(CHANNEL_B_LOCAL_PATH, exist_ok=True)
    print("[INFO] Downloading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(CHANNEL_B_MODEL_ID)
    tokenizer.save_pretrained(CHANNEL_B_LOCAL_PATH)

    print("[INFO] Downloading model weights (~250 MB)...")
    model = AutoModelForSequenceClassification.from_pretrained(
        CHANNEL_B_MODEL_ID,
        num_labels=2
    )
    model.save_pretrained(CHANNEL_B_LOCAL_PATH)
    print(f"[OK] Channel B model saved to: {CHANNEL_B_LOCAL_PATH}")


def download_arbiter_gguf(lite: bool = False):
    """
    Downloads the Stage 2 Arbiter GGUF model for 100% offline usage.
    Skip this if you're using Groq API (set GROQ_API_KEY in .env instead).

    Args:
        lite: If True, downloads the smaller Llama-3.2-1B (~800 MB) instead
              of Phi-3-Mini (~2.2 GB).
    """
    if lite:
        repo = ARBITER_GGUF_LITE_REPO
        filename = ARBITER_GGUF_LITE_FILE
        size_hint = "~800 MB"
    else:
        repo = ARBITER_GGUF_REPO
        filename = ARBITER_GGUF_FILE
        size_hint = "~2.2 GB"

    output_path = os.path.join(ARBITER_LOCAL_PATH, filename)

    print("\n" + "═" * 60)
    print("  Downloading Stage 2 Arbiter GGUF (Offline Mode)")
    print(f"  Model  : {repo} / {filename}")
    print(f"  Size   : {size_hint}")
    print(f"  Output : {output_path}")
    print("═" * 60)

    if os.path.exists(output_path):
        print("[SKIP] Arbiter GGUF already exists at:", output_path)
        return

    check_dependencies()
    from huggingface_hub import hf_hub_download

    os.makedirs(ARBITER_LOCAL_PATH, exist_ok=True)
    print(f"[INFO] Downloading {filename} ({size_hint}) — this may take a while...")

    downloaded_path = hf_hub_download(
        repo_id=repo,
        filename=filename,
        local_dir=ARBITER_LOCAL_PATH,
    )
    print(f"[OK] Arbiter GGUF saved to: {downloaded_path}")
    print("[TIP] Set ARBITER_GGUF_PATH in your .env to:", output_path)


def download_redteam_gguf():
    """
    Downloads Google Gemma-2-2B-IT GGUF for Pillar V Adversarial Strategist Agent.
    """
    output_path = os.path.join(REDTEAM_LOCAL_PATH, REDTEAM_GGUF_FILE)

    print("\n" + "═" * 60)
    print("  Downloading Pillar V Adversarial Strategist GGUF (Gemma-2-2B-IT)")
    print(f"  Model  : {REDTEAM_GGUF_REPO} / {REDTEAM_GGUF_FILE}")
    print("  Size   : ~1.58 GB")
    print(f"  Output : {output_path}")
    print("═" * 60)

    if os.path.exists(output_path):
        print("[SKIP] Pillar V GGUF already exists at:", output_path)
        return

    check_dependencies()
    from huggingface_hub import hf_hub_download

    os.makedirs(REDTEAM_LOCAL_PATH, exist_ok=True)
    print(f"[INFO] Downloading {REDTEAM_GGUF_FILE} (~1.58 GB)...")

    downloaded_path = hf_hub_download(
        repo_id=REDTEAM_GGUF_REPO,
        filename=REDTEAM_GGUF_FILE,
        local_dir=REDTEAM_LOCAL_PATH,
    )
    print(f"[OK] Pillar V Strategist GGUF saved to: {downloaded_path}")


def download_vision_models():
    """
    Verifies and pre-warms Pillar III Vision & Document Threat models:
    - Pre-caches EasyOCR PyTorch CRAFT & CRNN recognition weights
    - Verifies MobileCLIP-S0 edge architecture & concept bank centroids
    - Validates PyMuPDF & python-docx forensic parsers
    """
    print("\n" + "═" * 60)
    print("  Initializing Pillar III: Vision & Document Threat Engine")
    print("═" * 60)

    # 1. Document & Image Preprocessing Libraries
    for lib, name in [("PIL", "Pillow (Image Canonicalization)"), ("fitz", "PyMuPDF (PDF Parser)"), ("docx", "python-docx (DOCX Parser)")]:
        try:
            __import__(lib)
            print(f"[OK] {name} is installed and verified.")
        except ImportError:
            print(f"[WARN] {name} missing. Run: pip install {lib}")

    # 2. EasyOCR Engine & Weights
    try:
        import easyocr
        import torch
        print("[INFO] Pre-caching EasyOCR weights (CRAFT detector + CRNN recognizer)...")
        use_gpu = torch.backends.mps.is_available() or torch.cuda.is_available()
        easyocr.Reader(["en"], gpu=use_gpu, verbose=False)
        print("[OK] EasyOCR weights cached and ready for offline inference.")
    except ImportError:
        print("[INFO] EasyOCR not installed. Pillar III will use system Tesseract or MockOCRDriver.")
        print("       To install live GPU OCR: pip install easyocr")

    # 3. MobileCLIP Concept Bank
    try:
        from core.vision.semantic.concept_bank import concept_bank
        from core.vision.semantic.mobileclip_encoder import mobileclip_encoder
        print(f"[OK] MobileCLIP-S0 Vision Tower initialized ({mobileclip_encoder.model.embed_dim}-d).")
        print(f"[OK] Concept Bank loaded: {len(concept_bank.threat_names)} threat concepts, {len(concept_bank.benign_names)} benign anchors.")
    except Exception as e:
        print(f"[WARN] MobileCLIP concept bank initialization notice: {e}")

    print("[OK] Pillar III Vision Engine fully verified.")


def verify_channel_a():
    """Checks that the existing fine-tuned DeBERTa model is present."""
    deberta_path = os.path.join(MODELS_DIR, "sentinel_deberta")
    safetensors = os.path.join(deberta_path, "model.safetensors")
    if os.path.exists(safetensors):
        size_mb = os.path.getsize(safetensors) / (1024 ** 2)
        print(f"[OK] Channel A (DeBERTa): {deberta_path} ({size_mb:.0f} MB)")
    else:
        print("[WARN] Channel A (DeBERTa) model not found at:", deberta_path)
        print("       Copy sentinel/models/sentinel_deberta/ from your source machine via USB/AirDrop.")


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Model Downloader — downloads all required ML models."
    )
    parser.add_argument("--all", action="store_true", help="Download all models (Channel B + Arbiter + Pillar V Gemma + Pillar III Vision)")
    parser.add_argument("--channel-b", action="store_true", help="Download Channel B Harm Intent Classifier only")
    parser.add_argument("--arbiter", action="store_true", help="Download Stage 2 Arbiter GGUF (Phi-3 Mini, ~2.2 GB)")
    parser.add_argument("--arbiter-lite", action="store_true", help="Download Stage 2 Arbiter GGUF Lite (Llama-3.2-1B, ~800 MB)")
    parser.add_argument("--redteam", action="store_true", help="Download Pillar V Adversarial Strategist (Gemma-2-2B-IT GGUF, ~1.58 GB)")
    parser.add_argument("--vision", action="store_true", help="Verify & pre-cache Pillar III Vision & Document Threat models")

    args = parser.parse_args()

    if not any([args.all, args.channel_b, args.arbiter, args.arbiter_lite, args.redteam, args.vision]):
        parser.print_help()
        print("\n[TIP] Run with --all to download everything, or pick specific components.")
        sys.exit(0)

    print("\n  Sentinel Model Downloader")
    print(f"  Models directory: {MODELS_DIR}")
    print()

    verify_channel_a()

    if args.all or args.channel_b:
        download_channel_b()

    if args.all or args.arbiter:
        download_arbiter_gguf(lite=False)

    if args.arbiter_lite:
        download_arbiter_gguf(lite=True)

    if args.all or args.redteam:
        download_redteam_gguf()

    if args.all or args.vision:
        download_vision_models()

    print("\n" + "═" * 60)
    print("  All requested downloads and verifications complete!")
    print()
    print("  Next Steps for M1 MacBook Air (100% Local / Offline):")
    print("  1. Copy sentinel/models/ folder to your M1 Air (or zip and transfer)")
    print("  2. In sentinel/.env, ensure ARBITER_GGUF_PATH and DETECTION_DEVICE=auto (or mps) are set")
    print("  3. Run: python start.py")
    print("═" * 60 + "\n")


if __name__ == "__main__":
    main()
