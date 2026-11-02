"""
Developer 3 (Utkarsh) — Pillar V Model Downloader
Downloads Google Gemma-2-2B-IT GGUF (Q4_K_M) for the Adversarial Strategist Agent.
"""

import os
import sys
import urllib.request

MODEL_URL = "https://huggingface.co/bartowski/gemma-2-2b-it-GGUF/resolve/main/gemma-2-2b-it-Q4_K_M.gguf"
DEST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "redteam_gguf")
DEST_FILE = os.path.join(DEST_DIR, "gemma-2-2b-it-Q4_K_M.gguf")


def download_progress(block_num, block_size, total_size):
    downloaded = block_num * block_size
    if total_size > 0:
        percent = min(100.0, downloaded * 100.0 / total_size)
        mb_down = downloaded / (1024 * 1024)
        mb_total = total_size / (1024 * 1024)
        sys.stdout.write(f"\rDownloading Gemma-2-2B-IT: {percent:.1f}% ({mb_down:.1f} MB / {mb_total:.1f} MB)")
        sys.stdout.flush()


def main():
    os.makedirs(DEST_DIR, exist_ok=True)
    if os.path.exists(DEST_FILE):
        print(f"Gemma-2-2B-IT model already exists at: {DEST_FILE}")
        return

    print(f"Target path: {DEST_FILE}")
    print(f"Source URL: {MODEL_URL}")
    print("Initiating download (approx ~1.58 GB)...")

    try:
        urllib.request.urlretrieve(MODEL_URL, DEST_FILE, reporthook=download_progress)
        print("\nDownload complete! Gemma-2-2B-IT is ready for Metal GPU inference.")
    except Exception as e:
        print(f"\nDownload failed: {e}")
        if os.path.exists(DEST_FILE):
            os.remove(DEST_FILE)


if __name__ == "__main__":
    main()

