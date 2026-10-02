# Module 5: Voice-to-Prompt Attack Client (Add-on 9)
**Developer 3 (Utkarsh) | Branch: `br1` | File: `core/security_vectors/voice_client.py`**

---

## 1. Objective & Novelty
As generative AI moves to voice interfaces (ChatGPT Voice, Siri, smart home assistants), attackers speak their attacks. Spoken jailbreaks naturally contain phonetic variations, slang, filler words, and transcription noise that bypass simplistic keyword blacklists.

This client proves live in the viva that our gateway handles **multimodal inputs**:
1. Captures spoken audio via microphone or loads sample adversarial `.wav` files.
2. Transcribes audio to text using OpenAI Whisper (`openai/whisper-tiny` via Hugging Face pipelines).
3. Transmits the transcribed text to the Gateway (`POST http://127.0.0.1:8000/v1/chat/completions`).
4. Demonstrates that while naive filters miss the spoken phrasing, our gateway's semantic analysis successfully flags or blocks it.

---

## 2. Technical Specification

### 2.1 File Location
`core/security_vectors/voice_client.py`

### 2.2 Dual-Mode Architecture (Hardware-Resilient)
* **Mode 1 (Live Recording):** Captures 5 seconds from the local microphone at 16000 Hz using `sounddevice`.
* **Mode 2 (Offline Sample Fallback):** Reads pre-recorded audio files from `tests/samples/audio/` (vital for viva evaluations on computers with disabled microphones or missing ALSA/PulseAudio drivers).

### 2.3 Implementation Blueprint
```python
import os
import requests
from transformers import pipeline

class VoiceAttackClient:
    def __init__(self, gateway_url: str = "http://127.0.0.1:8000"):
        self.gateway_url = gateway_url
        self.transcriber = None

    def _init_model(self):
        if self.transcriber is None:
            self.transcriber = pipeline(
                "automatic-speech-recognition",
                model="openai/whisper-tiny",
                device="cpu"
            )

    def transcribe_audio_file(self, audio_path: str) -> str:
        """Transcribes a .wav audio file to text without needing ffmpeg."""
        import soundfile as sf
        self._init_model()
        audio_data, sample_rate = sf.read(audio_path)
        result = self.transcriber({"raw": audio_data, "sampling_rate": sample_rate})
        return result.get("text", "").strip()

    def send_to_gateway(self, prompt: str, session_id: str = "voice-session") -> dict:
        """Dispatches transcribed prompt to the gateway API."""
        url = f"{self.gateway_url}/v1/chat/completions"
        payload = {
            "session_id": session_id,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False
        }
        resp = requests.post(url, json=payload)
        return resp.json()
```

---

## 3. Verification & Testing
```bash
python3 core/security_vectors/voice_client.py
```
