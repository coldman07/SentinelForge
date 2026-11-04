"""Wait for the local Ollama API and download the configured small dev model."""

import json
import os
import time
import urllib.error
import urllib.request

base = os.getenv("OLLAMA_URL", "http://ollama:11434").rstrip("/")
model = os.getenv("SF_ASSISTANT_MODEL", "qwen2.5:0.5b")
deadline = time.monotonic() + 300
while time.monotonic() < deadline:
    try:
        with urllib.request.urlopen(f"{base}/api/tags", timeout=5):
            break
    except (urllib.error.URLError, TimeoutError):
        time.sleep(2)
else:
    raise SystemExit("Ollama API did not become ready within 5 minutes")

payload = json.dumps({"name": model, "stream": True}).encode()
request = urllib.request.Request(
    f"{base}/api/pull", data=payload, headers={"Content-Type": "application/json"}
)
with urllib.request.urlopen(request, timeout=3600) as response:
    for line in response:
        if line.strip():
            status = json.loads(line).get("status")
            if status:
                print(status, flush=True)
print(f"Ready: {model}", flush=True)
