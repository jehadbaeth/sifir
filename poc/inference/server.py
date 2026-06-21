"""
Sifir inference server — Phase 2 (local hardware).

Wraps llama-cpp-python with a minimal HTTP API that sifir-server proxies to.
Only binds on 127.0.0.1 — never exposed directly to the network.

Usage:
    MODEL_PATH=/path/to/model.gguf python server.py

Environment variables:
    MODEL_PATH       Path to the .gguf model file (required)
    HOST             Bind address (default: 127.0.0.1)
    PORT             Port (default: 8080)
    N_GPU_LAYERS     Number of layers to offload to GPU (-1 = all, default: -1)
    N_CTX            Context window size (default: 4096)
"""
import os
import sys
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import uvicorn

MODEL_PATH = os.environ.get("MODEL_PATH")
if not MODEL_PATH:
    print("ERROR: MODEL_PATH environment variable is required", file=sys.stderr)
    sys.exit(1)

N_GPU_LAYERS = int(os.environ.get("N_GPU_LAYERS", "-1"))
N_CTX = int(os.environ.get("N_CTX", "4096"))

print(f"[inference] loading model from {MODEL_PATH}", flush=True)
print(f"[inference] n_gpu_layers={N_GPU_LAYERS}, n_ctx={N_CTX}", flush=True)

t0 = time.time()
from llama_cpp import Llama  # noqa: E402
llm = Llama(
    model_path=MODEL_PATH,
    n_gpu_layers=N_GPU_LAYERS,
    n_ctx=N_CTX,
    verbose=False,
)
print(f"[inference] model loaded in {time.time() - t0:.1f}s", flush=True)

app = FastAPI(title="sifir-inference")


class GenerateRequest(BaseModel):
    prompt: str
    max_tokens: int = Field(default=512, ge=1, le=4096)


class GenerateResponse(BaseModel):
    text: str
    tokens_used: int


@app.post("/v1/generate", response_model=GenerateResponse)
def generate(req: GenerateRequest) -> GenerateResponse:
    result = llm(
        req.prompt,
        max_tokens=req.max_tokens,
        echo=False,
        stop=["<|endoftext|>", "<|im_end|>"],
    )
    choices = result.get("choices", [])
    if not choices:
        raise HTTPException(status_code=500, detail="model returned no output")

    text = choices[0].get("text", "")
    tokens_used = result.get("usage", {}).get("completion_tokens", 0)
    return GenerateResponse(text=text, tokens_used=tokens_used)


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    print(f"[inference] listening on {host}:{port}", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="warning")
