# api


# TinyLlama Model Integration Guide

- This project uses the [TinyLlama-1.1B-Chat-v1.0](https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0) model for local chatbot inference. The model powers the backend logic and is referred to as **`sana`** throughout the codebase.

- To maintain a lightweight repository and avoid pushing large files, the model directory `sana_ai/tinyllama_model/` is listed in `.gitignore` and is **not tracked by Git**. Collaborators must manually download and configure the model before running the application.

---

## Setup Instructions

1. **Download the model** from Hugging Face:  
   [https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0](https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0)

2. **Create the following directory** in your project root:

## sana_ai/tinyllama_model/

3. **Place the following files** inside `tinyllama_model/`:
- `config.json`
- `model.safetensors`
- `tokenizer_config.json`
- `tokenizer.json`
- `tokenizer.model`
- `special_tokens_map.json`
- `generation_config.json`

4. **Run the FastAPI server**:
```bash
uvicorn sana_ai.tinyllama_api.main:app --reload