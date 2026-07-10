# LLM Internals as Attack Surfaces

This repository contains a 7-component security portfolio that systematically tests the internal architecture of Large Language Models (LLMs) as distinct attack surfaces. Instead of relying purely on high-level prompt injection, these scripts target the mechanical and mathematical limitations of how LLMs process data.

## Project Scope & Constraints
- **Language**: Python 3.9+
- **Environment**: Windows OS (No local PyTorch or HuggingFace transformers due to DLL/environment constraints).
- **Backends Used**: 
  - **Ollama (Local)**: Used for testing physical memory constraints and quantized models (e.g., `llama3`).
  - **Groq API**: Used for testing high-precision, large-parameter models (e.g., `llama-3.3-70b-versatile`).

## The 7 Components

### 1. Tokenization (`attack_surfaces.py`)
Tests how the model segments words into tokens. Attackers can exploit token boundaries (e.g., Glitch Tokens, BPE manipulation) to bypass semantic filters or crash parsers.

### 2. Embeddings (`embeddings_attack_surface.py`)
Evaluates the vector representation of text. Attackers use synonym swapping or adversarial perturbations to create payloads that look benign to a human but map closely to malicious vectors in the model's latent space.

### 3. Context Window (`context_window_attack_surface.py`)
Tests the physical boundaries of the LLM's memory. By overflowing the context window, attackers can push safety instructions out of the model's memory, forcing it to "forget" its alignment.

### 4. Attention Mechanism (`attention_attack_surface.py`)
Exploits the "Lost in the Middle" phenomenon. Tests how placing malicious needles in the exact center of massive context blocks degrades the model's ability to maintain focus on the primary system prompt.

### 5. Quantization (`quantization_attack_surface.py`)
Demonstrates the **"Curse of Cognitive Complexity"**. Compares a highly capable 70B model against a heavily quantized 8B model. Surprisingly, high-precision models are often *more* vulnerable to complex roleplay jailbreaks, while smaller/quantized models are "dumbly safe" (over-aligned to basic keywords).

### 6. Inference Pipeline (`inference_pipeline_attack_surface.py`)
Attacks the token generation phase.
- **Temperature Degradation**: Proves whether extreme sampling parameters can force the model to abandon its deterministic safety training.
- **Stop Sequence Evasion**: Exploits application-layer vulnerabilities by obfuscating output to bypass hardcoded stop sequences (e.g., formatting `END_OF_TRANSLATION` with spaces).

### 7. KV Cache (`kv_cache_attack_surface.py`)
Tests optimization layers for Resource Exhaustion (Denial of Service).
Demonstrates a **KV Cache Invalidation Attack (Cache Miss)**. By shifting just a single prefix token in a massive 4,000-word payload, an attacker invalidates the entire cached attention matrix, forcing the server into a massive latency and compute spike.

## Setup & Execution

### Prerequisites
1. Ensure your local virtual environment is active:
   ```cmd
   .venv-main\Scripts\activate
   ```
2. Have [Ollama](https://ollama.com/) running locally with the `llama3` model pulled:
   ```cmd
   ollama run llama3
   ```
3. Set your Groq API key in the `.env` file at the root of the project:
   ```env
   GROQ_API_KEY=your_api_key_here
   ```

### Running the Tests
Each component is a standalone, executable Python script designed to output quantifiable verdicts (`SAFE`, `PARTIAL`, `VULNERABLE`).

Run any script using python, for example:
```cmd
python LLM-internals-as-attack-surfaces\kv_cache_attack_surface.py
```

## Security Metrics & Findings
Each script outputs concrete operational metrics (e.g., processing times, contextual extraction success, prompt snippet logs) and definitive verdicts, providing quantifiable proof of whether the underlying architecture is vulnerable to specific manipulation.
