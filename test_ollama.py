import requests
import json

# Test Ollama local model
prompt = "What is prompt injection in 2 sentences?"

response = requests.post(
    "http://localhost:11434/api/generate",
    json={
        "model": "llama3:latest",
        "prompt": prompt,
        "stream": False
    }
)

result = response.json()
print("=" * 60)
print("OLLAMA (Local Model)")
print("=" * 60)
print(f"Model: llama3:latest")
print(f"Prompt: {prompt}")
print(f"Response:\n{result['response']}")
print("=" * 60)