import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

prompt = "What is prompt injection in 2 sentences?"

response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": prompt}],
    max_tokens=200
)

print("=" * 60)
print("GROQ API (Cloud Model)")
print("=" * 60)
print(f"Model: llama-3.3-70b-versatile")
print(f"Prompt: {prompt}")
print(f"Response:\n{response.choices[0].message.content}")
print("=" * 60)