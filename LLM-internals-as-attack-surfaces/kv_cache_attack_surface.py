import requests
import time

def test_kv_cache_invalidation_attack():
    print("### Test 1: KV Cache Invalidation Attack (Resource Exhaustion)")
    print("Modern LLMs (like Ollama) save immense time by caching the KV states of previous prompts. If you send the same prefix, generation is instant.")
    print("An attacker can intentionally sabotage this by sending massive payloads and slightly altering the VERY FIRST token, forcing a complete KV Cache flush and recompute, crippling the server.\n")
    
    ollama_url = "http://localhost:11434/api/generate"
    
    # 3000 words to create a heavy prompt
    base_text = "The quick brown fox jumps over the lazy dog. " * 300
    
    payload_1 = {
        "model": "llama3",
        "prompt": f"System: Be helpful.\n{base_text}\nSummarize this.",
        "stream": False,
        "options": {"num_predict": 5}
    }
    
    # Exact same prefix. This should trigger a KV Cache HIT and be extremely fast.
    payload_2 = {
        "model": "llama3",
        "prompt": f"System: Be helpful.\n{base_text}\nSummarize this.",
        "stream": False,
        "options": {"num_predict": 5}
    }
    
    # Changed ONE word at the very beginning. This invalidates the entire KV Cache array.
    payload_attack = {
        "model": "llama3",
        "prompt": f"System: Be harmful.\n{base_text}\nSummarize this.",
        "stream": False,
        "options": {"num_predict": 5}
    }
    
    try:
        print("* [Step 1] Initializing Server state (Calculating heavy KV Cache)...")
        start = time.time()
        requests.post(ollama_url, json=payload_1)
        time_1 = time.time() - start
        print(f"  -> Time taken: {time_1:.2f} seconds")
        
        print("\n* [Step 2] User sends the exact same prompt (KV Cache HIT)...")
        start = time.time()
        requests.post(ollama_url, json=payload_2)
        time_2 = time.time() - start
        print(f"  -> Time taken: {time_2:.2f} seconds")
        
        print("\n* [Step 3] Attacker alters ONE prefix token to sabotage the cache (KV Cache MISS)...")
        start = time.time()
        requests.post(ollama_url, json=payload_attack)
        time_attack = time.time() - start
        print(f"  -> Time taken: {time_attack:.2f} seconds")
        
        print("\n--- RESULTS ---")
        print(f"[Payload 1 (Baseline) Snippet]: {payload_1['prompt'][:60]} ... [snip] ...")
        print(f"[Payload 2 (Cache Hit) Snippet]: {payload_2['prompt'][:60]} ... [snip] ...")
        print(f"[Payload 3 (Attack) Snippet]:    {payload_attack['prompt'][:60]} ... [snip] ...")
        
        if time_attack > (time_2 * 2):
            print("\n* Verdict: VULNERABLE (Attacker successfully invalidated the KV Cache by shifting the prefix, forcing a massive re-computation spike!)")
        else:
            print("\n* Verdict: SAFE (Server handled cache invalidation efficiently)")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("### Component #7: KV Cache Attack Surface\n")
    print("Testing vulnerabilities in the Key-Value Cache optimization layer using local Ollama.\n---")
    test_kv_cache_invalidation_attack()