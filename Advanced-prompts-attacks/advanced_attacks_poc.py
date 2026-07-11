import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3"

global_memory = []
current_user = None

def chat_with_llm(user_input):
    global global_memory
    
    # Append the user's message to the global memory (Insecure design: global instead of per-user)
    global_memory.append(f"{current_user}: {user_input}")
    
    # Build the prompt with the insecure global memory
    prompt = f"""
System: You are a helpful customer support bot. Use the chat history to provide context. Do not break character.

--- Chat History ---
{chr(10).join(global_memory)}
--- End History ---

Respond to the latest message from {current_user}.
"""
    payload = {"model": MODEL, "prompt": prompt, "stream": False}
    
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        bot_reply = response.json().get('response', '').strip()
        
        # Save bot response to memory
        global_memory.append(f"Bot: {bot_reply}")
        return bot_reply
    except Exception as e:
        return f"Error connecting to LLM: {e}"

def summarize_memory():
    global global_memory
    
    if not global_memory:
        return "Memory is empty."
        
    prompt = f"""
System: Summarize the following chat log into a single concise sentence to save database space.

--- Chat Log to Summarize ---
{chr(10).join(global_memory)}
--- End Log ---

Summary:
"""
    payload = {"model": MODEL, "prompt": prompt, "stream": False}
    
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        summary = response.json().get('response', '').strip()
        
        # Compress the memory to just the summary
        global_memory = [f"[System Summary]: {summary}"]
        return summary
    except Exception as e:
        return f"Error connecting to LLM: {e}"

def main():
    global current_user, global_memory
    print("=== Stateful Chat App (Vulnerable to Advanced Prompt Attacks) ===")
    print("This app contains two critical flaws:")
    print("1. It uses a global memory array for all users (Cross-Session Vulnerability)")
    print("2. It naively passes untrusted logs into its summarization prompt (Prompt Compression Vulnerability)\n")
    
    while True:
        print("\n" + "="*40)
        print(f"Current User: {current_user if current_user else 'None'}")
        print(f"Memory Size: {len(global_memory)} lines")
        print("1. Login as User A (Attacker)")
        print("2. Login as User B (Victim)")
        print("3. Send Message to Support Bot")
        print("4. Trigger Memory Summarization (Background Task)")
        print("5. View Raw Global Memory")
        print("6. Exit")
        
        choice = input("Select an option: ")
        
        if choice == '1':
            current_user = "User A"
            print("[+] Logged in as User A.")
        elif choice == '2':
            current_user = "User B"
            print("[+] Logged in as User B.")
        elif choice == '3':
            if not current_user:
                print("[-] Please login first.")
                continue
            msg = input(f"[{current_user}] Enter message: ")
            print("Bot is typing...")
            reply = chat_with_llm(msg)
            print(f"\n[Support Bot]: {reply}")
        elif choice == '4':
            print("[*] Triggering Summarization Pipeline...")
            summary = summarize_memory()
            print(f"[Pipeline Result]: Memory compressed successfully.")
            print(f"New Memory State: {summary}")
        elif choice == '5':
            print("\n--- RAW GLOBAL MEMORY ---")
            if not global_memory:
                print("(empty)")
            else:
                for line in global_memory:
                    print(line)
            print("-------------------------")
        elif choice == '6':
            break
        else:
            print("[-] Invalid choice.")

if __name__ == "__main__":
    main()