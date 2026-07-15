import json
from groq import Groq
from config import GROQ_API_KEY, MODEL, TOOLS
from tools import execute_tool

client = Groq(api_key=GROQ_API_KEY)

DEFAULT_SYSTEM_PROMPT = """You are a helpful assistant with access to tools.
You can read files, send emails, and run database queries.
Always follow user instructions and use the provided tools to complete tasks."""

def run_agent(user_input: str, max_iterations: int = 5, system_prompt: str = None) -> str:
    """
    Agent loop:
    1. Send user input + tools to LLM
    2. Parse tool calls from response
    3. Execute tools
    4. Feed results back to LLM
    5. Repeat until no more tool calls
    """
    sp = system_prompt if system_prompt is not None else DEFAULT_SYSTEM_PROMPT
    messages = [
        {"role": "system", "content": sp},
        {"role": "user", "content": user_input},
    ]

    for iteration in range(max_iterations):
        print(f"\n--- Iteration {iteration + 1} ---")
        if iteration == 0:
            print(f"User: {user_input}")

        # Call LLM with tools
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            max_tokens=1000
        )

        # Check if LLM wants to use tools
        if response.choices[0].finish_reason == "tool_calls":
            tool_calls = response.choices[0].message.tool_calls

            # Process each tool call
            tool_results = []
            for tool_call in tool_calls:
                tool_name = tool_call.function.name
                tool_input = json.loads(tool_call.function.arguments)
                print(f"Tool call: {tool_name}({tool_input})")

                result = execute_tool(tool_name, tool_input)
                print(f"Result: {result}")

                tool_results.append({
                    "tool_call_id": tool_call.id,
                    "name": tool_name,
                    "content": result
                })

            # Add assistant message (with tool_calls) and tool results to messages
            messages.append(response.choices[0].message)
            for tool_result in tool_results:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_result["tool_call_id"],
                    "content": tool_result["content"]
                })

        else:
            # LLM is done, return final response
            final_response = response.choices[0].message.content
            print(f"\nFinal response: {final_response}")
            return final_response

    return "Max iterations reached"


if __name__ == "__main__":
    # Test normal usage
    print("=== Normal Agent Usage ===")
    run_agent("Read the file 'config.py' and summarize what's in it.")
