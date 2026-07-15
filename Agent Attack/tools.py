import os
import json
from datetime import datetime

# Resolve all file paths relative to this file's directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOGS_DIR = os.path.join(BASE_DIR, "execution_logs")
os.makedirs(LOGS_DIR, exist_ok=True)

def read_file(path: str) -> str:
    """Read file and log the action.

    The LLM often invents absolute Linux paths (e.g. /home/user/config.py).
    On Windows os.path.isabs() returns True for these, so joining with
    BASE_DIR would be skipped and Windows would look for C:/home/user/...
    which never exists.

    Fix: always take just the basename (filename only) from whatever path
    the model provides, then resolve it from BASE_DIR. This means the model
    can only read files that are actually inside the Agent Attack folder.
    """
    log_action("read_file", {"path": path})
    filename = os.path.basename(path)          # strip any directory prefix
    resolved = os.path.join(BASE_DIR, filename)  # anchor to our folder
    try:
        with open(resolved, "r") as f:
            content = f.read()
        return f"File contents:\n{content}"
    except FileNotFoundError:
        return f"Error: File '{filename}' not found in Agent Attack folder"

def send_email(to: str, subject: str, body: str) -> str:
    """Log email (simulate sending without actually sending)"""
    log_action("send_email", {"to": to, "subject": subject, "body": body})
    return f"Email sent to {to} with subject '{subject}'"

def run_query(query: str) -> str:
    """Log query execution"""
    log_action("run_query", {"query": query})
    return f"Query executed: {query}"

def log_action(tool_name: str, params: dict):
    """Log all tool executions to a single daily log file (proof of side effect)"""
    log_file = os.path.join(LOGS_DIR, f"tool_calls_{datetime.now().strftime('%Y%m%d')}.jsonl")
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "params": params
    }
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def execute_tool(tool_name: str, tool_input: dict) -> str:
    """Route tool calls to implementations"""
    if tool_name == "read_file":
        return read_file(tool_input["path"])
    elif tool_name == "send_email":
        return send_email(tool_input["to"], tool_input["subject"], tool_input["body"])
    elif tool_name == "run_query":
        return run_query(tool_input["query"])
    else:
        return f"Unknown tool: {tool_name}"
