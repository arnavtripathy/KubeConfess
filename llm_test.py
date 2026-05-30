# Deprecated now -Was for learning


from openai import OpenAI
from config.vars import API_KEY
import json
client = OpenAI(
    api_key=API_KEY,
    base_url="https://api.anthropic.com/v1",
)


# --- Your actual functions ---
def get_weather(city: str) -> str:
    return f"The weather in {city} is 22°C and sunny."

def calculate(expression: str) -> str:
    try:
        return f"Result: {eval(expression)}"
    except:
        return "Invalid expression"

def get_time(timezone: str) -> str:
    from datetime import datetime
    return f"Current time in {timezone}: {datetime.now().strftime('%H:%M:%S')}"


# --- Tool definitions (OpenAI format — works with Anthropic too) ---
tools = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the weather for a given city",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "City name e.g. Dublin"}
                },
                "required": ["city"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "calculate",
            "description": "Evaluate a math expression",
            "parameters": {
                "type": "object",
                "properties": {
                    "expression": {"type": "string", "description": "e.g. '12 * 4 + 2'"}
                },
                "required": ["expression"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_time",
            "description": "Get the current time for a timezone",
            "parameters": {
                "type": "object",
                "properties": {
                    "timezone": {"type": "string", "description": "e.g. 'Europe/Dublin'"}
                },
                "required": ["timezone"]
            }
        }
    }
]


# --- Tool dispatcher ---
def run_tool(name: str, args: dict) -> str:
    if name == "get_weather":
        return get_weather(**args)
    elif name == "calculate":
        return calculate(**args)
    elif name == "get_time":
        return get_time(**args)
    return "Unknown tool"


# --- Main chat loop ---
def send(messages):
    while True:
        response = client.chat.completions.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            tools=tools,
            messages=messages
        )

        msg = response.choices[0].message
        finish_reason = response.choices[0].finish_reason

        if finish_reason == "tool_calls":
            messages.append(msg)
            for tool_call in msg.tool_calls:
                args = json.loads(tool_call.function.arguments)
                print(f"  \033[90m[tool] {tool_call.function.name}({args})\033[0m")
                result = run_tool(tool_call.function.name, args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result
                })

        elif finish_reason == "stop":
            messages.append({"role": "assistant", "content": msg.content})
            return msg.content

# --- CLI loop ---
def main():
    messages = []
    print("\033[96m╔══════════════════════════════════╗")
    print("║        Claude CLI Chat           ║")
    print("║  type 'exit' or 'quit' to leave  ║")
    print("╚══════════════════════════════════╝\033[0m\n")

    while True:
        try:
            user_input = input("\033[92myou>\033[0m ").strip()

            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                print("\033[90mGoodbye!\033[0m")
                break

            messages.append({"role": "user", "content": user_input})
            reply = send(messages)
            print(f"\033[94mclaude>\033[0m {reply}\n")

        except KeyboardInterrupt:
            print("\n\033[90mGoodbye!\033[0m")
            break

if __name__ == "__main__":
    main()