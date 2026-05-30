import json
import argparse
from openai import OpenAI
from config.vars import API_KEY
from kube_functions.connector import connect
from kube_functions.prompts import SYSTEM_PROMPT
import kube_functions.list as list_tools
import kube_functions.security as security_tools

client = OpenAI(api_key=API_KEY, base_url="https://api.anthropic.com/v1")

definitions = [
    *list_tools.definitions,
    *security_tools.definitions,
]

def dispatch(name, args, k8s, k8s_apps):
    return (
        list_tools.dispatch(name, args, k8s=k8s, k8s_apps=k8s_apps) or
        security_tools.dispatch(name, args, k8s=k8s, k8s_apps=k8s_apps) or
        f"Unknown tool: {name}"
    )

def send(messages, k8s, k8s_apps):
    while True:
        response = client.chat.completions.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            tools=definitions,
            messages=[{"role": "system", "content": SYSTEM_PROMPT}] + messages,
        )
        msg = response.choices[0].message
        finish_reason = response.choices[0].finish_reason

        if finish_reason == "tool_calls":
            messages.append(msg)
            for tool_call in msg.tool_calls:
                args = json.loads(tool_call.function.arguments)
                print(f"  \033[90m[tool] {tool_call.function.name}({args})\033[0m")
                result = dispatch(tool_call.function.name, args, k8s, k8s_apps)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result
                })

        elif finish_reason == "stop":
            messages.append({"role": "assistant", "content": msg.content})
            return msg.content

def main():
    parser = argparse.ArgumentParser(description="Kubernetes AI Agent")
    parser.add_argument("--kubeconfig", required=True, help="Path to kubeconfig file")
    args = parser.parse_args()

    k8s, k8s_apps = connect(args.kubeconfig)
    print(f"\033[90m✓ Connected via {args.kubeconfig}\033[0m")

    messages = []
    print("\033[96m╔══════════════════════════════════╗")
    print("║      Kubernetes AI Agent         ║")
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
            reply = send(messages, k8s, k8s_apps)
            print(f"\033[94mclaude>\033[0m {reply}\n")
        except KeyboardInterrupt:
            print("\n\033[90mGoodbye!\033[0m")
            break

if __name__ == "__main__":
    main()