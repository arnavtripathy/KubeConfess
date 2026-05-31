import json
from openai import OpenAI
from config.vars import API_KEY
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
            model="claude-haiku-4-5",
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