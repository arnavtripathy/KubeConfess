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

def dispatch(name, args, k8s, k8s_apps, k8s_auth):
    return (
        list_tools.dispatch(name, args, k8s=k8s, k8s_apps=k8s_apps, k8s_auth=k8s_auth) or
        security_tools.dispatch(name, args, k8s=k8s, k8s_apps=k8s_apps) or
        f"Unknown tool: {name}"
    )

def send(messages, k8s, k8s_apps, k8s_auth, on_tool_call=None):
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
                if on_tool_call:
                    on_tool_call(tool_call.function.name, args) 
                result = dispatch(tool_call.function.name, args, k8s, k8s_apps, k8s_auth)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result
                })

        elif finish_reason == "stop":
            messages.append({"role": "assistant", "content": msg.content})
            return msg.content