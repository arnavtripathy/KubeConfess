import json

from kubernetes.client.rest import ApiException
from openai import OpenAI

import kubeconfess.kube_functions.attack as attack_tools
import kubeconfess.kube_functions.list as list_tools
import kubeconfess.kube_functions.security as security_tools
from kubeconfess.config.vars import API_KEY, BASE_URL, MAX_TOKENS, MODEL_NAME
from kubeconfess.kube_functions.prompts import SYSTEM_PROMPT

client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

definitions = [
    *list_tools.definitions,
    *security_tools.definitions,
    *attack_tools.definitions,
]


def dispatch(name, args, k8s, k8s_apps, k8s_auth, k8s_rbac):
    return (
        list_tools.dispatch(name, args, k8s=k8s, k8s_apps=k8s_apps, k8s_auth=k8s_auth, k8s_rbac=k8s_rbac)
        or security_tools.dispatch(name, args, k8s=k8s, k8s_apps=k8s_apps, k8s_auth=k8s_auth)
        or attack_tools.dispatch(name, args, k8s=k8s, k8s_apps=k8s_apps)
        or f"Unknown tool: {name}"
    )


def send(messages, k8s, k8s_apps, k8s_auth, k8s_rbac, system_prompt=SYSTEM_PROMPT, on_tool_call=None):
    while True:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            max_tokens=MAX_TOKENS,
            tools=definitions,
            messages=[{"role": "system", "content": system_prompt}] + messages,
        )
        msg = response.choices[0].message
        finish_reason = response.choices[0].finish_reason

        if finish_reason == "tool_calls":
            messages.append(msg)
            for tool_call in msg.tool_calls:
                try:
                    args = json.loads(tool_call.function.arguments)
                except (json.JSONDecodeError, ValueError) as e:
                    result = f"Error: Could not parse tool arguments for {tool_call.function.name}: {e}"
                    messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": result})
                    continue

                if on_tool_call:
                    on_tool_call(tool_call.function.name, args)

                try:
                    result = dispatch(tool_call.function.name, args, k8s, k8s_apps, k8s_auth, k8s_rbac)
                except ApiException as e:
                    result = f"Kubernetes API error calling {tool_call.function.name}: {e.status} {e.reason}"
                except (ValueError, KeyError, AttributeError, TypeError) as e:
                    result = f"Invalid argument to {tool_call.function.name}: {type(e).__name__}: {e}"
                except OSError as e:
                    result = f"File/permission error in {tool_call.function.name}: {e}"
                except Exception as e:  # noqa: BLE001 # backstop: report any unforeseen tool error instead of crashing the agent loop
                    result = f"Unexpected error in {tool_call.function.name}: {type(e).__name__}: {e}"

                messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": result})

        elif finish_reason == "stop":
            messages.append({"role": "assistant", "content": msg.content})
            return msg.content
