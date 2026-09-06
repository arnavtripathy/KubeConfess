import shlex

from kubernetes.client.rest import ApiException
from kubernetes.stream import stream


def exec_pod(k8s, pod_name: str, namespace: str, command: str) -> str:
    try:
        output = stream(
            k8s.connect_get_namespaced_pod_exec,
            name=pod_name,
            namespace=namespace,
            command=shlex.split(command),
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
            _preload_content=True,
        )
        return f"{namespace}/{pod_name} $ {command}\n{output}"

    except ApiException as e:
        if e.status == 403:
            return f"✗ Exec denied on {namespace}/{pod_name}\n  SA lacks create pods/exec permission."
        if e.status == 404:
            return f"✗ Pod {namespace}/{pod_name} not found."
        return f"Kubernetes API error: {e.status} {e.reason}"
    except Exception as e:
        return f"Error: {e}"


definition = {
    "type": "function",
    "function": {
        "name": "exec_pod",
        "description": (
            "Run a command in a pod via the Kubernetes API. "
            "No kubectl or TTY needed — works from inside a pod "
            "using the mounted SA token. "
            "Returns the command output as a string. "
            "Only call if list_permissions confirmed create pods/exec is allowed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string", "description": "Name of the pod to run the command in."},
                "namespace": {"type": "string", "description": "Namespace the pod is in."},
                "command": {"type": "string", "description": "Command to run e.g. 'id', 'cat /etc/passwd', 'env'"},
            },
            "required": ["pod_name", "namespace", "command"],
        },
    },
}
