from kubernetes.client.rest import ApiException

def list_namespaces(k8s) -> str:
    try:
        namespaces = k8s.list_namespace()

        if not namespaces.items:
            return "No namespaces found."

        lines = [f"Found {len(namespaces.items)} namespace(s):\n"]
        for ns in namespaces.items:
            lines.append(f"  {ns.metadata.name} — {ns.status.phase}")
        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"

definition = {
    "type": "function",
    "function": {
        "name": "list_namespaces",
        "description": "List all namespaces in the Kubernetes cluster",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
}