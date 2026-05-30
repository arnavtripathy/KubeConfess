from kubernetes.client.rest import ApiException

def list_pods(k8s, namespace: str = "all") -> str:
    try:
        if namespace == "all":
            pods = k8s.list_pod_for_all_namespaces()
        else:
            pods = k8s.list_namespaced_pod(namespace=namespace)

        if not pods.items:
            return f"No pods found in: {namespace}"

        lines = [f"Found {len(pods.items)} pod(s):\n"]
        for pod in pods.items:
            lines.append(f"  {pod.metadata.namespace}/{pod.metadata.name} — {pod.status.phase}")
        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"

definition = {
    "type": "function",
    "function": {
        "name": "list_pods",
        "description": "List pods in the Kubernetes cluster, optionally filtered by namespace",
        "parameters": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "Namespace to filter by, or 'all' for every namespace"
                }
            },
            "required": []
        }
    }
}