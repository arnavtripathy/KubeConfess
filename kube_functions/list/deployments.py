from kubernetes.client.rest import ApiException

def list_deployments(k8s_apps, namespace: str = "all") -> str:
    try:
        if namespace == "all":
            deployments = k8s_apps.list_deployment_for_all_namespaces()
        else:
            deployments = k8s_apps.list_namespaced_deployment(namespace=namespace)

        if not deployments.items:
            return f"No deployments found in: {namespace}"

        lines = [f"Found {len(deployments.items)} deployment(s):\n"]
        for dep in deployments.items:
            ready = dep.status.ready_replicas or 0
            desired = dep.spec.replicas or 0
            lines.append(f"  {dep.metadata.namespace}/{dep.metadata.name} — {ready}/{desired} ready")
        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"

definition = {
    "type": "function",
    "function": {
        "name": "list_deployments",
        "description": "List deployments in the Kubernetes cluster, optionally filtered by namespace",
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