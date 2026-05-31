from kubernetes.client.rest import ApiException

def list_services(k8s, namespace: str = "all") -> str:
    try:
        if namespace == "all":
            services = k8s.list_service_for_all_namespaces()
        else:
            services = k8s.list_namespaced_service(namespace=namespace)

        if not services.items:
            return f"No services found in: {namespace}"

        lines = [f"Found {len(services.items)} service(s):\n"]
        for svc in services.items:
            ns = svc.metadata.namespace

            # Get selector to find matching pods
            selector = svc.spec.selector
            if selector:
                label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
                pods = k8s.list_namespaced_pod(namespace=ns, label_selector=label_selector)
                pod_names = [pod.metadata.name for pod in pods.items] or ["no pods matched"]
            else:
                pod_names = ["no selector — headless or external service"]

            # Build service info
            ports = ", ".join(
                f"{p.port}/{p.protocol}" for p in (svc.spec.ports or [])
            )
            lines.append(f"  {ns}/{svc.metadata.name}")
            lines.append(f"    type:  {svc.spec.type}")
            lines.append(f"    ports: {ports or 'none'}")
            lines.append(f"    pods:  {', '.join(pod_names)}\n")

        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"

definition = {
    "type": "function",
    "function": {
        "name": "list_services",
        "description": "List services in the Kubernetes cluster and which pods they are attached to, optionally filtered by namespace",
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