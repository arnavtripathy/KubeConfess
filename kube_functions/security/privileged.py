from kubernetes.client.rest import ApiException

def _check_container(pod) -> list:
    """Returns list of privileged container names for a given pod object."""
    findings = []
    for container in pod.spec.containers:
        sc = container.security_context
        if sc and sc.privileged:
            findings.append({
                "pod":       pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "container": container.name,
            })
    return findings


def check_privileged_pods(k8s, namespace: str = "all", pod: str = None) -> str:
    try:
        # ── Single pod ────────────────────────────────────────────────────────
        if pod:
            ns = namespace if namespace != "all" else "default"
            pod_obj = k8s.read_namespaced_pod(name=pod, namespace=ns)
            findings = _check_container(pod_obj)

            if not findings:
                return f"✓ Pod {ns}/{pod} has no privileged containers."

            lines = [f"⚠ Pod {ns}/{pod} has {len(findings)} privileged container(s):\n"]
            for f in findings:
                lines.append(f"  container: {f['container']}")
            lines.append("\nRisk: privileged containers have full host access and can escape the container boundary.")
            lines.append("Fix: remove `securityContext.privileged: true` unless absolutely required.")
            return "\n".join(lines)

        # ── Namespace / cluster scan ──────────────────────────────────────────
        if namespace == "all":
            pods = k8s.list_pod_for_all_namespaces()
        else:
            pods = k8s.list_namespaced_pod(namespace=namespace)

        findings = []
        for pod_obj in pods.items:
            findings.extend(_check_container(pod_obj))

        if not findings:
            return f"✓ No privileged containers found in: {namespace}."

        lines = [f"⚠ Found {len(findings)} privileged container(s):\n"]
        for f in findings:
            lines.append(f"  {f['namespace']}/{f['pod']} — container: {f['container']}")
        lines.append("\nRisk: privileged containers have full host access and can escape the container boundary.")
        lines.append("Fix: remove `securityContext.privileged: true` unless absolutely required.")
        return "\n".join(lines)

    except ApiException as e:
        if e.status == 404:
            return f"Pod '{pod}' not found in namespace '{namespace}'."
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "check_privileged_pods",
        "description": (
            "Check for privileged containers. "
            "Scans a whole namespace (or cluster) by default. "
            "If a pod name is provided, checks only that pod."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "Namespace to scan, or 'all' for every namespace. Defaults to 'all'."
                },
                "pod": {
                    "type": "string",
                    "description": "Specific pod name to check. If omitted, scans the whole namespace."
                }
            },
            "required": []
        }
    }
}