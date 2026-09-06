from kubernetes.client.rest import ApiException


def _check_containers(pod) -> list:
    """Returns privileged container findings for a given pod object."""
    findings = []
    for container in pod.spec.containers:
        sc = container.security_context
        if sc and sc.privileged:
            findings.append(
                {
                    "pod": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "container": container.name,
                }
            )
    return findings


def _format_findings(findings: list, scope: str) -> str:
    """Formats findings list into a human-readable result string."""
    if not findings:
        return f"✓ No privileged containers found in: {scope}"

    lines = [f"⚠ Found {len(findings)} privileged container(s) in {scope}:\n"]
    for f in findings:
        lines.append(f"  {f['namespace']}/{f['pod']} — container: {f['container']}")
    lines.append("\nRisk: privileged containers have full host access and can escape the container boundary.")
    lines.append("Fix: remove `securityContext.privileged: true` unless absolutely required.")
    return "\n".join(lines)


def check_privileged_pods(k8s, k8s_apps, namespace: str = "all", pod: str = None, deployment: str = None) -> str:
    try:
        # ── Single pod ────────────────────────────────────────────────────────
        if pod:
            ns = namespace if namespace != "all" else "default"
            pod_obj = k8s.read_namespaced_pod(name=pod, namespace=ns)
            findings = _check_containers(pod_obj)
            return _format_findings(findings, f"pod {ns}/{pod}")

        # ── Deployment — fetch pods via label selector ─────────────────────
        if deployment:
            ns = namespace if namespace != "all" else "default"

            # Read the deployment to get its label selector
            dep = k8s_apps.read_namespaced_deployment(name=deployment, namespace=ns)
            selector = dep.spec.selector.match_labels
            label_selector = ",".join(f"{k}={v}" for k, v in selector.items())

            pods = k8s.list_namespaced_pod(namespace=ns, label_selector=label_selector)

            if not pods.items:
                return f"No pods found for deployment '{deployment}' in namespace '{ns}'."

            findings = []
            for pod_obj in pods.items:
                findings.extend(_check_containers(pod_obj))
            return _format_findings(findings, f"deployment {ns}/{deployment}")

        # ── Namespace / cluster scan ──────────────────────────────────────────
        if namespace == "all":
            pods = k8s.list_pod_for_all_namespaces()
        else:
            pods = k8s.list_namespaced_pod(namespace=namespace)

        findings = []
        for pod_obj in pods.items:
            findings.extend(_check_containers(pod_obj))
        return _format_findings(findings, namespace)

    except ApiException as e:
        if e.status == 404:
            target = deployment or pod or namespace
            return f"'{target}' not found in namespace '{namespace}'."
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "check_privileged_pods",
        "description": (
            "Check for privileged containers. "
            "Scans a whole namespace by default. "
            "Provide a pod name to check a specific pod. "
            "Provide a deployment name to check all pods in that deployment."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "namespace": {"type": "string", "description": "Namespace to scan, or 'all' for every namespace."},
                "pod": {"type": "string", "description": "Specific pod name to check."},
                "deployment": {"type": "string", "description": "Deployment name — checks all pods belonging to it."},
            },
            "required": [],
        },
    },
}
