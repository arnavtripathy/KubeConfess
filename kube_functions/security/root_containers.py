from kubernetes.client.rest import ApiException

def _check_root(pod) -> list:
    findings = []
    for container in pod.spec.containers:
        sc = container.security_context
        reason = None

        if sc is None:
            reason = "no securityContext set — defaults to root"
        elif sc.run_as_non_root is None and sc.run_as_user is None:
            reason = "runAsNonRoot not set and runAsUser not set — likely running as root"
        elif sc.run_as_non_root is False:
            reason = "runAsNonRoot explicitly set to false"
        elif sc.run_as_user == 0:
            reason = "runAsUser set to 0 (root)"

        if reason:
            findings.append({
                "pod":       pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "container": container.name,
                "reason":    reason,
            })
    return findings


def _format_findings(findings: list, scope: str) -> str:
    if not findings:
        return f"✓ No root containers found in: {scope}"

    lines = [f"⚠ Found {len(findings)} container(s) running as root in {scope}:\n"]
    for f in findings:
        lines.append(f"  ⚠ HIGH — {f['namespace']}/{f['pod']} ({f['container']})")
        lines.append(f"     What: {f['reason']}")
        lines.append(f"     Risk: process breakout gives attacker root on the container filesystem")
        lines.append(f"     Fix: set securityContext.runAsNonRoot: true and runAsUser: <non-zero>\n")
    return "\n".join(lines)


def check_root_containers(k8s, namespace: str = "all", pod: str = None, deployment: str = None, k8s_apps=None) -> str:
    try:
        # ── Single pod ────────────────────────────────────────────────────────
        if pod:
            ns = namespace if namespace != "all" else "default"
            pod_obj = k8s.read_namespaced_pod(name=pod, namespace=ns)
            return _format_findings(_check_root(pod_obj), f"pod {ns}/{pod}")

        # ── Deployment ────────────────────────────────────────────────────────
        if deployment:
            ns = namespace if namespace != "all" else "default"
            dep = k8s_apps.read_namespaced_deployment(name=deployment, namespace=ns)
            selector = dep.spec.selector.match_labels
            label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
            pods = k8s.list_namespaced_pod(namespace=ns, label_selector=label_selector)

            if not pods.items:
                return f"No pods found for deployment '{deployment}' in '{ns}'."

            findings = []
            for pod_obj in pods.items:
                findings.extend(_check_root(pod_obj))
            return _format_findings(findings, f"deployment {ns}/{deployment}")

        # ── Namespace / cluster scan ──────────────────────────────────────────
        pods = k8s.list_pod_for_all_namespaces() if namespace == "all" else k8s.list_namespaced_pod(namespace=namespace)

        findings = []
        for pod_obj in pods.items:
            findings.extend(_check_root(pod_obj))
        return _format_findings(findings, namespace)

    except ApiException as e:
        if e.status == 404:
            target = deployment or pod or namespace
            return f"'{target}' not found in namespace '{namespace}'."
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "check_root_containers",
        "description": "Check for containers running as root. Scans cluster, namespace, a specific pod, or all pods in a deployment.",
        "parameters": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "Namespace to scan, or 'all' for every namespace."
                },
                "pod": {
                    "type": "string",
                    "description": "Specific pod name to check."
                },
                "deployment": {
                    "type": "string",
                    "description": "Deployment name — checks all pods belonging to it."
                }
            },
            "required": []
        }
    }
}