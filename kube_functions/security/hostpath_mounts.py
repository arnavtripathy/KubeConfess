from kubernetes.client.rest import ApiException

# Paths that indicate a container has meaningful host filesystem access
SENSITIVE_PATHS = [
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/var/run",
    "/var/run/docker.sock",
    "/run/containerd",
    "/root",
    "/home",
    "/boot",
    "/dev",
]

def _severity(path: str) -> str:
    critical = ["/", "/proc", "/sys", "/var/run/docker.sock",
                "/run/containerd", "/var/lib/kubelet", "/var/lib/docker"]
    return "CRITICAL" if path in critical else "HIGH"

def _check_hostpath(pod) -> list:
    findings = []

    volumes = {v.name: v for v in (pod.spec.volumes or [])}

    for container in pod.spec.containers:
        for mount in (container.volume_mounts or []):
            volume = volumes.get(mount.name)
            if not volume or not volume.host_path:
                continue

            host_path = volume.host_path.path
            is_sensitive = any(
                host_path == p or host_path.startswith(p + "/")
                for p in SENSITIVE_PATHS
            )

            if is_sensitive:
                findings.append({
                    "pod":       pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "container": container.name,
                    "host_path": host_path,
                    "mount":     mount.mount_path,
                    "severity":  _severity(host_path),
                })

    return findings


def _format_findings(findings: list, scope: str) -> str:
    if not findings:
        return f"✓ No sensitive host path mounts found in: {scope}"

    # Sort CRITICAL first
    findings.sort(key=lambda f: (0 if f["severity"] == "CRITICAL" else 1))

    lines = [f"⚠ Found {len(findings)} sensitive host path mount(s) in {scope}:\n"]
    for f in findings:
        lines.append(f"  ⚠ {f['severity']} — {f['namespace']}/{f['pod']} ({f['container']})")
        lines.append(f"     What: host path {f['host_path']} mounted at {f['mount']}")
        lines.append(f"     Risk: container can read/write host filesystem at that path")
        lines.append(f"     Fix:  remove hostPath volume — use PersistentVolumeClaim or ConfigMap instead\n")

    return "\n".join(lines)


def check_hostpath_mounts(k8s, k8s_apps=None, namespace: str = "all", pod: str = None, deployment: str = None) -> str:
    try:
        # ── Single pod ────────────────────────────────────────────────────────
        if pod:
            ns = namespace if namespace != "all" else "default"
            pod_obj = k8s.read_namespaced_pod(name=pod, namespace=ns)
            return _format_findings(_check_hostpath(pod_obj), f"pod {ns}/{pod}")

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
                findings.extend(_check_hostpath(pod_obj))
            return _format_findings(findings, f"deployment {ns}/{deployment}")

        # ── Namespace / cluster scan ──────────────────────────────────────────
        pods = (
            k8s.list_pod_for_all_namespaces()
            if namespace == "all"
            else k8s.list_namespaced_pod(namespace=namespace)
        )

        findings = []
        for pod_obj in pods.items:
            findings.extend(_check_hostpath(pod_obj))
        return _format_findings(findings, namespace)

    except ApiException as e:
        if e.status == 404:
            target = deployment or pod or namespace
            return f"'{target}' not found in namespace '{namespace}'."
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "check_hostpath_mounts",
        "description": (
            "Check for pods mounting sensitive host filesystem paths. "
            "Detects hostPath volumes pointing at paths like /, /etc, /proc, "
            "/var/lib/kubelet, docker socket, containerd socket, etc. "
            "Scans cluster-wide, per namespace, per pod, or per deployment."
        ),
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