from kubernetes.client.rest import ApiException

# Secret types that are noisy and rarely interesting during an audit
SYSTEM_SECRET_TYPES = [
    "kubernetes.io/service-account-token",
    "helm.sh/release.v1",
]


def _format_secret(secret, redact: bool = True) -> list:
    lines = []
    secret_type = secret.type or "Opaque"
    keys = list(secret.data.keys()) if secret.data else []

    lines.append(f"  {secret.metadata.namespace}/{secret.metadata.name}")
    lines.append(f"    type: {secret_type}")
    lines.append(f"    keys: {', '.join(keys) if keys else 'empty'}")
    return lines


def _secrets_for_pod(k8s, pod_obj) -> str:
    """Extract secrets a pod has access to via env vars and volume mounts."""
    ns = pod_obj.metadata.namespace
    name = pod_obj.metadata.name
    found: dict[str, list] = {}

    for container in pod_obj.spec.containers:
        # Secrets injected as env vars
        for env in container.env or []:
            if env.value_from and env.value_from.secret_key_ref:
                ref = env.value_from.secret_key_ref
                found[ref.name] = found.get(ref.name, [])
                found[ref.name].append(f"env:{env.name} → key:{ref.key}")

        # Secrets from envFrom
        for env_from in container.env_from or []:
            if env_from.secret_ref:
                ref = env_from.secret_ref
                found[ref.name] = found.get(ref.name, [])
                found[ref.name].append("envFrom (all keys)")

    # Secrets mounted as volumes
    volumes = {v.name: v for v in (pod_obj.spec.volumes or [])}
    for container in pod_obj.spec.containers:
        for mount in container.volume_mounts or []:
            volume = volumes.get(mount.name)
            if volume and volume.secret:
                ref = volume.secret.secret_name
                found[ref] = found.get(ref, [])
                found[ref].append(f"volume mounted at {mount.mount_path}")

    if not found:
        return f"Pod {ns}/{name} has no secrets referenced in its spec."

    lines = [f"Pod {ns}/{name} references {len(found)} secret(s):\n"]
    for secret_name, refs in found.items():
        # Try to fetch the actual secret to show its keys
        try:
            secret = k8s.read_namespaced_secret(name=secret_name, namespace=ns)
            keys = list(secret.data.keys()) if secret.data else []
            lines.append(f"  {ns}/{secret_name}")
            lines.append(f"    keys:   {', '.join(keys) if keys else 'empty'}")
            lines.append(f"    via:    {', '.join(refs)}")
        except ApiException:
            lines.append(f"  {ns}/{secret_name}")
            lines.append("    keys:   [could not read — insufficient permissions]")
            lines.append(f"    via:    {', '.join(refs)}")

    return "\n".join(lines)


def list_secrets(k8s, k8s_apps=None, namespace: str = "all", pod: str = None, deployment: str = None, include_system: bool = False) -> str:
    try:
        # ── Single pod — show secrets it references ───────────────────────────
        if pod:
            ns = namespace if namespace != "all" else "default"
            pod_obj = k8s.read_namespaced_pod(name=pod, namespace=ns)
            return _secrets_for_pod(k8s, pod_obj)

        # ── Deployment — show secrets referenced by its pods ──────────────────
        if deployment:
            ns = namespace if namespace != "all" else "default"
            dep = k8s_apps.read_namespaced_deployment(name=deployment, namespace=ns)
            selector = dep.spec.selector.match_labels
            label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
            pods = k8s.list_namespaced_pod(namespace=ns, label_selector=label_selector)

            if not pods.items:
                return f"No pods found for deployment '{deployment}' in '{ns}'."

            lines = [f"Secrets referenced by deployment {ns}/{deployment}:\n"]
            for pod_obj in pods.items:
                lines.append(_secrets_for_pod(k8s, pod_obj))
                lines.append("")
            return "\n".join(lines)

        # ── Namespace / cluster — list all secrets ────────────────────────────
        if namespace == "all":
            secret_list = k8s.list_secret_for_all_namespaces()
        else:
            secret_list = k8s.list_namespaced_secret(namespace=namespace)

        items = secret_list.items
        if not include_system:
            items = [s for s in items if s.type not in SYSTEM_SECRET_TYPES]

        if not items:
            return f"No secrets found in: {namespace}"

        lines = [f"Found {len(items)} secret(s) in {namespace}:\n"]
        for secret in items:
            lines.extend(_format_secret(secret))
            lines.append("")

        if not include_system:
            filtered = len(secret_list.items) - len(items)
            if filtered:
                lines.append(f"  [{filtered} system secret(s) hidden — use include_system=true to show]")

        return "\n".join(lines)

    except ApiException as e:
        if e.status == 404:
            target = deployment or pod or namespace
            return f"'{target}' not found in namespace '{namespace}'."
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "list_secrets",
        "description": (
            "List Kubernetes secrets. Three modes: "
            "1) namespace/cluster-wide — lists all secrets and their keys (values are never shown). "
            "2) pod — shows which secrets that specific pod references via env vars, envFrom, and volume mounts. "
            "3) deployment — shows secrets referenced by all pods in the deployment. "
            "System secrets (SA tokens, Helm releases) are hidden by default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "Namespace to list secrets from, or 'all' for cluster-wide.",
                },
                "pod": {"type": "string", "description": "Pod name — returns secrets that pod references in its spec."},
                "deployment": {
                    "type": "string",
                    "description": "Deployment name — returns secrets referenced by its pods.",
                },
                "include_system": {
                    "type": "boolean",
                    "description": "Include system secrets (SA tokens, Helm releases). Defaults to false.",
                },
            },
            "required": [],
        },
    },
}
