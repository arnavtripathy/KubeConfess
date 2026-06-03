from kubernetes.client.rest import ApiException


# System ClusterRoles are noisy and rarely interesting — filter by default
SYSTEM_PREFIXES = [
    "system:",
    "kubeadm:",
    "kindnet",
    "local-path",
]

EXCLUDED_NAMES = {"admin", "edit", "view", "cluster-admin"}


def list_clusterroles(k8s_rbac, include_system: bool = False) -> str:
    try:
        clusterroles = k8s_rbac.list_cluster_role()

        if not clusterroles.items:
            return "No ClusterRoles found."

        items = clusterroles.items
        if not include_system:
            items = [
                cr for cr in items
                if not any(cr.metadata.name.startswith(p) for p in SYSTEM_PREFIXES) and cr.metadata.name not in EXCLUDED_NAMES
            ]

        if not items:
            return "No non-system ClusterRoles found. Use include_system=true to see system roles."

        lines = [f"Found {len(items)} ClusterRole(s):\n"]
        for cr in items:
            rules_count = len(cr.rules) if cr.rules else 0
            lines.append(f"  {cr.metadata.name} — {rules_count} rule(s)")

            for rule in (cr.rules or []):
                verbs     = ", ".join(rule.verbs or [])
                resources = ", ".join(rule.resources or [])

                # Flag wildcards immediately
                if "*" in (rule.verbs or []) or "*" in (rule.resources or []):
                    lines.append(f"    ⚠ WILDCARD — verbs: [{verbs}]  resources: [{resources}]")
                else:
                    lines.append(f"    verbs: [{verbs}]  resources: [{resources}]")

        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "list_clusterroles",
        "description": (
            "List ClusterRoles and their rules. ClusterRoles apply across all namespaces. "
            "System roles (system:, kubeadm:) are hidden by default to reduce noise. "
            "Wildcards in verbs or resources are flagged automatically. "
            "Use include_system=true to see everything."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "include_system": {
                    "type": "boolean",
                    "description": "Include system ClusterRoles (system:, kubeadm: prefixes). Defaults to false."
                }
            },
            "required": []
        }
    }
}