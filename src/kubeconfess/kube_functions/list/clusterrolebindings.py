from kubernetes.client.rest import ApiException

DANGEROUS_ROLES = ["cluster-admin", "admin", "edit"]


def list_clusterrolebindings(k8s_rbac) -> str:
    try:
        crbs = k8s_rbac.list_cluster_role_binding().items

        if not crbs:
            return "No ClusterRoleBindings found."

        lines = [f"Found {len(crbs)} ClusterRoleBinding(s):\n"]
        for crb in crbs:
            role = crb.role_ref.name
            subjects = crb.subjects or []
            flag = " ⚠ CRITICAL" if role == "cluster-admin" else " ⚠" if role in DANGEROUS_ROLES else ""

            lines.append(f"  {crb.metadata.name} → {role}{flag}")
            for s in subjects:
                ns_str = f"/{s.namespace}" if getattr(s, "namespace", None) else ""
                lines.append(f"    subject: {s.kind}{ns_str}/{s.name}")
            lines.append("")

        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "list_clusterrolebindings",
        "description": (
            "List all ClusterRoleBindings in the cluster. "
            "ClusterRoleBindings grant permissions across all namespaces — "
            "always more dangerous than namespace-scoped RoleBindings. "
            "Flags cluster-admin bindings as CRITICAL. "
            "Use this to find over-privileged ServiceAccounts and users with cluster-wide access."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
}
