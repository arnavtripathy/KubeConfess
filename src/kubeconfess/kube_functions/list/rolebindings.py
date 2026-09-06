from kubernetes.client.rest import ApiException

DANGEROUS_ROLES = ["cluster-admin", "admin", "edit"]


def list_rolebindings(k8s_rbac, namespace: str = "all") -> str:
    try:
        if namespace == "all":
            rbs = k8s_rbac.list_role_binding_for_all_namespaces().items
        else:
            rbs = k8s_rbac.list_namespaced_role_binding(namespace=namespace).items

        if not rbs:
            return f"No RoleBindings found in: {namespace}"

        lines = [f"Found {len(rbs)} RoleBinding(s):\n"]
        for rb in rbs:
            role = rb.role_ref.name
            subjects = rb.subjects or []
            flag = " ⚠ CRITICAL" if role == "cluster-admin" else " ⚠" if role in DANGEROUS_ROLES else ""

            lines.append(f"  {rb.metadata.namespace}/{rb.metadata.name} → {role}{flag}")
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
        "name": "list_rolebindings",
        "description": (
            "List RoleBindings in the cluster, optionally filtered by namespace. "
            "RoleBindings grant permissions within a specific namespace only. "
            "Flags dangerous roles like admin and edit. "
            "Use this to understand namespace-scoped access. "
            "For cluster-wide bindings use list_clusterrolebindings instead."
        ),
        "parameters": {
            "type": "object",
            "properties": {"namespace": {"type": "string", "description": "Namespace to filter by, or 'all' for every namespace."}},
            "required": [],
        },
    },
}
