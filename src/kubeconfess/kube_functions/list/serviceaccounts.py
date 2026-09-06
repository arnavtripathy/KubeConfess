from kubernetes.client.rest import ApiException


def list_serviceaccounts(k8s, k8s_rbac, namespace: str = "all") -> str:
    try:
        if namespace == "all":
            sa_list = k8s.list_service_account_for_all_namespaces()
        else:
            sa_list = k8s.list_namespaced_service_account(namespace=namespace)

        if not sa_list.items:
            return f"No ServiceAccounts found in: {namespace}"

        # Fetch all bindings once — cheaper than per-SA lookups
        crbs = k8s_rbac.list_cluster_role_binding().items
        rbs = k8s_rbac.list_role_binding_for_all_namespaces().items

        lines = [f"Found {len(sa_list.items)} ServiceAccount(s):\n"]

        for sa in sa_list.items:
            ns = sa.metadata.namespace
            name = sa.metadata.name

            # Find RoleBindings for this SA
            sa_rbs = [
                rb for rb in rbs if any(s.kind == "ServiceAccount" and s.name == name and s.namespace == ns for s in (rb.subjects or []))
            ]

            # Find ClusterRoleBindings for this SA
            sa_crbs = [
                crb
                for crb in crbs
                if any(s.kind == "ServiceAccount" and s.name == name and s.namespace == ns for s in (crb.subjects or []))
            ]

            automount = sa.automount_service_account_token
            automount_str = "⚠ automount enabled" if automount is True or automount is None else "automount disabled"

            lines.append(f"  {ns}/{name} — {automount_str}")

            if not sa_rbs and not sa_crbs:
                lines.append("    bindings: none")
            else:
                for rb in sa_rbs:
                    lines.append(f"    RoleBinding:        {rb.metadata.namespace}/{rb.metadata.name} → {rb.role_ref.name}")
                for crb in sa_crbs:
                    is_dangerous = crb.role_ref.name in ("cluster-admin", "admin", "edit")
                    flag = " ⚠ CRITICAL" if crb.role_ref.name == "cluster-admin" else " ⚠" if is_dangerous else ""
                    lines.append(f"    ClusterRoleBinding: {crb.metadata.name} → {crb.role_ref.name}{flag}")

            lines.append("")

        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "list_serviceaccounts",
        "description": (
            "List ServiceAccounts and their RBAC bindings. "
            "For each SA, shows which RoleBindings and ClusterRoleBindings are attached "
            "and which roles they grant. Flags cluster-admin and over-privileged bindings. "
            "Also flags SAs with automountServiceAccountToken enabled. "
            "Use this to understand what permissions a pod inherits via its SA, "
            "or to find escalation paths via over-privileged SAs."
        ),
        "parameters": {
            "type": "object",
            "properties": {"namespace": {"type": "string", "description": "Namespace to list SAs from, or 'all' for cluster-wide."}},
            "required": [],
        },
    },
}
