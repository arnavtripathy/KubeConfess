from kubernetes.client.rest import ApiException


def list_pods(k8s, k8s_rbac=None, namespace: str = "all", show_sa: bool = False) -> str:
    try:
        if namespace == "all":
            pod_list = k8s.list_pod_for_all_namespaces()
        else:
            pod_list = k8s.list_namespaced_pod(namespace=namespace)

        if not pod_list.items:
            return f"No pods found in: {namespace}"

        # If show_sa, fetch bindings once for all SA lookups
        crbs = []
        rbs = []
        if show_sa and k8s_rbac:
            try:
                crbs = k8s_rbac.list_cluster_role_binding().items
            except ApiException:
                pass
            try:
                rbs = k8s_rbac.list_role_binding_for_all_namespaces().items
            except ApiException:
                try:
                    ns_to_check = namespace if namespace != "all" else "default"
                    rbs = k8s_rbac.list_namespaced_role_binding(namespace=ns_to_check).items
                except ApiException:
                    pass

        lines = [f"Found {len(pod_list.items)} pod(s):\n"]

        for pod in pod_list.items:
            ns = pod.metadata.namespace
            name = pod.metadata.name
            phase = pod.status.phase
            sa_name = pod.spec.service_account_name or "default"
            node = pod.spec.node_name

            lines.append(f"  {ns}/{name} — {phase} — node: {node}")
            lines.append(f"    serviceAccount: {sa_name}")

            if show_sa and k8s_rbac:
                # Find bindings for this SA
                sa_crbs = [
                    crb
                    for crb in crbs
                    if any(s.kind == "ServiceAccount" and s.name == sa_name and s.namespace == ns for s in (crb.subjects or []))
                ]
                sa_rbs = [
                    rb
                    for rb in rbs
                    if any(s.kind == "ServiceAccount" and s.name == sa_name and s.namespace == ns for s in (rb.subjects or []))
                ]

                if not sa_crbs and not sa_rbs:
                    lines.append("    bindings: none")
                else:
                    for crb in sa_crbs:
                        flag = " ⚠ CRITICAL" if crb.role_ref.name == "cluster-admin" else ""
                        lines.append(f"    ClusterRoleBinding: {crb.role_ref.name}{flag}")
                    for rb in sa_rbs:
                        lines.append(f"    RoleBinding: {rb.role_ref.name}")

            lines.append("")

        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "list_pods",
        "description": (
            "List pods in the cluster, optionally filtered by namespace. "
            "Set show_sa=true to also show the ServiceAccount each pod runs as "
            "and what RBAC bindings that SA has — useful for finding pods that "
            "inherit dangerous cluster permissions."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "namespace": {"type": "string", "description": "Namespace to filter by, or 'all' for every namespace."},
                "show_sa": {
                    "type": "boolean",
                    "description": "Show the ServiceAccount and its RBAC bindings for each pod. Defaults to false.",
                },
            },
            "required": [],
        },
    },
}
