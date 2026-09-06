from kubernetes.client.rest import ApiException


def list_deployments(k8s_apps, k8s=None, k8s_rbac=None, namespace: str = "all", show_sa: bool = False) -> str:
    try:
        if namespace == "all":
            dep_list = k8s_apps.list_deployment_for_all_namespaces()
        else:
            dep_list = k8s_apps.list_namespaced_deployment(namespace=namespace)

        if not dep_list.items:
            return f"No deployments found in: {namespace}"

        # Fetch bindings once if show_sa requested
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

        lines = [f"Found {len(dep_list.items)} deployment(s):\n"]

        for dep in dep_list.items:
            ns = dep.metadata.namespace
            name = dep.metadata.name
            ready = dep.status.ready_replicas or 0
            desired = dep.spec.replicas or 0

            # SA is defined in the pod template spec
            sa_name = dep.spec.template.spec.service_account_name or "default"

            lines.append(f"  {ns}/{name} — {ready}/{desired} ready")
            lines.append(f"    serviceAccount: {sa_name}")

            if show_sa and k8s_rbac:
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
                        lines.append(f"    RoleBinding: {rb.metadata.namespace}/{rb.role_ref.name}")

            # Show actual pods for this deployment
            if show_sa and k8s:
                selector = dep.spec.selector.match_labels
                label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
                pods = k8s.list_namespaced_pod(namespace=ns, label_selector=label_selector)
                pod_names = [p.metadata.name for p in pods.items]
                lines.append(f"    pods: {', '.join(pod_names) if pod_names else 'none running'}")

            lines.append("")

        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "list_deployments",
        "description": (
            "List Deployments and their replica health. "
            "Set show_sa=true to also show the ServiceAccount each deployment's pods "
            "run as, its RBAC bindings, and the actual pod names — "
            "useful for finding deployments that inherit dangerous cluster permissions."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "namespace": {"type": "string", "description": "Namespace to filter by, or 'all' for every namespace."},
                "show_sa": {
                    "type": "boolean",
                    "description": "Show ServiceAccount, RBAC bindings, and pod names for each deployment. Defaults to false.",
                },
            },
            "required": [],
        },
    },
}
