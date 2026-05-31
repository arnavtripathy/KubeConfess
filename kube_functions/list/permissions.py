from kubernetes.client.rest import ApiException
from kubernetes import client

# Covers the most operationally relevant verb/resource combos
CHECKS = [
    # Core workloads
    ("get",    "pods"),
    ("list",   "pods"),
    ("create", "pods"),
    ("delete", "pods"),
    ("get",    "pods/exec"),
    ("create", "pods/exec"),
    # Deployments
    ("get",    "deployments"),
    ("list",   "deployments"),
    ("create", "deployments"),
    ("delete", "deployments"),
    # Secrets
    ("get",    "secrets"),
    ("list",   "secrets"),
    ("create", "secrets"),
    # ConfigMaps
    ("get",    "configmaps"),
    ("list",   "configmaps"),
    # Services
    ("get",    "services"),
    ("list",   "services"),
    # RBAC
    ("get",    "roles"),
    ("list",   "roles"),
    ("create", "rolebindings"),
    ("get",    "clusterroles"),
    ("list",   "clusterroles"),
    ("create", "clusterrolebindings"),
    # ServiceAccounts
    ("get",    "serviceaccounts"),
    ("list",   "serviceaccounts"),
    ("create", "serviceaccounts"),
    # Nodes
    ("get",    "nodes"),
    ("list",   "nodes"),
    # Namespaces
    ("get",    "namespaces"),
    ("list",   "namespaces"),
    ("create", "namespaces"),
    # Wildcard — cluster admin check
    ("*",      "*"),
]

def list_permissions(k8s_auth: client.AuthorizationV1Api, namespace: str = "all") -> str:
    try:
        allowed = []
        denied  = []

        for verb, resource in CHECKS:
            # Handle subresources like pods/exec
            parts       = resource.split("/")
            res         = parts[0]
            subresource = parts[1] if len(parts) > 1 else None

            ns = None if namespace == "all" else namespace

            attrs = client.V1ResourceAttributes(
                verb=verb,
                resource=res,
                subresource=subresource,
                namespace=ns,
            )
            review = k8s_auth.create_self_subject_access_review(
                body=client.V1SelfSubjectAccessReview(
                    spec=client.V1SelfSubjectAccessReviewSpec(
                        resource_attributes=attrs
                    )
                )
            )

            entry = f"{verb} {resource}"
            if review.status.allowed:
                allowed.append(entry)
            else:
                denied.append(entry)

        lines = []

        # Cluster admin shortcut
        if "* *" in allowed:
            lines.append("⚠ [CLUSTER-ADMIN] Wildcard permissions detected — full cluster access\n")

        lines.append(f"Checked {len(CHECKS)} permission(s) in namespace: {namespace}\n")

        if allowed:
            lines.append(f"[ALLOWED] {len(allowed)} permission(s):")
            for p in allowed:
                lines.append(f"  ✓  {p}")

        lines.append("")

        if denied:
            lines.append(f"[DENIED] {len(denied)} permission(s):")
            for p in denied:
                lines.append(f"  ✗  {p}")

        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "list_permissions",
        "description": (
            "Check what actions the current user/serviceaccount is allowed to perform "
            "in the cluster. Simulates kubectl auth can-i for a curated list of "
            "security-relevant verb and resource combinations."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "Namespace to check permissions in, or 'all' for cluster-scoped check."
                }
            },
            "required": []
        }
    }
}