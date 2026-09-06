from pathlib import Path

from kubernetes import client
from kubernetes.client.rest import ApiException

CHECKS = [
    ("get", "pods"),
    ("list", "pods"),
    ("create", "pods"),
    ("delete", "pods"),
    ("get", "pods/exec"),
    ("create", "pods/exec"),
    ("get", "deployments"),
    ("list", "deployments"),
    ("create", "deployments"),
    ("delete", "deployments"),
    ("patch", "deployments"),
    ("update", "deployments"),
    ("get", "secrets"),
    ("list", "secrets"),
    ("create", "secrets"),
    ("get", "configmaps"),
    ("list", "configmaps"),
    ("get", "services"),
    ("list", "services"),
    ("get", "roles"),
    ("list", "roles"),
    ("create", "rolebindings"),
    ("patch", "rolebindings"),
    ("get", "clusterroles"),
    ("list", "clusterroles"),
    ("create", "clusterrolebindings"),
    ("patch", "clusterrolebindings"),
    ("get", "serviceaccounts"),
    ("list", "serviceaccounts"),
    ("create", "serviceaccounts"),
    ("get", "nodes"),
    ("list", "nodes"),
    ("get", "namespaces"),
    ("list", "namespaces"),
    ("create", "namespaces"),
    ("*", "*"),
]


def _check_single_permission(k8s_auth, verb, resource, namespace=None) -> bool:
    """Check one verb/resource combo, return True if allowed."""
    parts = resource.split("/")
    res = parts[0]
    subresource = parts[1] if len(parts) > 1 else None
    try:
        review = k8s_auth.create_self_subject_access_review(
            body=client.V1SelfSubjectAccessReview(
                spec=client.V1SelfSubjectAccessReviewSpec(
                    resource_attributes=client.V1ResourceAttributes(
                        verb=verb,
                        resource=res,
                        subresource=subresource,
                        namespace=namespace,
                    )
                )
            )
        )
        return review.status.allowed
    except ApiException:
        return False


def _get_accessible_namespaces(k8s_auth, k8s) -> list:
    """
    Figure out which namespaces we can actually see.
    First try listing all namespaces — if that works we have broad access.
    If not, fall back to known namespaces and check each one individually.
    """
    # try cluster-wide list first
    if _check_single_permission(k8s_auth, "list", "namespaces"):
        try:
            ns_list = k8s.list_namespace()
            return [ns.metadata.name for ns in ns_list.items]
        except ApiException:
            pass

    # can't list namespaces — try common ones + current namespace
    candidates = [
        "default",
        "kube-system",
        "kube-public",
        "monitoring",
        "logging",
        "istio-system",
        "cert-manager",
        "ingress-nginx",
        "vault",
        "payments",
        "staging",
        "production",
        "dev",
    ]

    # add current namespace if in-cluster
    try:
        current = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read_text().strip()
        if current not in candidates:
            candidates.insert(0, current)
    except FileNotFoundError:
        pass

    # check which ones we can actually get pods from
    accessible = []
    for ns in candidates:
        if _check_single_permission(k8s_auth, "get", "pods", namespace=ns):
            accessible.append(ns)

    return accessible


def list_permissions(k8s_auth: client.AuthorizationV1Api, k8s: client.CoreV1Api = None, namespace: str = "all") -> str:
    try:
        allowed_cluster = []
        allowed_by_ns: dict[str, list] = {}  # namespace → list of allowed permissions
        denied = []

        # ── Step 1: cluster-scoped check ─────────────────────────────────────
        for verb, resource in CHECKS:
            entry = f"{verb} {resource}"
            if _check_single_permission(k8s_auth, verb, resource, namespace=None):
                allowed_cluster.append(entry)

        # ── Step 2: figure out which namespaces to check ──────────────────────
        if namespace == "all":
            if k8s:
                namespaces_to_check = _get_accessible_namespaces(k8s_auth, k8s)
            else:
                namespaces_to_check = []
        else:
            namespaces_to_check = [namespace]

        # ── Step 3: namespace-scoped check for anything not allowed cluster-wide
        cluster_allowed_set = set(allowed_cluster)

        for ns in namespaces_to_check:
            for verb, resource in CHECKS:
                entry = f"{verb} {resource}"
                if entry in cluster_allowed_set:
                    continue  # already allowed cluster-wide, skip
                if _check_single_permission(k8s_auth, verb, resource, namespace=ns):
                    if ns not in allowed_by_ns:
                        allowed_by_ns[ns] = []
                    allowed_by_ns[ns].append(entry)

        # ── Step 4: anything not allowed anywhere is denied ───────────────────
        ns_allowed_set = set(p for perms in allowed_by_ns.values() for p in perms)
        for verb, resource in CHECKS:
            entry = f"{verb} {resource}"
            if entry not in cluster_allowed_set and entry not in ns_allowed_set:
                denied.append(entry)

        # ── Format output ─────────────────────────────────────────────────────
        lines = []

        if "* *" in allowed_cluster:
            lines.append("⚠ [CLUSTER-ADMIN] Wildcard permissions — full cluster access\n")

        lines.append(f"Checked {len(CHECKS)} permission(s)\n")

        if allowed_cluster:
            lines.append(f"[ALLOWED CLUSTER-WIDE] {len(allowed_cluster)}:")
            for p in allowed_cluster:
                lines.append(f"  ✓  {p}")
            lines.append("")

        if allowed_by_ns:
            for ns, perms in allowed_by_ns.items():
                lines.append(f"[ALLOWED IN {ns}] {len(perms)}:")
                for p in perms:
                    lines.append(f"  ✓  {p}")
                lines.append("")

        if not allowed_cluster and not allowed_by_ns:
            lines.append("[ALLOWED] none — very restricted identity")
            lines.append("")

        if namespaces_to_check:
            lines.append(f"Namespaces checked: {', '.join(namespaces_to_check)}\n")

        if denied:
            lines.append(f"[DENIED] {len(denied)}:")
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
            "Check what the current identity can do in the cluster. "
            "Works for both kubeconfig users and in-cluster ServiceAccounts. "
            "Automatically discovers accessible namespaces and checks permissions "
            "both cluster-wide and per namespace. "
            "Use this to understand full access scope regardless of how restricted the identity is."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": ("Specific namespace to check, or 'all' to auto-discover accessible namespaces and check each one."),
                }
            },
            "required": [],
        },
    },
}
