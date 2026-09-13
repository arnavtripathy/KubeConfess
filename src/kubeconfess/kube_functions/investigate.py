"""
Runs a fixed sequence of tools against a target, collects all results,
then sends everything to Claude in one shot for analysis.
No agentic loop — guaranteed to stop.
"""

from kubeconfess.kube_functions.attack.harvest_secrets import harvest_secrets
from kubeconfess.kube_functions.attack.steal_tokens import steal_tokens
from kubeconfess.kube_functions.list.clusterrolebindings import list_clusterrolebindings
from kubeconfess.kube_functions.list.clusterroles import list_clusterroles
from kubeconfess.kube_functions.list.permissions import list_permissions
from kubeconfess.kube_functions.list.pods import list_pods
from kubeconfess.kube_functions.list.rolebindings import list_rolebindings
from kubeconfess.kube_functions.list.roles import list_roles
from kubeconfess.kube_functions.list.secrets import list_secrets
from kubeconfess.kube_functions.list.serviceaccounts import list_serviceaccounts
from kubeconfess.kube_functions.security.hostpath_mounts import check_hostpath_mounts
from kubeconfess.kube_functions.security.privileged import check_privileged_pods
from kubeconfess.kube_functions.security.root_containers import check_root_containers


def _parse_target(target: str) -> tuple:
    """
    Parse target string into (type, name, namespace).
    Accepts:
      pod/nginx-abc
      pod/nginx-abc -n payments
      namespace/payments
      sa/deployer -n default
    """
    parts = target.strip().split("/", 1)
    kind = parts[0].lower() if len(parts) > 1 else "pod"
    name = parts[1] if len(parts) > 1 else parts[0]

    # Extract namespace if provided e.g. "pod/nginx -n payments"
    namespace = "default"
    if " -n " in name:
        name, namespace = name.split(" -n ", 1)
        name = name.strip()
        namespace = namespace.strip()

    #Fix for namespaces being specified as the target, e.g. "namespace/payments"
    if kind == "namespace":
        namespace = name

    return kind, name.strip(), namespace


def _section(title: str, content: str) -> str:
    return f"\n{'=' * 50}\n{title}\n{'=' * 50}\n{content}\n"


def gather(target: str, k8s, k8s_apps, k8s_auth, k8s_rbac, on_step=None) -> str:
    """
    Run all checks against the target and return a single string
    with all findings concatenated. This goes to Claude as one message.
    """
    kind, name, namespace = _parse_target(target)
    results = []

    def run(label, fn, *args, **kwargs):
        if on_step:
            on_step(label)
        try:
            result = fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 # We want to catch all exceptions here to report errors in the output.
            result = f"Error: {e}"
        results.append(_section(label, result))

    # ── Always run ────────────────────────────────────────────────────────────
    run("PERMISSIONS (what can this identity do?)", list_permissions, k8s_auth, namespace=namespace)

    run("SERVICE ACCOUNTS + BINDINGS", list_serviceaccounts, k8s, k8s_rbac, namespace=namespace)

    run("ROLEBINDINGS", list_rolebindings, k8s_rbac, namespace=namespace)
    run(
        "CLUSTERROLEBINDINGS",  # ← add
        list_clusterrolebindings,
        k8s_rbac,
    )  # ← add

    run("ROLES", list_roles, k8s_rbac, namespace=namespace)

    run("CLUSTER ROLES", list_clusterroles, k8s_rbac)

    # ── Pod-specific ──────────────────────────────────────────────────────────
    if kind == "pod":
        run(f"TARGET POD ({namespace}/{name})", list_pods, k8s, k8s_rbac=k8s_rbac, namespace=namespace, show_sa=True)

        run("SECRETS ACCESSIBLE", list_secrets, k8s, k8s_apps=k8s_apps, namespace=namespace, pod=name)

    # ── Namespace-specific ────────────────────────────────────────────────────
    if kind in ("namespace", "pod"):
        run("ALL PODS IN SCOPE", list_pods, k8s, k8s_rbac=k8s_rbac, namespace=namespace, show_sa=True)

        run("SECRETS IN NAMESPACE", list_secrets, k8s, k8s_apps=k8s_apps, namespace=namespace)

    # ── SA-specific ───────────────────────────────────────────────────────────
    if kind == "sa":
        run(f"TARGET SERVICE ACCOUNT ({namespace}/{name})", list_serviceaccounts, k8s, k8s_rbac, namespace=namespace)

        run("PODS RUNNING AS THIS SA", list_pods, k8s, k8s_rbac=k8s_rbac, namespace=namespace, show_sa=True)

    # ── Security checks — always ──────────────────────────────────────────────
    run("PRIVILEGED CONTAINERS", check_privileged_pods, k8s, k8s_apps, namespace=namespace)

    run("ROOT CONTAINERS", check_root_containers, k8s, k8s_apps=k8s_apps, namespace=namespace)

    run("HOST PATH MOUNTS", check_hostpath_mounts, k8s, k8s_apps=k8s_apps, namespace=namespace)

    # ──  Attack mode Stuff ─────────────────────────────────────────────
    run("TOKEN THEFT — static SA tokens readable from secrets", steal_tokens, k8s, namespace=namespace)
    run("SECRET HARVEST — decoded credentials", harvest_secrets, k8s, namespace=namespace)

    return "\n".join(results)
