from kubeconfess.kube_functions.list.clusterrolebindings import definition as crb_def
from kubeconfess.kube_functions.list.clusterrolebindings import list_clusterrolebindings  # ← add
from kubeconfess.kube_functions.list.clusterroles import definition as clusterroles_def
from kubeconfess.kube_functions.list.clusterroles import list_clusterroles
from kubeconfess.kube_functions.list.deployments import definition as deployments_def
from kubeconfess.kube_functions.list.deployments import list_deployments
from kubeconfess.kube_functions.list.namespaces import definition as namespaces_def
from kubeconfess.kube_functions.list.namespaces import list_namespaces
from kubeconfess.kube_functions.list.permissions import definition as permissions_def
from kubeconfess.kube_functions.list.permissions import list_permissions
from kubeconfess.kube_functions.list.pods import definition as pods_def
from kubeconfess.kube_functions.list.pods import list_pods
from kubeconfess.kube_functions.list.rolebindings import definition as rolebindings_def
from kubeconfess.kube_functions.list.rolebindings import list_rolebindings
from kubeconfess.kube_functions.list.roles import definition as roles_def
from kubeconfess.kube_functions.list.roles import list_roles
from kubeconfess.kube_functions.list.secrets import definition as secrets_def
from kubeconfess.kube_functions.list.secrets import list_secrets
from kubeconfess.kube_functions.list.serviceaccounts import definition as sa_def
from kubeconfess.kube_functions.list.serviceaccounts import list_serviceaccounts
from kubeconfess.kube_functions.list.services import definition as services_def
from kubeconfess.kube_functions.list.services import list_services

definitions = [
    pods_def,
    deployments_def,
    namespaces_def,
    services_def,
    permissions_def,
    roles_def,
    clusterroles_def,
    secrets_def,
    sa_def,
    rolebindings_def,
    crb_def,
]


def dispatch(name: str, args: dict, k8s=None, k8s_apps=None, k8s_auth=None, k8s_rbac=None) -> str | None:
    if name == "list_pods":
        return list_pods(k8s, k8s_rbac=k8s_rbac, **args)
    if name == "list_deployments":
        return list_deployments(k8s_apps, k8s=k8s, k8s_rbac=k8s_rbac, **args)
    if name == "list_namespaces":
        return list_namespaces(k8s)
    if name == "list_services":
        return list_services(k8s, **args)
    if name == "list_permissions":
        return list_permissions(k8s_auth, k8s, **args)
    if name == "list_roles":
        return list_roles(k8s_rbac, **args)
    if name == "list_clusterroles":
        return list_clusterroles(k8s_rbac, **args)
    if name == "list_secrets":
        return list_secrets(k8s, k8s_apps=k8s_apps, **args)
    if name == "list_serviceaccounts":
        return list_serviceaccounts(k8s, k8s_rbac, **args)
    if name == "list_rolebindings":
        return list_rolebindings(k8s_rbac, **args)
    if name == "list_clusterrolebindings":
        return list_clusterrolebindings(k8s_rbac)
    return None
