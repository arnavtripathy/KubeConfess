from kube_functions.security.hostpath_mounts import check_hostpath_mounts
from kube_functions.security.hostpath_mounts import definition as hostpath_def
from kube_functions.security.pod_self_scan import definition as self_scan_def
from kube_functions.security.pod_self_scan import scan_current_pod
from kube_functions.security.privileged import check_privileged_pods
from kube_functions.security.privileged import definition as privileged_def
from kube_functions.security.root_containers import check_root_containers
from kube_functions.security.root_containers import definition as root_def
from kube_functions.security.patchable_deployments import definition as patchable_def
from kube_functions.security.patchable_deployments import check_patchable_deployments

definitions = [privileged_def, root_def, hostpath_def, self_scan_def, patchable_def]


def dispatch(name: str, args: dict, k8s=None, k8s_apps=None, k8s_auth=None) -> str | None:
    if name == "check_privileged_pods":
        return check_privileged_pods(k8s, k8s_apps, **args)
    if name == "check_root_containers":
        return check_root_containers(k8s, k8s_apps=k8s_apps, **args)
    if name == "check_hostpath_mounts":
        return check_hostpath_mounts(k8s, k8s_apps=k8s_apps, **args)
    if name == "check_patchable_deployments":
        return check_patchable_deployments(k8s_apps, k8s_auth=k8s_auth, **args)
    if name == "scan_current_pod":
        return scan_current_pod()
    return None
