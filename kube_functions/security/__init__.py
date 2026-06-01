from kube_functions.security.privileged      import check_privileged_pods,   definition as privileged_def
from kube_functions.security.root_containers import check_root_containers,    definition as root_def
from kube_functions.security.hostpath_mounts import check_hostpath_mounts,   definition as hostpath_def 

definitions = [privileged_def, root_def, hostpath_def]  

def dispatch(name: str, args: dict, k8s=None, k8s_apps=None) -> str:
    if name == "check_privileged_pods":
        return check_privileged_pods(k8s, k8s_apps, **args)
    if name == "check_root_containers":
        return check_root_containers(k8s, k8s_apps=k8s_apps, **args)
    if name == "check_hostpath_mounts":                               
        return check_hostpath_mounts(k8s, k8s_apps=k8s_apps, **args)  
    return None