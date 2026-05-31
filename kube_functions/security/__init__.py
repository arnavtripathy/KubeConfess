from kube_functions.security.privileged    import check_privileged_pods,  definition as privileged_def
from kube_functions.security.root_containers import check_root_containers, definition as root_def 

definitions = [privileged_def, root_def]  # ← add

def dispatch(name: str, args: dict, k8s=None, k8s_apps=None) -> str:
    if name == "check_privileged_pods":
        return check_privileged_pods(k8s,k8s_apps=k8s_apps, **args)
    if name == "check_root_containers":                         
        return check_root_containers(k8s, k8s_apps=k8s_apps, **args)
    return None