from kube_functions.security.privileged import check_privileged_pods, definition as privileged_def

definitions = [privileged_def]

def dispatch(name: str, args: dict, k8s=None, k8s_apps=None) -> str:
    if name == "check_privileged_pods":
        return check_privileged_pods(k8s, **args)
    return None