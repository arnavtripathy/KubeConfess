from kube_functions.list.pods import list_pods, definition as pods_def
from kube_functions.list.deployments import list_deployments, definition as deployments_def

definitions = [pods_def, deployments_def]

def dispatch(name: str, args: dict, k8s=None, k8s_apps=None) -> str:
    if name == "list_pods":
        return list_pods(k8s, **args)
    if name == "list_deployments":                        
        return list_deployments(k8s_apps, **args)         
    return None