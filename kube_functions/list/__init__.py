from kube_functions.list.pods import list_pods, definition as pods_def
from kube_functions.list.deployments import list_deployments, definition as deployments_def
from kube_functions.list.namespaces  import list_namespaces, definition as namespaces_def  
from kube_functions.list.services    import list_services, definition as services_def

definitions = [pods_def, deployments_def, namespaces_def, services_def]

def dispatch(name: str, args: dict, k8s=None, k8s_apps=None) -> str:
    if name == "list_pods":
        return list_pods(k8s, **args)
    if name == "list_deployments":                        
        return list_deployments(k8s_apps, **args)   
    if name == "list_namespaces":          
        return list_namespaces(k8s)    
    if name == "list_services":         
        return list_services(k8s, **args)
    return None