from kube_functions.list.pods import list_pods, definition as pods_def
from kube_functions.list.deployments import list_deployments, definition as deployments_def
from kube_functions.list.namespaces  import list_namespaces, definition as namespaces_def  
from kube_functions.list.services    import list_services, definition as services_def
from kube_functions.list.permissions import list_permissions, definition as permissions_def
from kube_functions.list.roles       import list_roles, definition as roles_def
from kube_functions.list.clusterroles import list_clusterroles, definition as clusterroles_def


definitions = [pods_def, deployments_def, namespaces_def, services_def, permissions_def, roles_def, clusterroles_def]

def dispatch(name: str, args: dict, k8s=None, k8s_apps=None, k8s_auth=None, k8s_rbac=None) -> str:
    if name == "list_pods":
        return list_pods(k8s, **args)
    if name == "list_deployments":                        
        return list_deployments(k8s_apps, **args)   
    if name == "list_namespaces":          
        return list_namespaces(k8s)    
    if name == "list_services":         
        return list_services(k8s, **args)
    if name == "list_permissions":
        return list_permissions(k8s_auth, **args)
    if name == "list_roles":          
        return list_roles(k8s_rbac, **args)       
    if name == "list_clusterroles":               
        return list_clusterroles(k8s_rbac, **args) 
    return None