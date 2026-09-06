from kubernetes import client, config


def connect(kubeconfig_path: str = None, incluster: bool = False):
    if incluster:  # For incluster, just need to call this function to load the incluster config.
        config.load_incluster_config()
    else:
        config.load_kube_config(config_file=kubeconfig_path)

    return (
        client.CoreV1Api(),
        client.AppsV1Api(),
        client.AuthorizationV1Api(),
        client.RbacAuthorizationV1Api(),
    )
