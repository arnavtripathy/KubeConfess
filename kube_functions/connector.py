from kubernetes import client, config

def connect(kubeconfig_path: str):
    config.load_kube_config(config_file=kubeconfig_path)
    return (
        client.CoreV1Api(),
        client.AppsV1Api(),
        client.AuthorizationV1Api(),
        client.RbacAuthorizationV1Api(),
    )