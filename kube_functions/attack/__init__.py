from kube_functions.attack.exec_pod import definition as exec_def
from kube_functions.attack.exec_pod import exec_pod
from kube_functions.attack.harvest_secrets import definition as harvest_def
from kube_functions.attack.harvest_secrets import harvest_secrets
from kube_functions.attack.steal_tokens import definition as token_def
from kube_functions.attack.steal_tokens import steal_tokens
from kube_functions.attack.inject_deployments import definition as inject_def
from kube_functions.attack.inject_deployments import inject_deployment

definitions = [token_def, harvest_def, exec_def, inject_def]


def dispatch(name: str, args: dict, k8s=None, k8s_apps=None) -> str | None:
    if name == "steal_tokens":
        return steal_tokens(k8s, **args)
    if name == "harvest_secrets":
        return harvest_secrets(k8s, **args)
    if name == "exec_pod":
        return exec_pod(k8s, **args)
    if name == "inject_deployment":
        return inject_deployment(k8s_apps, **args)
    return None
