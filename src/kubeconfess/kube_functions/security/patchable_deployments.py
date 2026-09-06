from kubernetes import client
from kubernetes.client.rest import ApiException


def check_patchable_deployments(k8s_apps, k8s_auth, namespace: str = "all") -> str:
    try:
        if namespace == "all":
            deps = k8s_apps.list_deployment_for_all_namespaces()
        else:
            deps = k8s_apps.list_namespaced_deployment(namespace=namespace)

        if not deps.items:
            return f"No deployments found in: {namespace}"

        patchable = []

        for dep in deps.items:
            ns = dep.metadata.namespace
            name = dep.metadata.name

            try:
                review = k8s_auth.create_self_subject_access_review(
                    body=client.V1SelfSubjectAccessReview(
                        spec=client.V1SelfSubjectAccessReviewSpec(
                            resource_attributes=client.V1ResourceAttributes(
                                verb="patch",
                                resource="deployments",
                                namespace=ns,
                            )
                        )
                    )
                )
                allowed = review.status.allowed
            except ApiException:
                allowed = False

            if allowed:
                patchable.append(
                    {
                        "ns": ns,
                        "name": name,
                        "sa": dep.spec.template.spec.service_account_name or "default",
                        "replicas": dep.spec.replicas or 1,
                        "image": dep.spec.template.spec.containers[0].image,
                    }
                )

        if not patchable:
            return f"✓ No patchable deployments found — current identity cannot patch any of the {len(deps.items)} deployment(s) checked."

        lines = [f"⚠ Found {len(patchable)} patchable deployment(s) out of {len(deps.items)} total:\n"]

        for d in patchable:
            lines.append(f"  {d['ns']}/{d['name']}")
            lines.append(f"    SA:       {d['sa']}")
            lines.append(f"    Replicas: {d['replicas']}")
            lines.append(f"    Image:    {d['image']}")
            lines.append(f"    Command:  inject_deployment(deployment={d['name']}, namespace={d['ns']}, image=<your-image>)")
            lines.append("")

        return "\n".join(lines)

    except ApiException as e:
        if e.status == 403:
            return "✗ Deployment list access denied."
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "check_patchable_deployments",
        "description": (
            "List all deployments the current identity can patch. "
            "Checks patch permission per namespace using SelfSubjectAccessReview. "
            "Shows SA, replica count, current image, and the command to inject. "
            "Use this to find injection targets before calling inject_deployment."
        ),
        "parameters": {
            "type": "object",
            "properties": {"namespace": {"type": "string", "description": "Namespace to check, or 'all' for cluster-wide."}},
            "required": [],
        },
    },
}
