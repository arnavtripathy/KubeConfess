from kubernetes.client.rest import ApiException


def list_roles(k8s_rbac, namespace: str = "all") -> str:
    try:
        if namespace == "all":
            roles = k8s_rbac.list_role_for_all_namespaces()
        else:
            roles = k8s_rbac.list_namespaced_role(namespace=namespace)

        if not roles.items:
            return f"No roles found in: {namespace}"

        lines = [f"Found {len(roles.items)} role(s):\n"]
        for role in roles.items:
            rules_count = len(role.rules) if role.rules else 0
            lines.append(f"  {role.metadata.namespace}/{role.metadata.name} — {rules_count} rule(s)")

            for rule in (role.rules or []):
                verbs     = ", ".join(rule.verbs or [])
                resources = ", ".join(rule.resources or [])
                lines.append(f"    verbs: [{verbs}]  resources: [{resources}]")

        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "list_roles",
        "description": (
            "List Kubernetes Roles and their rules, optionally filtered by namespace. "
            "Shows each role's allowed verbs and resources. "
            "Use this to understand what permissions exist within a namespace."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "namespace": {
                    "type": "string",
                    "description": "Namespace to filter by, or 'all' for every namespace."
                }
            },
            "required": []
        }
    }
}