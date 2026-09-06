import base64

from kubernetes.client.rest import ApiException

SKIP_TYPES = [
    "kubernetes.io/dockerconfigjson",
    "kubernetes.io/dockercfg",
    "bootstrap.kubernetes.io/token",
]

INTERESTING_NAMES = [
    "prod",
    "production",
    "db",
    "database",
    "api",
    "admin",
    "root",
    "master",
    "credentials",
    "secret",
    "token",
    "aws",
    "gcp",
    "azure",
    "github",
    "stripe",
    "key",
    "password",
    "auth",
    "access",
    "private",
    "cert",
    "tls",
    "ssl",
    "vault",
    "deploy",
    "ci",
    "cd",
]

INTERESTING_KEYS = [
    "password",
    "passwd",
    "secret",
    "token",
    "key",
    "api",
    "credential",
    "auth",
    "private",
    "access",
    "database",
    "db",
    "url",
    "connection",
    "dsn",
    "jwt",
    "bearer",
    "aws",
    "gcp",
    "azure",
    "github",
    "gitlab",
    "stripe",
    "sendgrid",
    "twilio",
    "slack",
    "webhook",
]


def _is_interesting_secret(name: str) -> bool:
    return any(p in name.lower() for p in INTERESTING_NAMES)


def _is_interesting_key(key: str) -> bool:
    return any(p in key.lower() for p in INTERESTING_KEYS)


def _decode(encoded: str) -> str:
    try:
        return base64.b64decode(encoded).decode("utf-8", errors="replace")
    except Exception:
        return "[decode error]"


def harvest_secrets(k8s, namespace: str = "all") -> str:
    try:
        if namespace == "all":
            secret_list = k8s.list_secret_for_all_namespaces()
        else:
            secret_list = k8s.list_namespaced_secret(namespace=namespace)

    except ApiException as e:
        if e.status == 403:
            return "✗ Secret read access denied — cannot harvest secrets."
        return f"Kubernetes API error: {e.status} {e.reason}"

    interesting = []
    boring = []

    for secret in secret_list.items:
        if secret.type in SKIP_TYPES:
            continue
        if not secret.data:
            continue
        if _is_interesting_secret(secret.metadata.name):
            interesting.append(secret)
        else:
            boring.append(secret)

    total = len(interesting) + len(boring)

    if total == 0:
        return "No secrets found.\nNote: SA tokens are handled by steal_tokens. Docker pull secrets and bootstrap tokens are skipped."

    lines = [f"Found {total} secret(s) — {len(interesting)} high priority, {len(boring)} low priority.\n"]

    # ── High priority ─────────────────────────────────────────────────────────
    if interesting:
        lines.append(f"{'═' * 55}")
        lines.append(f"  HIGH PRIORITY ({len(interesting)})")
        lines.append(f"{'═' * 55}\n")

        for secret in interesting:
            ns = secret.metadata.namespace
            name = secret.metadata.name
            stype = secret.type or "Opaque"

            lines.append(f"  ⚠ {ns}/{name} ({stype})")
            for key, val in secret.data.items():
                decoded = _decode(val)
                marker = " ◄ INTERESTING" if _is_interesting_key(key) else ""
                lines.append(f"    {key}: {decoded}{marker}")
            lines.append("")

    # ── Low priority ──────────────────────────────────────────────────────────
    if boring:
        lines.append(f"{'─' * 55}")
        lines.append(f"  OTHER SECRETS ({len(boring)})")
        lines.append(f"{'─' * 55}\n")

        for secret in boring:
            ns = secret.metadata.namespace
            name = secret.metadata.name
            stype = secret.type or "Opaque"

            interesting_keys = {k: _decode(v) for k, v in secret.data.items() if _is_interesting_key(k)}

            if interesting_keys:
                lines.append(f"  ~ {ns}/{name} ({stype})")
                for key, val in interesting_keys.items():
                    lines.append(f"    {key}: {val} ◄ INTERESTING")
                lines.append("")
            else:
                keys = ", ".join(secret.data.keys())
                lines.append(f"  - {ns}/{name} — keys: [{keys}]")

    lines.append(
        "\nFix: use external secret managers (Vault, AWS Secrets Manager). "
        "Enable etcd encryption at rest. "
        "Avoid storing credentials as Kubernetes secrets where possible."
    )

    return "\n".join(lines)


definition = {
    "type": "function",
    "function": {
        "name": "harvest_secrets",
        "description": (
            "Decode and dump Kubernetes secret values. "
            "Unlike list_secrets which only shows key names, "
            "this decodes base64 and shows actual values — "
            "passwords, connection strings, API keys, tokens. "
            "Prioritises secrets with interesting names (prod, db, api, aws) "
            "and flags interesting keys (password, token, key, credential). "
            "SA tokens are skipped — use steal_tokens for those. "
            "Only call if list_permissions confirmed secret read access."
        ),
        "parameters": {
            "type": "object",
            "properties": {"namespace": {"type": "string", "description": "Namespace to harvest from, or 'all' for cluster-wide."}},
            "required": [],
        },
    },
}
