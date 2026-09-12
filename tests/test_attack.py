import base64
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from kubernetes.client.rest import ApiException

from kubeconfess.kube_functions.attack import exec_pod
from kubeconfess.kube_functions.attack.harvest_secrets import _decode, harvest_secrets
from kubeconfess.kube_functions.attack.steal_tokens import _decode_jwt, steal_tokens


def _jwt(payload: dict) -> str:
    """Build a 3-part JWT string with the given (unsigned) payload."""
    body = base64.b64encode(json.dumps(payload).encode()).decode()
    return f"header.{body}.signature"


def _sa_token_secret(token_b64: str, name="admin-token", namespace="kube-system", sa_name="admin-sa"):
    """A mock service-account-token secret whose data['token'] is token_b64."""
    return SimpleNamespace(
        type="kubernetes.io/service-account-token",
        data={"token": token_b64},
        metadata=SimpleNamespace(
            name=name,
            namespace=namespace,
            annotations={"kubernetes.io/service-account.name": sa_name},
        ),
    )


# ── harvest_secrets ─────────────────────────────────────────────────────────


def test_harvest_secrets_403_denied():
    k8s = MagicMock()
    k8s.list_secret_for_all_namespaces.side_effect = ApiException(status=403, reason="Forbidden")

    result = harvest_secrets(k8s)

    assert result == "✗ Secret read access denied — cannot harvest secrets."


def test_harvest_secrets_other_api_error():
    k8s = MagicMock()
    k8s.list_secret_for_all_namespaces.side_effect = ApiException(status=500, reason="Internal Server Error")

    result = harvest_secrets(k8s)

    assert result == "Kubernetes API error: 500 Internal Server Error"


def test_harvest_secrets_no_data():
    k8s = MagicMock()
    secret = MagicMock()
    secret.type = "Opaque"
    secret.data = None
    secret.metadata.name = "empty-secret"
    secret.metadata.namespace = "default"
    k8s.list_secret_for_all_namespaces.return_value = SimpleNamespace(items=[secret])

    result = harvest_secrets(k8s)

    assert result.startswith("No secrets found.")


def test_harvest_secrets_decodes_values_and_survives_bad_base64():
    secret = SimpleNamespace(
        type="Opaque",
        data={"password": base64.b64encode(b"hunter2").decode(), "broken": "A"},
        metadata=SimpleNamespace(name="prod-db", namespace="default"),
    )
    k8s = MagicMock()
    k8s.list_secret_for_all_namespaces.return_value = SimpleNamespace(items=[secret])

    result = harvest_secrets(k8s)

    assert "password: hunter2 ◄ INTERESTING" in result
    assert "broken: [decode error]" in result


def test_harvest_secrets_happy_path_full_report():
    """Only the k8s API is faked; the real scoring, base64 decode and report
    formatting run end to end over a mix of interesting and boring secrets."""
    interesting = SimpleNamespace(
        type="Opaque",
        data={"password": base64.b64encode(b"s3cr3t").decode()},
        metadata=SimpleNamespace(name="prod-db", namespace="payments"),
    )
    boring = SimpleNamespace(
        type="Opaque",
        data={"note": base64.b64encode(b"hello").decode()},
        metadata=SimpleNamespace(name="frontend-config", namespace="web"),
    )
    k8s = MagicMock()
    k8s.list_secret_for_all_namespaces.return_value = SimpleNamespace(items=[interesting, boring])

    result = harvest_secrets(k8s)

    assert result.startswith("Found 2 secret(s) — 1 high priority, 1 low priority.")
    assert "HIGH PRIORITY (1)" in result
    assert "⚠ payments/prod-db (Opaque)" in result
    assert "password: s3cr3t ◄ INTERESTING" in result
    assert "OTHER SECRETS (1)" in result
    assert "web/frontend-config — keys: [note]" in result


# ── steal_tokens ──────────────────────────────────────────────────────────────


def test_steal_tokens_403_denied():
    k8s = MagicMock()
    k8s.list_secret_for_all_namespaces.side_effect = ApiException(status=403, reason="Forbidden")

    result = steal_tokens(k8s)

    assert result == "✗ Secret read access denied — cannot perform token theft."


def test_steal_tokens_other_api_error():
    k8s = MagicMock()
    k8s.list_secret_for_all_namespaces.side_effect = ApiException(status=500, reason="Internal Server Error")

    result = steal_tokens(k8s)

    assert result == "Kubernetes API error: 500 Internal Server Error"


def test_steal_tokens_decodes_valid_token():
    token = _jwt({"kubernetes.io": {"namespace": "kube-system"}, "exp": 1735689600})
    secret = _sa_token_secret(base64.b64encode(token.encode()).decode())
    k8s = MagicMock()
    k8s.list_secret_for_all_namespaces.return_value = SimpleNamespace(items=[secret])

    result = steal_tokens(k8s)

    assert "kube-system/admin-token — HIGH VALUE" in result
    assert "ServiceAccount: admin-sa" in result
    assert "Expiry:         1735689600" in result


def test_steal_tokens_undecodable_token():
    # "A" is a single base64 data character, which b64decode rejects — the
    # narrowed `except (ValueError, TypeError)` must catch it, not crash.
    secret = _sa_token_secret("A")
    k8s = MagicMock()
    k8s.list_secret_for_all_namespaces.return_value = SimpleNamespace(items=[secret])

    result = steal_tokens(k8s)

    assert "Token: [could not decode]" in result


# ── exec_pod ──────────────────────────────────────────────────────────────────


def test_exec_pod_404_not_found():
    k8s = MagicMock()
    with patch.object(exec_pod, "stream") as mock_stream:
        mock_stream.side_effect = ApiException(status=404, reason="Not Found")
        result = exec_pod.exec_pod(k8s, "ghost", "default", "id")

    assert result == "✗ Pod default/ghost not found."


def test_exec_pod_403_denied():
    k8s = MagicMock()
    with patch.object(exec_pod, "stream") as mock_stream:
        mock_stream.side_effect = ApiException(status=403, reason="Forbidden")
        result = exec_pod.exec_pod(k8s, "web", "default", "id")

    assert result == "✗ Exec denied on default/web\n  SA lacks create pods/exec permission."


def test_exec_pod_other_api_error():
    k8s = MagicMock()
    with patch.object(exec_pod, "stream") as mock_stream:
        mock_stream.side_effect = ApiException(status=500, reason="Internal Server Error")
        result = exec_pod.exec_pod(k8s, "web", "default", "id")

    assert result == "Kubernetes API error: 500 Internal Server Error"


def test_exec_pod_invalid_command():
    # An unbalanced quote makes shlex.split() raise ValueError before stream()
    # is ever called.
    result = exec_pod.exec_pod(MagicMock(), "web", "default", "echo 'unterminated")

    assert result.startswith('✗ Invalid command "echo \'unterminated":')


def test_exec_pod_connection_error():
    k8s = MagicMock()
    with patch.object(exec_pod, "stream") as mock_stream:
        mock_stream.side_effect = OSError("Connection refused")
        result = exec_pod.exec_pod(k8s, "web", "default", "id")

    assert result == "✗ Exec connection error on default/web: Connection refused"


def test_exec_pod_success():
    k8s = MagicMock()
    with patch.object(exec_pod, "stream") as mock_stream:
        mock_stream.return_value = "uid=0(root)"
        result = exec_pod.exec_pod(k8s, "web", "default", "id")

    assert result == "default/web $ id\nuid=0(root)"


# ── decode helpers ────────────────────────────────────────────────────────────


def test_decode_valid_base64():
    encoded = base64.b64encode(b"test_data").decode()

    assert _decode(encoded) == "test_data"


def test_decode_malformed_base64():
    assert _decode("!!!not_base64!!!") == "[decode error]"


def test_decode_non_string_value():
    # A non-str/bytes value raises TypeError inside b64decode; the narrowed
    # except must turn it into the sentinel rather than propagating.
    assert _decode(None) == "[decode error]"  # type: ignore[arg-type]


def test_decode_jwt_wrong_part_count():
    assert _decode_jwt("not.enough.parts.and.more") == {}


def test_decode_jwt_empty():
    assert _decode_jwt("") == {}


def test_decode_jwt_invalid_base64_payload():
    assert _decode_jwt("header.!!!invalid!!!.signature") == {}


def test_decode_jwt_payload_not_an_object():
    # Payload decodes and is valid JSON, but it's a bare int rather than an
    # object — payload.get(...) would raise AttributeError, which the narrowed
    # except must swallow into {}.
    body = base64.b64encode(b"123").decode()
    assert _decode_jwt(f"header.{body}.signature") == {}


def test_decode_jwt_valid_token():
    token = _jwt({"kubernetes.io": {"serviceaccount": {"name": "deployer"}, "namespace": "ci"}, "exp": 42})

    assert _decode_jwt(token) == {"serviceaccount": "deployer", "namespace": "ci", "expiry": 42}
