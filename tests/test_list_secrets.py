from types import SimpleNamespace
from unittest.mock import MagicMock

from kubernetes.client.rest import ApiException

from kubeconfess.kube_functions.list.secrets import list_secrets


def test_list_secrets_403_forbidden():
    k8s = MagicMock()
    k8s.list_secret_for_all_namespaces.side_effect = ApiException(status=403, reason="Forbidden")

    result = list_secrets(k8s, k8s_apps=MagicMock())

    assert result == "Kubernetes API error: 403 Forbidden"


def test_list_secrets_500_server_error():
    k8s = MagicMock()
    k8s.list_secret_for_all_namespaces.side_effect = ApiException(status=500, reason="Internal Server Error")

    result = list_secrets(k8s, k8s_apps=MagicMock())

    assert result == "Kubernetes API error: 500 Internal Server Error"


def test_list_secrets_404_reports_missing_target():
    k8s = MagicMock()
    k8s.list_namespaced_secret.side_effect = ApiException(status=404, reason="Not Found")

    result = list_secrets(k8s, k8s_apps=MagicMock(), namespace="ghost")

    assert result == "'ghost' not found in namespace 'ghost'."


def test_list_secrets_happy_path_lists_keys_and_hides_system():
    """Only the k8s API is faked; real filtering and formatting run — one
    application secret is listed while a system SA-token secret is hidden."""
    app_secret = SimpleNamespace(
        type="Opaque",
        data={"username": "abc", "password": "def"},
        metadata=SimpleNamespace(name="app-creds", namespace="payments"),
    )
    system_secret = SimpleNamespace(
        type="kubernetes.io/service-account-token",
        data={"token": "xyz"},
        metadata=SimpleNamespace(name="default-token", namespace="payments"),
    )
    k8s = MagicMock()
    k8s.list_namespaced_secret.return_value = SimpleNamespace(items=[app_secret, system_secret])

    result = list_secrets(k8s, k8s_apps=MagicMock(), namespace="payments")

    k8s.list_namespaced_secret.assert_called_once_with(namespace="payments")
    assert result.startswith("Found 1 secret(s) in payments:")
    assert "payments/app-creds" in result
    assert "keys: username, password" in result
    assert "[1 system secret(s) hidden — use include_system=true to show]" in result
