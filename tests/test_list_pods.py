from types import SimpleNamespace
from unittest.mock import MagicMock

from kubernetes.client.rest import ApiException

from kubeconfess.kube_functions.list.pods import list_pods


def _make_pod(namespace, name, phase="Running", node="node-1", service_account="default"):
    return SimpleNamespace(
        metadata=SimpleNamespace(namespace=namespace, name=name),
        status=SimpleNamespace(phase=phase),
        spec=SimpleNamespace(node_name=node, service_account_name=service_account),
    )


def test_list_pods_no_pods_found():
    k8s = MagicMock()
    k8s.list_pod_for_all_namespaces.return_value = SimpleNamespace(items=[])

    result = list_pods(k8s)

    assert result == "No pods found in: all"


def test_list_pods_lists_namespace_and_name():
    k8s = MagicMock()
    k8s.list_namespaced_pod.return_value = SimpleNamespace(items=[_make_pod("payments", "api-abc123")])

    result = list_pods(k8s, namespace="payments")

    k8s.list_namespaced_pod.assert_called_once_with(namespace="payments")
    assert "payments/api-abc123" in result
    assert "serviceAccount: default" in result


def test_list_pods_403_forbidden():
    k8s = MagicMock()
    k8s.list_pod_for_all_namespaces.side_effect = ApiException(status=403, reason="Forbidden")

    result = list_pods(k8s)

    assert result == "Kubernetes API error: 403 Forbidden"


def test_list_pods_404_not_found():
    k8s = MagicMock()
    k8s.list_namespaced_pod.side_effect = ApiException(status=404, reason="Not Found")

    result = list_pods(k8s, namespace="nonexistent")

    assert result == "Kubernetes API error: 404 Not Found"


def test_list_pods_500_server_error():
    k8s = MagicMock()
    k8s.list_pod_for_all_namespaces.side_effect = ApiException(status=500, reason="Internal Server Error")

    result = list_pods(k8s)

    assert result == "Kubernetes API error: 500 Internal Server Error"
