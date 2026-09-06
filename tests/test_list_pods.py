from types import SimpleNamespace
from unittest.mock import MagicMock

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
