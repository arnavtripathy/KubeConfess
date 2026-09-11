"""Tests for the agent loop's tool-dispatch error handling.

These drive ``agent.send()`` for real: the OpenAI client is faked to emit one
tool call and then stop, ``dispatch`` is faked to fail in a particular way, and
we assert on the ``tool`` message the loop feeds back to the model.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from kubernetes.client.rest import ApiException

from kubeconfess import agent


def _fake_client(tool_name="list_pods", arguments="{}"):
    """A client that returns one tool call, then a plain stop response."""
    tool_call = SimpleNamespace(id="call_1", function=SimpleNamespace(name=tool_name, arguments=arguments))
    tool_turn = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=[tool_call], content=None), finish_reason="tool_calls")]
    )
    stop_turn = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=None, content="done"), finish_reason="stop")])
    client = MagicMock()
    client.chat.completions.create.side_effect = [tool_turn, stop_turn]
    return client


def _run(client, dispatch_side_effect=None):
    """Run send() with fakes and return the content of the tool message."""
    messages = []
    ctx = MagicMock()
    with patch.object(agent, "client", client):
        if dispatch_side_effect is not None:
            with patch.object(agent, "dispatch", side_effect=dispatch_side_effect):
                agent.send(messages, k8s=ctx, k8s_apps=ctx, k8s_auth=ctx, k8s_rbac=ctx)
        else:
            agent.send(messages, k8s=ctx, k8s_apps=ctx, k8s_auth=ctx, k8s_rbac=ctx)

    tool_messages = [m for m in messages if isinstance(m, dict) and m.get("role") == "tool"]
    assert len(tool_messages) == 1
    return tool_messages[0]["content"]


def test_malformed_json_arguments_reported():
    content = _run(_fake_client(arguments="{not valid json"))
    assert content.startswith("Error: Could not parse tool arguments for list_pods:")


def test_api_exception_reported():
    content = _run(_fake_client(), dispatch_side_effect=ApiException(status=403, reason="Forbidden"))
    assert content == "Kubernetes API error calling list_pods: 403 Forbidden"


def test_argument_error_reported():
    content = _run(_fake_client(), dispatch_side_effect=ValueError("bad namespace"))
    assert content == "Invalid argument to list_pods: ValueError: bad namespace"


def test_os_error_reported():
    content = _run(_fake_client(), dispatch_side_effect=OSError("Permission denied"))
    assert content == "File/permission error in list_pods: Permission denied"


def test_unexpected_error_reported():
    content = _run(_fake_client(), dispatch_side_effect=RuntimeError("boom"))
    assert content == "Unexpected error in list_pods: RuntimeError: boom"


# ── happy path ────────────────────────────────────────────────────────────────


def test_send_happy_path_runs_real_dispatch():
    """End-to-end: only the OpenAI client and the k8s API are faked. The real
    dispatch routes the tool call to the real list_pods, and its formatted
    output is fed back to the model as the tool result."""
    pod = SimpleNamespace(
        metadata=SimpleNamespace(namespace="default", name="web-1"),
        status=SimpleNamespace(phase="Running"),
        spec=SimpleNamespace(node_name="node-1", service_account_name="default"),
    )
    k8s = MagicMock()
    k8s.list_pod_for_all_namespaces.return_value = SimpleNamespace(items=[pod])

    observed = []
    messages = []
    with patch.object(agent, "client", _fake_client(tool_name="list_pods", arguments="{}")):
        content = agent.send(
            messages,
            k8s=k8s,
            k8s_apps=MagicMock(),
            k8s_auth=MagicMock(),
            k8s_rbac=MagicMock(),
            on_tool_call=lambda name, args: observed.append((name, args)),
        )

    # real list_pods ran against the faked API
    k8s.list_pod_for_all_namespaces.assert_called_once_with()
    assert observed == [("list_pods", {})]

    tool_result = next(m for m in messages if isinstance(m, dict) and m.get("role") == "tool")
    assert tool_result["content"].startswith("Found 1 pod(s):")
    assert "default/web-1 — Running — node: node-1" in tool_result["content"]

    # loop consumed the tool result and returned the model's final answer
    assert content == "done"
