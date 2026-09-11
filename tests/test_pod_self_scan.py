from unittest.mock import MagicMock, patch

import requests

from kubeconfess.kube_functions.security.pod_self_scan import (
    _get_capabilities,
    _get_identity,
    _get_mounts,
    _get_pid_namespace,
    _get_runtime_sockets,
    _get_sensitive_files,
    _probe_metadata,
)

PATH = "kubeconfess.kube_functions.security.pod_self_scan.Path"
REQUESTS_GET = "kubeconfess.kube_functions.security.pod_self_scan.requests.get"
# os.getuid() is POSIX-only; create=True lets us patch it on Windows too so the
# identity tests run cross-platform.
GETUID = "kubeconfess.kube_functions.security.pod_self_scan.os.getuid"

# ── _get_mounts ───────────────────────────────────────────────────────────────


def test_get_mounts_file_not_found():
    with patch(PATH) as mock_path:
        mock_path.return_value.read_text.side_effect = FileNotFoundError()
        result = _get_mounts()

    assert result == {"suspicious": [], "error": "/proc/mounts not found (not a Linux host?)"}


def test_get_mounts_permission_denied():
    with patch(PATH) as mock_path:
        mock_path.return_value.read_text.side_effect = PermissionError("Permission denied")
        result = _get_mounts()

    assert result["suspicious"] == []
    assert result["error"] == "could not read /proc/mounts: Permission denied"


# ── _get_capabilities ─────────────────────────────────────────────────────────


def test_get_capabilities_file_not_found():
    with patch(PATH) as mock_path:
        mock_path.return_value.read_text.side_effect = FileNotFoundError()
        result = _get_capabilities()

    assert result == {"error": "/proc/self/status not found (not a Linux host?)"}


def test_get_capabilities_malformed_capeff():
    with patch(PATH) as mock_path:
        mock_path.return_value.read_text.return_value = "CapEff: not_hex_value\n"
        result = _get_capabilities()

    assert result["error"].startswith("could not parse CapEff line:")


def test_get_capabilities_missing_capeff_line():
    with patch(PATH) as mock_path:
        mock_path.return_value.read_text.return_value = "Name: test\nState: S\n"
        result = _get_capabilities()

    assert result == {"error": "CapEff line not found in /proc/self/status"}


# ── _get_pid_namespace ────────────────────────────────────────────────────────


def test_get_pid_namespace_permission_error():
    with patch(PATH) as mock_path:
        mock_path.return_value.glob.side_effect = PermissionError("Permission denied")
        result = _get_pid_namespace()

    assert result == {"error": "could not enumerate /proc: Permission denied"}


# ── _get_runtime_sockets ──────────────────────────────────────────────────────


def test_get_runtime_sockets_stat_error():
    with patch(PATH) as mock_path:
        mock_path.return_value.exists.side_effect = OSError("Permission denied")
        result = _get_runtime_sockets()

    assert result["sockets"] == []
    # every configured socket path failed to stat
    assert result["errors"]
    assert all(msg == "could not stat: Permission denied" for msg in result["errors"].values())


# ── _get_sensitive_files ──────────────────────────────────────────────────────


def test_get_sensitive_files_partial_failure():
    with patch(PATH) as mock_path:

        def side_effect(path):
            m = MagicMock()
            if "aws" in path:
                m.exists.side_effect = OSError("Permission denied")
            else:
                m.exists.return_value = False
            return m

        mock_path.side_effect = side_effect
        result = _get_sensitive_files()

    assert result["files"] == []
    assert result["errors"]["/root/.aws/credentials"] == "could not stat: Permission denied"


# ── _probe_metadata ───────────────────────────────────────────────────────────


def test_probe_metadata_connection_error():
    with patch(REQUESTS_GET, side_effect=requests.exceptions.ConnectionError("refused")):
        result = _probe_metadata()

    assert result == {
        "aws": {"reachable": False},
        "gcp": {"reachable": False},
        "azure": {"reachable": False},
    }


def test_probe_metadata_timeout():
    with patch(REQUESTS_GET, side_effect=requests.exceptions.Timeout("slow")):
        result = _probe_metadata()

    assert result == {
        "aws": {"reachable": False, "note": "timeout"},
        "gcp": {"reachable": False, "note": "timeout"},
        "azure": {"reachable": False, "note": "timeout"},
    }


# ── _get_identity ─────────────────────────────────────────────────────────────


def test_get_identity_token_read_permission_error():
    with patch(GETUID, create=True, return_value=1000), patch(PATH) as mock_path:

        def side_effect(path):
            m = MagicMock()
            if "namespace" in path:
                m.read_text.return_value.strip.return_value = "default"
            elif "token" in path:
                m.read_text.side_effect = PermissionError("Permission denied")
            return m

        mock_path.side_effect = side_effect
        result = _get_identity()

    assert result["token_present"] is False
    assert result["token_error"] == ("could not read /var/run/secrets/kubernetes.io/serviceaccount/token: Permission denied")
