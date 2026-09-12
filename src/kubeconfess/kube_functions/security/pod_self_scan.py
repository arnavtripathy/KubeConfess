import base64
import json
import os
import socket
from pathlib import Path

import requests

SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
SA_NS_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

SENSITIVE_ENV_PATTERNS = [
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "APIKEY",
    "PRIVATE_KEY",
    "CREDENTIALS",
    "AUTH",
    "DATABASE_URL",
    "DB_URL",
    "AWS_",
    "GCP_",
    "AZURE_",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "BEARER",
]

SENSITIVE_FILES = [
    "/root/.aws/credentials",
    "/root/.kube/config",
    "/root/.ssh/id_rsa",
    "/etc/boto.cfg",
]

SENSITIVE_DIRS = [
    "/vault/secrets",
    "/run/secrets",
    "/etc/secrets",
]

RUNTIME_SOCKETS = [
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/cri-dockerd.sock",
]

METADATA_ENDPOINTS = {
    "aws": ("http://169.254.169.254/latest/meta-data/", {}),
    "gcp": ("http://metadata.google.internal/computeMetadata/v1/", {"Metadata-Flavor": "Google"}),
    "azure": ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", {"Metadata": "true"}),
}


def _get_identity() -> dict:
    result = {
        "uid": os.getuid(),
        "is_root": os.getuid() == 0,
        "hostname": socket.gethostname(),
    }
    try:
        result["namespace"] = Path(SA_NS_PATH).read_text().strip()
    except FileNotFoundError:
        result["namespace"] = "unknown"
    except OSError as e:
        result["namespace"] = "unknown"
        result["namespace_error"] = f"could not read {SA_NS_PATH}: {e}"

    try:
        token = Path(SA_TOKEN_PATH).read_text().strip()
    except FileNotFoundError:
        result["token_present"] = False
        return result
    except OSError as e:
        result["token_present"] = False
        result["token_error"] = f"could not read {SA_TOKEN_PATH}: {e}"
        return result

    result["token_present"] = True
    parts = token.split(".")
    if len(parts) != 3:
        result["token_error"] = "malformed service account token (expected a 3-part JWT)"
        return result

    try:
        payload = json.loads(base64.b64decode(parts[1] + "==").decode("utf-8", errors="replace"))
    except (ValueError, TypeError) as e:
        result["token_error"] = f"could not decode token payload: {e}"
        return result

    k8s = payload.get("kubernetes.io", {})
    result["serviceaccount"] = k8s.get("serviceaccount", {}).get("name", "unknown")
    result["pod_name"] = k8s.get("pod", {}).get("name", "unknown")
    result["node_name"] = k8s.get("node", {}).get("name", "unknown")
    result["token_expiry"] = payload.get("exp", "no expiry — static token ⚠")
    return result


def _get_capabilities() -> dict:
    try:
        status_text = Path("/proc/self/status").read_text()
    except FileNotFoundError:
        return {"error": "/proc/self/status not found (not a Linux host?)"}
    except OSError as e:
        return {"error": f"could not read /proc/self/status: {e}"}

    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            try:
                cap_hex = int(line.split(":")[1].strip(), 16)
            except (IndexError, ValueError) as e:
                return {"error": f"could not parse CapEff line: {e}"}
            return {
                "CapEff": hex(cap_hex),
                "is_privileged": cap_hex >= 0x0000003FFFFFFFFF,
                "has_CAP_SYS_ADMIN": bool(cap_hex & (1 << 21)),
                "has_CAP_NET_ADMIN": bool(cap_hex & (1 << 12)),
                "has_CAP_SYS_PTRACE": bool(cap_hex & (1 << 19)),
            }
    return {"error": "CapEff line not found in /proc/self/status"}


def _get_mounts() -> dict:
    try:
        lines = Path("/proc/mounts").read_text().splitlines()
    except FileNotFoundError:
        return {"suspicious": [], "error": "/proc/mounts not found (not a Linux host?)"}
    except OSError as e:
        return {"suspicious": [], "error": f"could not read /proc/mounts: {e}"}

    suspicious = []
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        mp = parts[1]
        if any(
            mp.startswith(p)
            for p in [
                "/host",
                "/rootfs",
                "/proc/host",
                "/etc/kubernetes",
                "/var/lib/kubelet",
                "/var/lib/docker",
                "/var/run/docker",
            ]
        ):
            suspicious.append(mp)
    return {"suspicious": suspicious, "error": None}


def _get_pid_namespace() -> dict:
    try:
        pids = len(list(Path("/proc").glob("[0-9]*")))
    except OSError as e:
        return {"error": f"could not enumerate /proc: {e}"}
    return {"visible_processes": pids, "likely_host_pid": pids > 50}


def _get_runtime_sockets() -> dict:
    found = []
    errors = {}
    for s in RUNTIME_SOCKETS:
        try:
            if Path(s).exists():
                found.append(s)
        except OSError as e:
            errors[s] = f"could not stat: {e}"
    return {"sockets": found, "errors": errors}


def _get_env_secrets() -> list:
    findings = []
    for key, val in os.environ.items():
        for pattern in SENSITIVE_ENV_PATTERNS:
            if pattern in key.upper():
                findings.append({"key": key, "value": val})
                break
    return findings


def _get_sensitive_files() -> dict:
    found = []
    errors = {}

    for path_str in SENSITIVE_FILES:
        p = Path(path_str)
        try:
            is_file = p.exists() and p.is_file()
        except OSError as e:
            errors[path_str] = f"could not stat: {e}"
            continue
        if not is_file:
            continue
        try:
            found.append({"path": path_str, "content": p.read_text(errors="replace")[:500]})
        except OSError as e:
            found.append({"path": path_str, "content": "[unreadable]"})
            errors[path_str] = str(e)

    for dir_str in SENSITIVE_DIRS:
        d = Path(dir_str)
        try:
            is_dir = d.exists() and d.is_dir()
        except OSError as e:
            errors[dir_str] = f"could not stat: {e}"
            continue
        if not is_dir:
            continue
        try:
            entries = list(d.rglob("*"))
        except OSError as e:
            errors[dir_str] = f"could not walk directory: {e}"
            continue
        for f in entries:
            try:
                if not f.is_file():
                    continue
            except OSError as e:
                errors[str(f)] = f"could not stat: {e}"
                continue
            try:
                found.append({"path": str(f), "content": f.read_text(errors="replace")[:500]})
            except OSError as e:
                found.append({"path": str(f), "content": "[unreadable]"})
                errors[str(f)] = str(e)

    return {"files": found, "errors": errors}


def _probe_metadata() -> dict:
    results = {}
    for cloud, (url, headers) in METADATA_ENDPOINTS.items():
        try:
            r = requests.get(url, headers=headers, timeout=2, allow_redirects=False)
            results[cloud] = {
                "reachable": True,
                "status": r.status_code,
                "preview": r.text[:200],
            }
        except requests.exceptions.ConnectionError:
            results[cloud] = {"reachable": False}
        except requests.exceptions.Timeout:
            results[cloud] = {"reachable": False, "note": "timeout"}
        except requests.exceptions.RequestException as e:
            results[cloud] = {"reachable": False, "error": str(e)}
    return results


def scan_current_pod() -> str:
    lines = ["=== CURRENT POD SELF-SCAN ===\n"]

    # ── Identity ──────────────────────────────────────────────────────────────
    identity = _get_identity()
    lines.append("IDENTITY:")
    lines.append(f"  hostname:   {identity.get('hostname', 'unknown')}")
    uid_str = "root ⚠" if identity.get("is_root") else f"uid={identity.get('uid')}"
    lines.append(f"  running as: {uid_str}")
    if identity.get("token_present"):
        lines.append(f"  namespace:      {identity.get('namespace', 'unknown')}")
        if identity.get("namespace_error"):
            lines.append(f"    ? {identity['namespace_error']}")
        lines.append(f"  serviceaccount: {identity.get('serviceaccount', 'unknown')}")
        lines.append(f"  pod:            {identity.get('pod_name', 'unknown')}")
        lines.append(f"  node:           {identity.get('node_name', 'unknown')}")
        lines.append(f"  token expiry:   {identity.get('token_expiry', 'unknown')}")
        if identity.get("token_error"):
            lines.append(f"  ? token could not be fully parsed — {identity['token_error']}")
    else:
        lines.append("  sa token: ✗ not mounted — no direct K8s API access")
        if identity.get("token_error"):
            lines.append(f"    ? {identity['token_error']}")
    lines.append("")

    # ── Capabilities ──────────────────────────────────────────────────────────
    caps = _get_capabilities()
    lines.append("CAPABILITIES:")
    if "error" in caps:
        lines.append(f"  ? could not determine — {caps['error']}")
    else:
        cap_findings = []
        if caps.get("is_privileged"):
            cap_findings.append("  ⚠ CRITICAL — privileged mode")
        if caps.get("has_CAP_SYS_ADMIN"):
            cap_findings.append("  ⚠ CRITICAL — CAP_SYS_ADMIN")
        if caps.get("has_CAP_NET_ADMIN"):
            cap_findings.append("  ⚠ HIGH     — CAP_NET_ADMIN")
        if caps.get("has_CAP_SYS_PTRACE"):
            cap_findings.append("  ⚠ HIGH     — CAP_SYS_PTRACE")
        if cap_findings:
            lines.extend(cap_findings)
        else:
            lines.append("  ✓ no dangerous capabilities")
        lines.append(f"  CapEff: {caps.get('CapEff', 'unknown')}")
    lines.append("")

    # ── Runtime sockets ───────────────────────────────────────────────────────
    socket_result = _get_runtime_sockets()
    sockets = socket_result["sockets"]
    lines.append("RUNTIME SOCKETS:")
    if sockets:
        for s in sockets:
            lines.append(f"  ⚠ CRITICAL — {s}")
    else:
        lines.append("  ✓ none found")
    for path, err in socket_result.get("errors", {}).items():
        lines.append(f"  ? could not check {path} — {err}")
    lines.append("")

    # ── Host mounts ───────────────────────────────────────────────────────────
    mount_result = _get_mounts()
    lines.append("SUSPICIOUS HOST MOUNTS:")
    if mount_result.get("error"):
        lines.append(f"  ? could not check — {mount_result['error']}")
    elif mount_result["suspicious"]:
        for m in mount_result["suspicious"]:
            lines.append(f"  ⚠ CRITICAL — {m}")
    else:
        lines.append("  ✓ none found")
    lines.append("")

    # ── PID namespace ─────────────────────────────────────────────────────────
    pid = _get_pid_namespace()
    lines.append("PID NAMESPACE:")
    if "error" in pid:
        lines.append(f"  ? could not check — {pid['error']}")
    elif pid.get("likely_host_pid"):
        lines.append(f"  ⚠ CRITICAL — {pid['visible_processes']} processes visible (likely host PID namespace)")
    else:
        lines.append(f"  ✓ {pid.get('visible_processes', '?')} processes (isolated)")
    lines.append("")

    # ── Cloud metadata ────────────────────────────────────────────────────────
    lines.append("CLOUD METADATA:")
    metadata = _probe_metadata()
    any_reachable = False
    for cloud, result in metadata.items():
        if result.get("reachable"):
            any_reachable = True
            lines.append(f"  ⚠ CRITICAL — {cloud} metadata reachable")
            lines.append(f"    {result.get('preview', '')[:100]}")
    if not any_reachable:
        lines.append("  ✓ no metadata endpoints reachable")
    lines.append("")

    # ── Env secrets ───────────────────────────────────────────────────────────
    env_secrets = _get_env_secrets()
    lines.append("SENSITIVE ENV VARS:")
    if env_secrets:
        for e in env_secrets:
            lines.append(f"  ⚠ HIGH — {e['key']} = {e['value']}")
    else:
        lines.append("  ✓ none found")
    lines.append("")

    # ── Sensitive files ───────────────────────────────────────────────────────
    sensitive_result = _get_sensitive_files()
    sensitive = sensitive_result["files"]
    lines.append("SENSITIVE FILES:")
    if sensitive:
        for f in sensitive:
            lines.append(f"  ⚠ HIGH — {f['path']}")
            lines.append(f"    {f['content'][:150]}")
    else:
        lines.append("  ✓ none found")
    for path, err in sensitive_result.get("errors", {}).items():
        lines.append(f"  ? could not check {path} — {err}")

    return "\n".join(lines)


definition = {
    "type": "function",
    "function": {
        "name": "scan_current_pod",
        "description": (
            "Scan the pod this agent is currently running in. "
            "Only useful in --incluster mode. "
            "Checks identity, capabilities, runtime sockets, host mounts, "
            "PID namespace, cloud metadata endpoints, sensitive env vars, "
            "and sensitive files. Always run this first when operating in-cluster."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
}
