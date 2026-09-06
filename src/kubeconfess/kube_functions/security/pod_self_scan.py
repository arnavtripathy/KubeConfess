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
        token = Path(SA_TOKEN_PATH).read_text().strip()
        result["token_present"] = True
        parts = token.split(".")
        if len(parts) == 3:
            payload = json.loads(base64.b64decode(parts[1] + "==").decode("utf-8", errors="replace"))
            k8s = payload.get("kubernetes.io", {})
            result["serviceaccount"] = k8s.get("serviceaccount", {}).get("name", "unknown")
            result["pod_name"] = k8s.get("pod", {}).get("name", "unknown")
            result["node_name"] = k8s.get("node", {}).get("name", "unknown")
            result["token_expiry"] = payload.get("exp", "no expiry — static token ⚠")
    except FileNotFoundError:
        result["token_present"] = False
    except Exception as e:
        result["error"] = str(e)
    return result


def _get_capabilities() -> dict:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                cap_hex = int(line.split(":")[1].strip(), 16)
                return {
                    "CapEff": hex(cap_hex),
                    "is_privileged": cap_hex >= 0x0000003FFFFFFFFF,
                    "has_CAP_SYS_ADMIN": bool(cap_hex & (1 << 21)),
                    "has_CAP_NET_ADMIN": bool(cap_hex & (1 << 12)),
                    "has_CAP_SYS_PTRACE": bool(cap_hex & (1 << 19)),
                }
    except Exception as e:
        return {"error": str(e)}
    return {}


def _get_mounts() -> list:
    suspicious = []
    try:
        for line in Path("/proc/mounts").read_text().splitlines():
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
    except Exception:
        pass
    return suspicious


def _get_pid_namespace() -> dict:
    try:
        pids = len(list(Path("/proc").glob("[0-9]*")))
        return {"visible_processes": pids, "likely_host_pid": pids > 50}
    except Exception as e:
        return {"error": str(e)}


def _get_runtime_sockets() -> list:
    return [s for s in RUNTIME_SOCKETS if Path(s).exists()]


def _get_env_secrets() -> list:
    findings = []
    for key, val in os.environ.items():
        for pattern in SENSITIVE_ENV_PATTERNS:
            if pattern in key.upper():
                findings.append({"key": key, "value": val})
                break
    return findings


def _get_sensitive_files() -> list:
    found = []
    for path_str in SENSITIVE_FILES:
        p = Path(path_str)
        if p.exists() and p.is_file():
            try:
                found.append({"path": path_str, "content": p.read_text(errors="replace")[:500]})
            except Exception:
                found.append({"path": path_str, "content": "[unreadable]"})
    for dir_str in SENSITIVE_DIRS:
        d = Path(dir_str)
        if d.exists() and d.is_dir():
            for f in d.rglob("*"):
                if f.is_file():
                    try:
                        found.append({"path": str(f), "content": f.read_text(errors="replace")[:500]})
                    except Exception:
                        found.append({"path": str(f), "content": "[unreadable]"})
    return found


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
        except Exception as e:
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
        lines.append(f"  serviceaccount: {identity.get('serviceaccount', 'unknown')}")
        lines.append(f"  pod:            {identity.get('pod_name', 'unknown')}")
        lines.append(f"  node:           {identity.get('node_name', 'unknown')}")
        lines.append(f"  token expiry:   {identity.get('token_expiry', 'unknown')}")
    else:
        lines.append("  sa token: ✗ not mounted — no direct K8s API access")
    lines.append("")

    # ── Capabilities ──────────────────────────────────────────────────────────
    caps = _get_capabilities()
    lines.append("CAPABILITIES:")
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
    sockets = _get_runtime_sockets()
    lines.append("RUNTIME SOCKETS:")
    if sockets:
        for s in sockets:
            lines.append(f"  ⚠ CRITICAL — {s}")
    else:
        lines.append("  ✓ none found")
    lines.append("")

    # ── Host mounts ───────────────────────────────────────────────────────────
    mounts = _get_mounts()
    lines.append("SUSPICIOUS HOST MOUNTS:")
    if mounts:
        for m in mounts:
            lines.append(f"  ⚠ CRITICAL — {m}")
    else:
        lines.append("  ✓ none found")
    lines.append("")

    # ── PID namespace ─────────────────────────────────────────────────────────
    pid = _get_pid_namespace()
    lines.append("PID NAMESPACE:")
    if pid.get("likely_host_pid"):
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
    sensitive = _get_sensitive_files()
    lines.append("SENSITIVE FILES:")
    if sensitive:
        for f in sensitive:
            lines.append(f"  ⚠ HIGH — {f['path']}")
            lines.append(f"    {f['content'][:150]}")
    else:
        lines.append("  ✓ none found")

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
