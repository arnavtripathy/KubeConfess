<div align="center">

<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/f48c72fc-67d8-4161-a83e-14697f3f7f74" />


**Make your cluster confess its vulnerabilities raher than running multiple tools. A conversational AI agent for Kubernetes — inspect and audit your cluster in plain English.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.24+-326CE5?style=flat-square&logo=kubernetes)](https://kubernetes.io)
[![AI Agnostic](https://img.shields.io/badge/AI-Agnostic-purple?style=flat-square)](https://github.com/arnavtripathy/KubeConfess)

</div>

---

## What is KubeConfess?

KubeConfess is a CLI AI agent that lets you interrogate your Kubernetes cluster in plain English. No more memorising `kubectl` flags and output formats — just describe what you want, and the agent figures out which API calls to make, executes them against your live cluster, and explains what it found.

Built for security engineers and platform engineers who want faster cluster visibility. Under the hood it uses any OpenAI-compatible API — Claude, GPT-4, Gemini, local models via Ollama, or anything else that speaks the OpenAI chat completions format. Swap the base URL and model name in one config file.

<img width="2458" height="1179" alt="kubeconfess" src="https://github.com/user-attachments/assets/7b1995ed-cf6d-47fd-8995-8474c1fddaa8" />


---

## Motivation

Kubernetes audits are tedious. You're constantly juggling `kubectl` flags, cross-referencing pod specs against policies, and mentally joining data across resources. KubeConfess replaces that with a conversation — ask it what you'd ask a colleague, get a direct answer backed by live cluster data.

It's also a learning project. If you've ever wanted to understand how AI agents actually work under the hood — tool calling, agentic loops, how the model decides what to do — this codebase is small enough to read in an afternoon.

---

## Features

### Workload Listing
- Pods, deployments, services, namespaces — filtered by namespace or cluster-wide
- Services show which pods they're attached to (resolved via label selector)
- Deployments show replica health (ready/desired)

### Security Scanning
- Privileged container detection — cluster-wide, per namespace, per pod, or per deployment
- Root container detection — catches missing `runAsNonRoot`, explicit UID 0, and no securityContext at all
- Every finding includes: what it is, why it matters, exact fix

### Permission Auditing
- Simulates `kubectl auth can-i` for a curated list of security-relevant verb/resource combinations
- Covers secrets, pods/exec, RBAC bindings, wildcard permissions, and more
- Scoped to a namespace or cluster-wide

---

## Setup

### Prerequisites

- Python 3.10+
- A Kubernetes cluster with a kubeconfig file
- An API key for any OpenAI-compatible provider

### Install

```bash
git clone https://github.com/arnavtripathy/KubeConfess.git
cd KubeConfess

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### Configure

Create `config/vars.py` — this file is gitignored and never committed:

```python
# config/vars.py
API_KEY  = "your-api-key-here"
BASE_URL = "https://api.anthropic.com/v1"   # Claude  (default)
# BASE_URL = "https://api.openai.com/v1"    # OpenAI
# BASE_URL = "http://localhost:11434/v1"    # Ollama  (local, no key needed)
MODEL    = "claude-haiku-4-5"               # or gpt-4o, llama3, gemma3, etc.
```

### Run

```bash
python main.py --kubeconfig ~/.kube/config
```

---

## How it works

Understanding this before contributing will save you a lot of time.

KubeConfess is a **tool-calling agent**. The AI doesn't have direct access to your cluster — it can only call functions you've explicitly defined. When you send a message, the loop works like this:

```
You type a message
       ↓
AI reads your message + all tool definitions
AI decides: which tool(s) do I need to call?
       ↓
Your Python code executes the tool against the cluster
Result is passed back to the AI
       ↓
AI reads the result, decides if it needs more tools
or if it has enough to give a final answer
       ↓
Final answer printed to terminal
```

The AI never sees your Python implementation — it only sees the tool's `name`, `description`, and `parameters` schema. This means **the description you write is everything**. If it's vague, the AI will call the wrong tool or not call it at all.

### The three files that matter

**`agent.py`** is the brain. It holds the AI client, combines all tool definitions into one list, and runs the agentic loop — sending messages to the AI, detecting tool call requests, executing them, feeding results back, and looping until the AI produces a final answer. If you want to understand agents, read this file first. It's about 50 lines.

**`kube_functions/list/__init__.py`** and **`kube_functions/security/__init__.py`** are the registries. Each one imports tools from its group, exposes a `definitions` list (sent to the AI so it knows what's available), and a `dispatch()` function (called by `agent.py` when the AI requests a tool). When you add a new tool, these are the files you touch.

**`main.py`** is just the CLI. It handles args, connects to the cluster, and runs the chat loop. It knows nothing about the AI or the tools — it just calls `send()` from `agent.py` and prints the result. You rarely need to touch this.

### Project layout

```
KubeConfess/
├── main.py                          ← CLI only
├── agent.py                         ← AI client, tool dispatch, agent loop
├── requirements.txt
│
├── config/
│   └── vars.py                      ← API key + model config (gitignored)
│
└── kube_functions/
    ├── connector.py                 ← kubeconfig loading, returns k8s clients
    ├── prompts.py                   ← system prompt
    │
    ├── list/
    │   ├── __init__.py              ← registry for listing tools
    │   ├── pods.py
    │   ├── deployments.py
    │   ├── services.py
    │   ├── namespaces.py
    │   └── permissions.py
    │
    └── security/
        ├── __init__.py              ← registry for security tools
        ├── privileged.py
        └── root_containers.py
```

---

## Contributing

### The pattern

Every tool is a Python file with two exports: a **function** that does the actual work, and a **definition** dict that describes it to the AI. That's the whole contract.

Here's the simplest possible example — `kube_functions/list/nodes.py`:

```python
from kubernetes.client.rest import ApiException

def list_nodes(k8s) -> str:
    try:
        nodes = k8s.list_node()

        if not nodes.items:
            return "No nodes found."

        lines = [f"Found {len(nodes.items)} node(s):\n"]
        for node in nodes.items:
            status = "Ready" if any(
                c.type == "Ready" and c.status == "True"
                for c in node.status.conditions
            ) else "NotReady"
            lines.append(f"  {node.metadata.name} — {status}")
        return "\n".join(lines)

    except ApiException as e:
        return f"Kubernetes API error: {e.status} {e.reason}"


definition = {
    "type": "function",
    "function": {
        "name": "list_nodes",
        "description": "List all nodes in the cluster and their Ready status.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
}
```

A few things worth noting here:

The function receives a Kubernetes client (`k8s`, `k8s_apps`, or `k8s_auth`) — it never imports from `kubernetes.*` directly. The client is passed in from the connector. This keeps tools testable.

The function always returns a **string**. Never raise an exception — catch it and return a plain error string. The AI needs to read the result and explain it to the user. A Python traceback is not useful there.

The `description` in the definition is what the AI reads to decide whether to call this tool. Write it the way you'd explain the tool to someone who needs to decide whether it's relevant. Be specific — "List all nodes and their Ready status" is better than "Get nodes".

### Registering the tool

Once the file exists, add two lines to `kube_functions/list/__init__.py`:

```python
from kube_functions.list.nodes import list_nodes, definition as nodes_def

definitions = [..., nodes_def]   # add nodes_def to the existing list

def dispatch(name, args, k8s=None, k8s_apps=None, k8s_auth=None):
    ...
    if name == "list_nodes":
        return list_nodes(k8s)   # pass the right client
```

`agent.py` and `main.py` don't change. The AI automatically learns about the new tool because `definitions` is passed to it on every request.

### Adding a security check

Same pattern, different folder. Security tools go in `kube_functions/security/` and register in `kube_functions/security/__init__.py`.

The one difference: security tools should follow the finding format already established in `privileged.py` and `root_containers.py`:

```
⚠ CRITICAL — <namespace>/<pod> (<container>)
   What: <what was found>
   Risk: <why it matters>
   Fix:  <exact remediation>
```

This matters because the system prompt in `prompts.py` tells the AI to expect this format and reason about severity. Consistent structure means consistent output.

### Which Kubernetes client to use

There are three clients available via `dispatch()`:

- `k8s` — `CoreV1Api`. Use this for pods, services, namespaces, secrets, nodes, configmaps.
- `k8s_apps` — `AppsV1Api`. Use this for deployments, daemonsets, statefulsets, replicasets.
- `k8s_auth` — `AuthorizationV1Api`. Use this for permission checks (SelfSubjectAccessReview).

If you need a client that isn't here yet (e.g. `NetworkingV1Api` for NetworkPolicies), add it to `kube_functions/connector.py`, return it from `connect()`, unpack it in `main.py`, and thread it through `agent.py`'s `dispatch()`.

### What makes a good contribution

A good tool is one that would actually save time during a real audit or investigation. Think about the questions you find yourself asking repeatedly — "which pods are running as root?", "what services are exposed externally?", "which namespaces have no network policies?" — and turn those into tools.

A bad tool is one that duplicates something `kubectl` already does trivially, or one so broad it's not actionable ("check security" is not a tool, it's a goal).

### Submitting

Open a PR with:
- The new tool file
- The two-line registration change in the relevant `__init__.py`
- A brief note in the PR description of what you tested it against

If you find a bug, open an issue with what you typed, the `⚙` tool line that appeared, and what you expected.

---

## Requirements

```
openai>=1.0.0
kubernetes>=29.0.0
rich>=13.0.0
```

---

## Author

Built by [Arnav Tripathy](https://github.com/arnavtripathy) — Security and DevOps Engineer, Trinity College Dublin.

Also check out [KubeDecoy](https://github.com/arnavtripathy/kubedecoy) — a Kubernetes honeypot built with vcluster, Falco, and Falcosidekick.

---

## License

MIT — do whatever you want, just don't blame me if your cluster confesses something you didn't want to know.
