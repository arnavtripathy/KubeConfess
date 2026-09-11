import argparse

from openai import OpenAI
from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.text import Text

from kubeconfess.agent import send
from kubeconfess.config.vars import API_KEY, BASE_URL, MAX_TOKENS, MODEL_NAME
from kubeconfess.kube_functions.connector import connect
from kubeconfess.kube_functions.investigate import gather
from kubeconfess.kube_functions.prompts import ANALYSE_PROMPT, SYSTEM_PROMPT

console = Console()
ai = OpenAI(api_key=API_KEY, base_url=BASE_URL)

BANNER = """
[bold cyan] ██╗  ██╗██╗   ██╗██████╗ ███████╗[/bold cyan]
[bold cyan] ██║ ██╔╝██║   ██║██╔══██╗██╔════╝[/bold cyan]
[bold cyan] █████╔╝ ██║   ██║██████╔╝█████╗  [/bold cyan]
[bold cyan] ██╔═██╗ ██║   ██║██╔══██╗██╔══╝  [/bold cyan]
[bold cyan] ██║  ██╗╚██████╔╝██████╔╝███████╗[/bold cyan]
[bold cyan] ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝[/bold cyan]
[bold white]          C O N F E S S[/bold white]  [dim]|[/dim]  [bold cyan]v1[/bold cyan]  [dim]|[/dim]  [dim]Kubernetes AI Agent[/dim]
"""


def print_banner():
    console.print(BANNER)
    console.print(
        Panel.fit(
            "[dim]Kubernetes AI Agent\n"
            "Type [/dim][bold white]exit[/bold white][dim] or [/dim][bold white]quit[/bold white][dim] to leave  •  [/dim]"
            "[bold white]↑↓[/bold white][dim] for history  •  [/dim]"
            "[bold white]investigate <target>[/bold white][dim] to map attack paths[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()


def print_connection(kubeconfig: str):
    console.print(f"  [bold green]✓[/bold green] [dim]Connected via[/dim] [cyan]{kubeconfig}[/cyan]\n")


def print_tool_call(name: str, args: dict):
    args_str = ", ".join(f"{k}=[cyan]{v}[/cyan]" for k, v in args.items()) if args else ""
    console.print(f"  [dim]⚙  {name}({args_str})[/dim]")


def print_reply(reply: str, investigate: bool = False):
    text = Text.from_markup(
        reply.replace("✓", "[bold green]✓[/bold green]")
        .replace("⚠", "[bold yellow]⚠[/bold yellow]")
        .replace("CRITICAL", "[bold red]CRITICAL[/bold red]")
        .replace("HIGH", "[bold yellow]HIGH[/bold yellow]")
        .replace("STARTING POINT", "[bold cyan]STARTING POINT[/bold cyan]")
        .replace("ATTACK PATHS", "[bold red]ATTACK PATHS[/bold red]")
        .replace("BLAST RADIUS", "[bold red]BLAST RADIUS[/bold red]")
        .replace("RECOMMENDED FIXES", "[bold green]RECOMMENDED FIXES[/bold green]")
    )
    console.print(
        Panel(
            text,
            border_style="red" if investigate else "dim",
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )
    console.print()


def get_input() -> str:
    try:
        return console.input("[bold green]you[/bold green][dim]>[/dim] ").strip()
    except EOFError:
        return "exit"


def send_with_spinner(messages, k8s, k8s_apps, k8s_auth, k8s_rbac, prompt):
    with Live(Spinner("dots", text="[dim]thinking...[/dim]"), console=console, transient=True) as live:

        def on_tool(name, args):
            live.stop()
            print_tool_call(name, args)
            live.start()

        return send(messages, k8s, k8s_apps, k8s_auth, k8s_rbac, system_prompt=prompt, on_tool_call=on_tool)


def run_investigate(target, k8s, k8s_apps, k8s_auth, k8s_rbac, messages):
    """
    Gather all data with fixed tool calls (no AI loop),
    then send to Claude once for analysis.
    """

    # ── Step 1: gather data with progress display ─────────────────────────────
    with Live(console=console, transient=True) as live:

        def on_step(label):
            live.update(Spinner("dots", text=f"[dim]gathering: {label}[/dim]"))

        data = gather(target, k8s, k8s_apps, k8s_auth, k8s_rbac, on_step=on_step)

    console.print("  [bold green]✓[/bold green] [dim]Data gathered — analysing...[/dim]")

    # ── Step 2: send everything to Claude once, no tools ─────────────────────
    analysis_message = f"Target: {target}\n\nHere is the raw data gathered from the cluster:\n\n{data}\n\nWrite the attack path report."

    with Live(Spinner("dots", text="[dim]analysing...[/dim]"), console=console, transient=True):
        response = ai.chat.completions.create(
            model=MODEL_NAME,
            max_tokens=MAX_TOKENS,
            messages=[
                {"role": "system", "content": ANALYSE_PROMPT},
                {"role": "user", "content": analysis_message},
            ],
            # no tools= — Claude cannot call tools here, must write report
        )

    reply = response.choices[0].message.content

    # Add to conversation history so follow-ups are grounded in the findings
    messages.append({"role": "user", "content": analysis_message})
    messages.append({"role": "assistant", "content": reply})

    return reply


def parse_investigate(user_input: str):
    lower = user_input.lower().strip()
    if not lower.startswith("investigate"):
        return None
    parts = user_input.strip().split(maxsplit=1)
    if len(parts) < 2:
        return None
    return parts[1].strip()


def main():
    parser = argparse.ArgumentParser(description="KubeConfess — Kubernetes AI Agent")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    parser.add_argument("--incluster", action="store_true", help="Run inside a pod using mounted SA token")
    args = parser.parse_args()

    if not args.kubeconfig and not args.incluster:
        console.print("  [bold red]✗[/bold red] Provide --kubeconfig <path> or --incluster")
        return

    print_banner()

    try:
        if args.incluster:
            k8s, k8s_apps, k8s_auth, k8s_rbac = connect(incluster=True)
            console.print("  [bold green]✓[/bold green] [dim]Running in-cluster[/dim]\n")
        else:
            k8s, k8s_apps, k8s_auth, k8s_rbac = connect(kubeconfig_path=args.kubeconfig)
            console.print(f"  [bold green]✓[/bold green] [dim]Connected via[/dim] [cyan]{args.kubeconfig}[/cyan]\n")
    except Exception as e:  # noqa: BLE001 # We want to catch all exceptions here to report connection errors.
        console.print(f"  [bold red]✗[/bold red] Failed to connect: {e}")
        return

    messages = []

    while True:
        try:
            user_input = get_input()

            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                console.print("\n[dim]Goodbye.[/dim]\n")
                break

            # ── Investigate ───────────────────────────────────────────────────
            target = parse_investigate(user_input)
            if target:
                console.print(f"\n  [bold red]⚡[/bold red] Investigating: [cyan]{target}[/cyan]\n")
                reply = run_investigate(target, k8s, k8s_apps, k8s_auth, k8s_rbac, messages)
                print_reply(reply, investigate=True)
                continue

            # ── Normal scan ───────────────────────────────────────────────────
            messages.append({"role": "user", "content": user_input})
            reply = send_with_spinner(messages, k8s, k8s_apps, k8s_auth, k8s_rbac, SYSTEM_PROMPT)
            print_reply(reply)

        except KeyboardInterrupt:
            console.print("\n[dim]Goodbye.[/dim]\n")
            break


if __name__ == "__main__":
    main()
