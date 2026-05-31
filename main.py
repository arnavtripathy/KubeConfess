import argparse
import readline 
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich import box
from kube_functions.connector import connect
from agent import send

console = Console()

BANNER = """
[bold cyan] ██╗  ██╗██╗   ██╗██████╗ ███████╗[/bold cyan]
[bold cyan] ██║ ██╔╝██║   ██║██╔══██╗██╔════╝[/bold cyan]
[bold cyan] █████╔╝ ██║   ██║██████╔╝█████╗  [/bold cyan]
[bold cyan] ██╔═██╗ ██║   ██║██╔══██╗██╔══╝  [/bold cyan]
[bold cyan] ██║  ██╗╚██████╔╝██████╔╝███████╗[/bold cyan]
[bold cyan] ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝[/bold cyan]
[dim]    C O N F E S S    E D I T I O N[/dim]
"""

def print_banner():
    console.print(BANNER)
    console.print(Panel.fit(
        "[dim]Kubernetes AI Agent — talk to your cluster in plain English[/dim]\n"
        "[dim]Type [/dim][bold white]exit[/bold white][dim] or [/dim][bold white]quit[/bold white][dim] to leave  •  [/dim][bold white]↑↓[/bold white][dim] for history[/dim]",
        border_style="cyan",
        box=box.ROUNDED,
    ))
    console.print()

def print_connection(kubeconfig: str):
    console.print(f"  [bold green]✓[/bold green] [dim]Connected via[/dim] [cyan]{kubeconfig}[/cyan]\n")

def print_tool_call(name: str, args: dict):
    args_str = ", ".join(f"{k}=[cyan]{v}[/cyan]" for k, v in args.items()) if args else ""
    console.print(f"  [dim]⚙  {name}({args_str})[/dim]")

def print_reply(reply: str):
    # Colour ✓ green and ⚠ yellow automatically
    text = Text.from_markup(
        reply
        .replace("✓", "[bold green]✓[/bold green]")
        .replace("⚠", "[bold yellow]⚠[/bold yellow]")
        .replace("CRITICAL", "[bold red]CRITICAL[/bold red]")
        .replace("HIGH", "[bold yellow]HIGH[/bold yellow]")
    )
    console.print(Panel(
        text,
        border_style="dim",
        box=box.ROUNDED,
        padding=(0, 1),
    ))
    console.print()

def get_input() -> str:
    try:
        return console.input("[bold green]you[/bold green][dim]>[/dim] ").strip()
    except EOFError:
        return "exit"


# Wrap send() to show a spinner while waiting
def send_with_spinner(messages, k8s, k8s_apps):
    with Live(Spinner("dots", text="[dim]thinking...[/dim]"), console=console, transient=True) as live:
        def on_tool(name, args):
            live.stop()
            print_tool_call(name, args)
            live.start()

        return send(messages, k8s, k8s_apps, on_tool_call=on_tool)


def main():
    parser = argparse.ArgumentParser(description="KubeConfess — Kubernetes AI Agent")
    parser.add_argument("--kubeconfig", required=True, help="Path to kubeconfig file")
    args = parser.parse_args()

    print_banner()

    try:
        k8s, k8s_apps = connect(args.kubeconfig)
        print_connection(args.kubeconfig)
    except Exception as e:
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

            messages.append({"role": "user", "content": user_input})
            reply = send_with_spinner(messages, k8s, k8s_apps)
            print_reply(reply)

        except KeyboardInterrupt:
            console.print("\n[dim]Goodbye.[/dim]\n")
            break

if __name__ == "__main__":
    main()