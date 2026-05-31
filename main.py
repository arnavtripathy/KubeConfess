import argparse
from kube_functions.connector import connect
from agent import send

def main():
    parser = argparse.ArgumentParser(description="Kubernetes AI Agent")
    parser.add_argument("--kubeconfig", required=True, help="Path to kubeconfig file")
    args = parser.parse_args()

    k8s, k8s_apps = connect(args.kubeconfig)
    print(f"\033[90m✓ Connected via {args.kubeconfig}\033[0m")

    messages = []
    print("\033[96m╔══════════════════════════════════╗")
    print("║      Kubernetes AI Agent         ║")
    print("║  type 'exit' or 'quit' to leave  ║")
    print("╚══════════════════════════════════╝\033[0m\n")

    while True:
        try:
            user_input = input("\033[92myou>\033[0m ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                print("\033[90mGoodbye!\033[0m")
                break
            messages.append({"role": "user", "content": user_input})
            reply = send(messages, k8s, k8s_apps)
            print(f"\033[94mclaude>\033[0m {reply}\n")
        except KeyboardInterrupt:
            print("\n\033[90mGoodbye!\033[0m")
            break

if __name__ == "__main__":
    main()