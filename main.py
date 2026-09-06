"""Backward-compatible entry point. Prefer the installed `kubeconfess` command."""

from kubeconfess.main import main

if __name__ == "__main__":
    main()
