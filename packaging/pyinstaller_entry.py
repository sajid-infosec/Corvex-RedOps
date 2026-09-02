"""PyInstaller entry point — a single script so the CLI bundles into one binary."""
from pentestiq.cli import app

if __name__ == "__main__":
    app()
