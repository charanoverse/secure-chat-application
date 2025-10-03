# secure_chat/cli.py
import typer
from rich import print
from pathlib import Path
from .storage.history import init_db, search_messages
from .services.chat_service import run_server, run_client

# Initialize the encrypted history database on first run
init_db()

app = typer.Typer(help="Secure Chat - Phase 1 (X25519 handshake, AEAD, replay protection, rekey)")

@app.command()
def server(
    bind: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(65432, help="Port"),
    history: str = typer.Option("chat_history.enc", help="Encrypted history file"),
    peer_id: str = typer.Option(..., "--peer-id", help="Server's logical peer ID (e.g., 'SERVER')"),
    priv: Path = typer.Option(..., "--priv", exists=True, file_okay=True, dir_okay=False, help="Server's RSA private key PEM (identity)"),
):
    """Run the secure chat server (Phase 1)."""
    run_server(bind, port, history, server_peer_id=peer_id, server_private_pem=priv)

@app.command()
def client(
    host: str = typer.Option(..., help="Server host"),
    port: int = typer.Option(65432, help="Server port"),
    history: str = typer.Option("chat_history.enc", help="Encrypted history file"),
    peer_id: str = typer.Option(..., "--peer-id", help="Client's logical peer ID (e.g., 'ALICE')"),
    server_peer_id: str = typer.Option(..., "--server-peer-id", help="Expected server peer ID"),
    server_pub: Path = typer.Option(
        ..., exists=True, file_okay=True, dir_okay=False,
        help="Pinned server RSA public key PEM"
    ),
):
    run_client(
        host,
        port,
        history,
        client_peer_id=peer_id,
        server_peer_id=server_peer_id,
        pinned_server_pubkey_pem=server_pub,
    )

@app.command()
def search(term: str):
    """
    Search encrypted chat history for a term.
    """
    results = search_messages(term)
    if not results:
        typer.echo("No messages found.")
    else:
        typer.echo(f"Found {len(results)} messages:")
        for msg in results:
            typer.echo(f"- {msg}")

if __name__ == "__main__":
    app()