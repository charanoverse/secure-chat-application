# secure_chat/cli.py
import typer
from rich import print
from pathlib import Path
from datetime import datetime
from .storage.history import init_db, search_messages
from .services.chat_service import run_server, run_client
# 🆕 import new relay server runner
from .relay.relay_server import app as relay_app
import uvicorn

init_db()

app = typer.Typer(help="Secure Chat CLI")

@app.command()
def server(
    bind: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(65432, help="Port"),
    history: str = typer.Option("chat_history.enc", help="Encrypted history file"),
    peer_id: str = typer.Option(..., "--peer-id", help="Server's logical peer ID (e.g., 'SERVER')"),
    priv: Path = typer.Option(..., "--priv", exists=True, file_okay=True, dir_okay=False, help="Server's RSA private key PEM (identity)"),
) -> None:
    """Run secure chat server (TCP mode)."""
    run_server(bind, port, history, server_peer_id=peer_id, server_private_pem=priv)


@app.command()
def client(
    host: str = typer.Option(..., help="Server host (TCP)"),
    port: int = typer.Option(65432, help="Server port (TCP)"),
    history: str = typer.Option("chat_history.enc", help="Encrypted history file"),
    peer_id: str = typer.Option(..., "--peer-id", help="Client's logical peer ID"),
    server_peer_id: str = typer.Option(..., "--server-peer-id", help="Expected server peer ID"),
    server_pub: Path = typer.Option(..., exists=True, help="Pinned server RSA public key PEM"),
    relay: str = typer.Option(None, help="Optional relay WebSocket URL (e.g., ws://localhost:8000/ws/room1)"),
) -> None:
    """Run secure chat client. Falls back to relay if TCP fails."""
    run_client(
        host,
        port,
        history,
        client_peer_id=peer_id,
        server_peer_id=server_peer_id,
        pinned_server_pubkey_pem=server_pub,
        relay_url=relay,   # 🆕 pass relay param
    )


@app.command()
def search(term: str) -> None:
    """Search encrypted chat history."""
    results = search_messages(term)
    if not results:
        typer.echo("No messages found.")
    else:
        typer.echo(f"Found {len(results)} matches:")
        for r in results:
            mid = r.get("message_id", "<unknown>")
            sender = r.get("sender", "<unknown>")
            ts = r.get("ts", None)
            ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "<unknown>"
            typer.echo(f"- message_id={mid} sender={sender} ts={ts_str}")


# 🆕 New: start relay server
@app.command("relay-server")
def relay_server(
    host: str = typer.Option("0.0.0.0", help="Relay host"),
    port: int = typer.Option(8000, help="Relay port"),
):
    """Run FastAPI WebSocket relay server."""
    print(f"[bold green]Starting SecureChat Relay on {host}:{port}[/bold green]")
    uvicorn.run(relay_app, host=host, port=port)

if __name__ == "__main__":
    app()
