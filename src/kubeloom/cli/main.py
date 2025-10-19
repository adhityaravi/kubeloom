"""Main CLI entry point."""

import asyncio
from typing import Optional

import click

from ..core.models import ServiceMeshType
from .commands import list_policies_async, describe_policy_async


@click.group()
@click.version_option()
def cli() -> None:
    """kubeloom - Service mesh policy discovery and management for Kubernetes."""
    pass


@cli.command("list")
@click.option(
    "--namespace", "-n",
    help="Kubernetes namespace to scan (all namespaces if not specified)"
)
@click.option(
    "--output", "-o",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format"
)
@click.option(
    "--mesh-type",
    type=click.Choice([mesh.value for mesh in ServiceMeshType if mesh != ServiceMeshType.NONE]),
    help="Filter by specific service mesh type"
)
def list_policies(namespace: Optional[str], output: str, mesh_type: Optional[str]) -> None:
    """List all service mesh policies in the cluster."""
    asyncio.run(list_policies_async(namespace, output, mesh_type))


@cli.command("describe")
@click.option(
    "--namespace", "-n",
    help="Kubernetes namespace"
)
@click.argument("policy_name")
def describe(namespace: Optional[str], policy_name: str) -> None:
    """Describe a specific policy in detail."""
    asyncio.run(describe_policy_async(namespace, policy_name))


@cli.command("tui")
def tui() -> None:
    """Launch the Terminal User Interface."""
    from ..tui import run
    run()


if __name__ == "__main__":
    cli()