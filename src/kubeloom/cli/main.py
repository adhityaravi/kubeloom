"""Main CLI entry point."""

import asyncio

import click

from kubeloom.cli.commands import describe_policy_async, list_policies_async
from kubeloom.core.models import ServiceMeshType


@click.group()
@click.version_option()
def cli() -> None:
    """kubeloom - Service mesh policy discovery and management for Kubernetes."""
    pass


@cli.command("list")
@click.option("--namespace", "-n", help="Kubernetes namespace to scan (all namespaces if not specified)")
@click.option("--output", "-o", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.option(
    "--mesh-type",
    type=click.Choice([mesh.value for mesh in ServiceMeshType if mesh != ServiceMeshType.NONE]),
    help="Filter by specific service mesh type",
)
def list_policies(namespace: str | None, output: str, mesh_type: str | None) -> None:
    """List all service mesh policies in the cluster."""
    asyncio.run(list_policies_async(namespace, output, mesh_type))


@cli.command("describe")
@click.option("--namespace", "-n", help="Kubernetes namespace")
@click.argument("policy_name")
def describe(namespace: str | None, policy_name: str) -> None:
    """Describe a specific policy in detail."""
    asyncio.run(describe_policy_async(namespace, policy_name))


@cli.command("tui")
def tui() -> None:
    """Launch the Terminal User Interface."""
    from kubeloom.tui import run

    run()


if __name__ == "__main__":
    cli()
