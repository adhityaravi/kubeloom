"""CLI command implementations."""

import json

from rich.console import Console
from rich.table import Table

from kubeloom.core.models import Policy
from kubeloom.k8s.client import K8sClient
from kubeloom.mesh.istio.adapter import IstioAdapter

console = Console()


async def list_policies_async(namespace: str | None, output: str, mesh_type: str | None) -> None:
    """List all service mesh policies in the cluster."""
    try:
        k8s_client = K8sClient()

        adapter = IstioAdapter(k8s_client)
        service_mesh = await adapter.detect()

        if not service_mesh:
            console.print("No supported service mesh detected")
            return

        policies: list[Policy] = []

        if namespace:
            policies = await adapter.get_policies(namespace)
        else:
            namespaces = await k8s_client.get_namespaces()
            for ns in namespaces:
                ns_policies = await adapter.get_policies(ns.name)
                policies.extend(ns_policies)

        if output == "json":
            _output_json(policies)
        elif output == "table":
            _output_table(policies)
        else:
            console.print(f"Output format '{output}' not supported")

    except Exception as e:
        console.print(f"Error: {e}")


async def describe_policy_async(namespace: str | None, policy_name: str) -> None:
    """Describe a specific policy in detail."""
    try:
        k8s_client = K8sClient()

        adapter = IstioAdapter(k8s_client)
        service_mesh = await adapter.detect()

        if not service_mesh:
            console.print("No supported service mesh detected")
            return

        # TODO: Implement get_policy method that takes policy type
        console.print(f"Policy description for {policy_name} not implemented yet")

    except Exception as e:
        console.print(f"Error: {e}")


def _output_table(policies: list[Policy]) -> None:
    """Output policies as a table."""
    if not policies:
        console.print("No policies found")
        return

    table = Table()
    table.add_column("NAMESPACE")
    table.add_column("NAME")
    table.add_column("TYPE")
    table.add_column("STATUS")
    table.add_column("TARGETS")
    table.add_column("ROUTES")

    for policy in policies:
        table.add_row(
            policy.namespace,
            policy.name,
            policy.type.value,
            policy.status.value,
            str(len(policy.targets)),
            str(len(policy.allowed_routes)),
        )

    console.print(table)


def _output_json(policies: list[Policy]) -> None:
    """Output policies as JSON."""
    policy_data = []
    for policy in policies:
        policy_data.append(
            {
                "name": policy.name,
                "namespace": policy.namespace,
                "type": policy.type.value,
                "status": policy.status.value,
                "mesh_type": policy.mesh_type.value,
                "targets": len(policy.targets),
                "routes": len(policy.allowed_routes),
                "conflicts": len(policy.conflicts),
            }
        )

    print(json.dumps(policy_data, indent=2))
