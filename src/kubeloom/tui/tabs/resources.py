"""Resources tab component."""

from typing import List
from textual.widgets import DataTable

from ...core.models import Policy
from ...core.services import ResourceInfo


class ResourcesTab:
    """Resources tab logic."""

    @staticmethod
    def update_table(table: DataTable, resources: List[ResourceInfo], policies: List[Policy]) -> None:
        """Update the resources table."""
        table.clear(columns=True)

        table.add_column("Name")
        table.add_column("Type")
        table.add_column("Service Account")
        table.add_column("Policies")
        table.add_column("Labels")

        # Group resources by type
        grouped_resources = {}
        for resource in resources:
            if resource.type not in grouped_resources:
                grouped_resources[resource.type] = []
            grouped_resources[resource.type].append(resource)

        # Sort resource types for consistent display
        type_order = ["service", "pod", "statefulset", "deployment", "daemonset"]
        sorted_types = []

        # Add known types in order
        for resource_type in type_order:
            if resource_type in grouped_resources:
                sorted_types.append(resource_type)

        # Add any unknown types at the end
        for resource_type in sorted(grouped_resources.keys()):
            if resource_type not in sorted_types:
                sorted_types.append(resource_type)

        # Add resources to table grouped by type
        for resource_type in sorted_types:
            resources_of_type = grouped_resources[resource_type]

            # Sort resources within type by name
            resources_of_type.sort(key=lambda r: r.name)

            for resource in resources_of_type:
                # Count policies affecting this resource
                affecting_policies = sum(
                    1 for policy in policies
                    if ResourcesTab._resource_affected_by_policy(resource, policy)
                )

                # Format labels (show first few key=value pairs)
                labels_str = ", ".join([f"{k}={v}" for k, v in list(resource.labels.items())[:2]])
                if len(resource.labels) > 2:
                    labels_str += f"... (+{len(resource.labels) - 2})"

                table.add_row(
                    resource.name,
                    resource.type,
                    resource.service_account or "-",
                    str(affecting_policies),
                    labels_str or "-"
                )

    @staticmethod
    def _resource_affected_by_policy(resource: ResourceInfo, policy: Policy) -> bool:
        """Check if a resource is affected by a policy (as source or target)."""
        # Check if resource is a target
        for target in policy.targets:
            if resource.type == "service" and resource.name in target.services:
                return True
            if resource.type == "pod" and resource.name in target.pods:
                return True
            if target.workload_labels:
                if all(resource.labels.get(k) == v for k, v in target.workload_labels.items()):
                    return True

        # Check if resource is a source
        if policy.source:
            if (resource.service_account and
                resource.service_account in policy.source.service_accounts):
                return True
            if policy.source.workload_labels:
                if all(resource.labels.get(k) == v for k, v in policy.source.workload_labels.items()):
                    return True

        return False
