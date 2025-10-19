#!/usr/bin/env python3
"""Debug resource extraction logic."""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from kubeloom.k8s.client import K8sClient
from kubeloom.mesh.istio.adapter import IstioAdapter
from kubeloom.core.services import PolicyAnalyzer


async def debug_resources():
    """Debug resource extraction logic."""
    print("Debugging resource extraction...")

    try:
        # Initialize clients
        client = K8sClient()
        await client._ensure_connected()
        print("✓ Connected to cluster")

        # Get adapter and analyzer
        adapter = IstioAdapter(client)
        analyzer = PolicyAnalyzer(client)

        # Get policies in tempo namespace
        policies = await adapter.get_policies("tempo")
        print(f"\nFound {len(policies)} policies in tempo namespace")

        for policy in policies:
            print(f"  - {policy.name} ({policy.type.value})")
            print(f"    Targets: {len(policy.targets)}")
            for target in policy.targets:
                print(f"      Services: {target.services}")
                print(f"      Pods: {target.pods}")
                print(f"      Workload labels: {target.workload_labels}")

            if policy.source:
                print(f"    Source:")
                print(f"      Service accounts: {policy.source.service_accounts}")
                print(f"      Workload labels: {policy.source.workload_labels}")

        # Test resource extraction
        print(f"\nExtracting resources...")
        resources = await analyzer.get_all_affected_resources(policies)
        print(f"Found {len(resources)} affected resources:")

        for resource in resources:
            print(f"  - {resource.name} ({resource.type}) in {resource.namespace}")
            print(f"    Service Account: {resource.service_account}")
            print(f"    Labels: {resource.labels}")

        # Test resource access analysis for a specific resource
        print(f"\nTesting resource access analysis:")

        # Test with tempo-0 pod
        test_resource = None
        for resource in resources:
            if resource.name == "tempo-0" and resource.type == "pod":
                test_resource = resource
                break

        if test_resource:
            print(f"\nAnalyzing access for: {test_resource.name} ({test_resource.type})")
            print(f"Service Account: {test_resource.service_account}")

            # Check what the controller SA is
            controller_sa = await analyzer._get_pod_controller_service_account(test_resource)
            print(f"Controller Service Account: {controller_sa}")

            analysis = await analyzer.analyze_resource_policies(test_resource, policies)

            print(f"\nInbound access ({len(analysis.inbound_access)} sources can reach this):")
            for source, routes in analysis.inbound_access:
                print(f"  - {source.name} ({source.type})")
                for route in routes[:2]:  # Show first 2 routes
                    if hasattr(route, 'allow_all') and route.allow_all:
                        print(f"    Routes: All allowed")
                    elif hasattr(route, 'ports') and route.ports:
                        print(f"    Routes: Ports {route.ports}")
                    else:
                        print(f"    Routes: {route}")

            print(f"\nOutbound access (this can reach {len(analysis.outbound_access)} targets):")
            for target, routes in analysis.outbound_access:
                print(f"  - {target.name} ({target.type})")
                for route in routes[:2]:  # Show first 2 routes
                    if hasattr(route, 'allow_all') and route.allow_all:
                        print(f"    Routes: All allowed")
                    elif hasattr(route, 'ports') and route.ports:
                        print(f"    Routes: Ports {route.ports}")
                    else:
                        print(f"    Routes: {route}")

        await client.close()
        return True

    except Exception as e:
        print(f"\n❌ Debug failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    asyncio.run(debug_resources())