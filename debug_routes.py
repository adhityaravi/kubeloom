#!/usr/bin/env python3
"""Debug different route scenarios in real policies."""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from kubeloom.k8s.client import K8sClient
from kubeloom.mesh.istio.converter import IstioConverter


async def debug_routes():
    """Debug different route scenarios."""
    print("Debugging route scenarios...")

    try:
        # Initialize client
        client = K8sClient()
        await client._ensure_connected()
        print("✓ Connected to cluster")

        # Get all authorization policies
        auth_policies = await client.get_resources(
            api_version="security.istio.io/v1beta1",
            kind="AuthorizationPolicy",
            namespace="tempo"
        )

        print(f"\nFound {len(auth_policies)} authorization policies")

        # Analyze route patterns
        converter = IstioConverter()

        for policy_raw in auth_policies:
            policy_name = policy_raw.get("metadata", {}).get("name", "unknown")
            spec = policy_raw.get("spec", {})
            rules = spec.get("rules", [])

            print(f"\n=== Policy: {policy_name} ===")
            print(f"Raw rules: {rules}")

            # Convert and check routes
            policy = converter.convert_authorization_policy(policy_raw)
            print(f"Converted routes: {policy.allowed_routes}")
            print(f"Number of routes: {len(policy.allowed_routes) if policy.allowed_routes else 0}")

            # Analyze each rule's 'to' clause
            for i, rule in enumerate(rules):
                print(f"  Rule {i}:")
                if "to" in rule:
                    to_clause = rule["to"]
                    print(f"    'to' clause: {to_clause}")
                    if to_clause == []:
                        print(f"    -> ALLOW NOTHING (empty array)")
                    elif to_clause == [{}]:
                        print(f"    -> ALLOW ALL (empty operation)")
                    elif any("operation" in to_item for to_item in to_clause):
                        print(f"    -> SPECIFIC ROUTES")
                    else:
                        print(f"    -> UNCLEAR PATTERN")
                else:
                    print(f"    No 'to' clause -> ALLOW ALL")

        await client.close()
        return True

    except Exception as e:
        print(f"\n❌ Debug failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    asyncio.run(debug_routes())