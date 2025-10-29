"""Unit tests for core models."""

from kubeloom.core.models import Policy, PolicyStatus, PolicyType, ServiceMeshType


class TestPolicy:
    """Test Policy model."""

    def test_policy_creation(self):
        """Test basic policy creation."""
        policy = Policy(
            name="test-policy",
            namespace="default",
            type=PolicyType.AUTHORIZATION_POLICY,
            mesh_type=ServiceMeshType.ISTIO,
        )

        assert policy.name == "test-policy"
        assert policy.namespace == "default"
        assert policy.type == PolicyType.AUTHORIZATION_POLICY
        assert policy.mesh_type == ServiceMeshType.ISTIO
        assert policy.status == PolicyStatus.UNKNOWN

    def test_policy_full_name(self):
        """Test policy full name generation."""
        policy = Policy(
            name="test-policy",
            namespace="default",
            type=PolicyType.AUTHORIZATION_POLICY,
            mesh_type=ServiceMeshType.ISTIO,
        )

        assert policy.get_full_name() == "default/test-policy"

    def test_policy_hash(self):
        """Test policy hashing for sets."""
        policy1 = Policy(
            name="test-policy",
            namespace="default",
            type=PolicyType.AUTHORIZATION_POLICY,
            mesh_type=ServiceMeshType.ISTIO,
        )

        policy2 = Policy(
            name="test-policy",
            namespace="default",
            type=PolicyType.AUTHORIZATION_POLICY,
            mesh_type=ServiceMeshType.ISTIO,
        )

        assert hash(policy1) == hash(policy2)
        assert policy1 in {policy2}

    def test_policy_applies_to_namespace(self):
        """Test namespace targeting logic."""
        policy = Policy(
            name="test-policy",
            namespace="default",
            type=PolicyType.AUTHORIZATION_POLICY,
            mesh_type=ServiceMeshType.ISTIO,
        )

        # No targets means applies to all
        assert policy.applies_to_namespace("any-namespace") is True
