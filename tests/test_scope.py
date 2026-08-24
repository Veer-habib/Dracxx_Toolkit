from dracxx.core.scope import Scope, build_scope_from_targets


def test_domain_allowed():
    scope = Scope(allowed_domains=["example.com"])
    assert scope.is_domain_allowed("example.com")
    assert scope.is_domain_allowed("sub.example.com")
    assert not scope.is_domain_allowed("evil.com")


def test_domain_exclusion():
    scope = Scope(allowed_domains=["example.com"], exclusions=["internal.example.com"])
    assert not scope.is_domain_allowed("internal.example.com")


def test_ip_in_cidr():
    scope = Scope(allowed_cidrs=["10.0.0.0/24"])
    assert scope.is_ip_allowed("10.0.0.5")
    assert not scope.is_ip_allowed("10.0.1.5")


def test_build_scope_from_targets():
    scope = build_scope_from_targets(["example.com", "10.0.0.0/24"])
    assert scope.is_target_allowed("example.com")
    assert scope.is_target_allowed("10.0.0.5")
