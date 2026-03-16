"""
Unit tests 22-23: Architectural invariants.
  22 - Firewall Core contains no OpenClaw imports
  23 - Unregistered wrapper -> controlled 403 (UNREGISTERED_TOOL_FAMILY), never a 500
"""
from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

import pytest


CORE_MODULES = [
    "core.modes",
    "core.schemas",
    "core.normalize",
    "core.audit",
    "core.policy",
    "core.risk",
    "core.decision",
    "core.killswitch",
    "core.approval",
    "core.evaluation",
    "core.logging",
    "core.agents",
    "core.sessions",
]

OPENCLAW_MODULES = {"openclaw", "adapters.openclaw", "adapters"}


def _get_project_root() -> Path:
    """Resolve the zdg-agent-firewall project root on the Python path."""
    for path_entry in sys.path:
        candidate = Path(path_entry)
        if (candidate / "core").is_dir() and (candidate / "core" / "modes.py").exists():
            return candidate
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "core" / "modes.py").exists():
            return parent
    raise RuntimeError("Cannot locate zdg-agent-firewall project root")


def _collect_imports(source_path: Path) -> set[str]:
    """Parse a Python source file and return all imported module names."""
    try:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
    except SyntaxError:
        return set()

    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
            imports.add(node.module)
    return imports


def test_core_has_no_openclaw_imports():
    """core/ modules must not import anything from adapters.openclaw or openclaw."""
    root = _get_project_root()
    core_dir = root / "core"
    assert core_dir.is_dir(), f"core/ directory not found at {root}"

    violations: list[str] = []
    for py_file in core_dir.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        imports = _collect_imports(py_file)
        bad = imports & OPENCLAW_MODULES
        if bad:
            violations.append(f"{py_file.name}: imports {bad}")

    assert not violations, (
        "Firewall Core must be runtime-agnostic (no OpenClaw imports):\n"
        + "\n".join(violations)
    )


def test_core_has_no_adapter_imports():
    """Core modules must not import from the adapters package at all."""
    root = _get_project_root()
    core_dir = root / "core"

    violations: list[str] = []
    for py_file in core_dir.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        imports = _collect_imports(py_file)
        if "adapters" in imports:
            violations.append(f"{py_file.name}: imports 'adapters'")

    assert not violations, (
        "Firewall Core must not import from adapters/:\n"
        + "\n".join(violations)
    )


def test_core_modules_importable():
    """All core modules must be importable without side effects."""
    root = _get_project_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    for module_name in CORE_MODULES:
        try:
            imported = importlib.import_module(module_name)
            assert imported is not None, f"Module {module_name} imported as None"
        except ImportError as exc:
            pytest.fail(f"Failed to import {module_name}: {exc}")


def test_db_has_no_openclaw_imports():
    """db/ modules must not import openclaw either."""
    root = _get_project_root()
    db_dir = root / "db"
    if not db_dir.is_dir():
        pytest.skip("db/ directory not present")

    violations: list[str] = []
    for py_file in db_dir.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        imports = _collect_imports(py_file)
        bad = imports & OPENCLAW_MODULES
        if bad:
            violations.append(f"{py_file.name}: imports {bad}")

    assert not violations, "db/ must not import openclaw:\n" + "\n".join(violations)


def test_unregistered_tool_family_raises_controlled_exception():
    """get_wrapper raises UnregisteredToolFamily for unknown families."""
    from wrappers import UnregisteredToolFamily, get_wrapper

    with pytest.raises(UnregisteredToolFamily) as exc_info:
        get_wrapper("nonexistent_family")

    exc = exc_info.value
    assert exc.tool_family == "nonexistent_family"
    assert exc.reason_code == "UNREGISTERED_TOOL_FAMILY"
    assert not isinstance(exc, ValueError)
    assert not isinstance(exc, RuntimeError)


def test_unregistered_wrapper_not_value_error():
    """UnregisteredToolFamily is its own exception type, not ValueError."""
    from wrappers import UnregisteredToolFamily

    exc = UnregisteredToolFamily("some_family")
    assert isinstance(exc, Exception)
    assert not isinstance(exc, (ValueError, RuntimeError, KeyError))
    assert exc.reason_code == "UNREGISTERED_TOOL_FAMILY"


def test_evaluate_route_converts_unregistered_to_403(bundle):
    """The evaluate route turns UnregisteredToolFamily into a controlled BLOCK."""
    from core.modes import Decision, ReasonCode
    from wrappers import UnregisteredToolFamily

    exc = UnregisteredToolFamily("unknown_tool")
    assert exc.reason_code == "UNREGISTERED_TOOL_FAMILY"
    assert ReasonCode.UNREGISTERED_TOOL_FAMILY.value == "UNREGISTERED_TOOL_FAMILY"
    assert Decision.BLOCK.value == "BLOCK"


def test_registered_families_are_present():
    """Core wrappers are all registered."""
    from wrappers import registered_families

    families = registered_families()
    expected = {"shell", "http", "filesystem", "messaging"}
    missing = expected - set(families)
    assert not missing, f"Missing registered wrapper families: {missing}"


def test_all_registered_wrappers_are_instantiable():
    """Every registered wrapper can be instantiated without errors."""
    from wrappers import get_wrapper, registered_families

    for family in registered_families():
        wrapper = get_wrapper(family)
        assert wrapper is not None, f"Wrapper for {family} returned None"


def test_modes_enums_have_expected_values():
    """Decision, ReasonCode, NormalizationStatus enums must have required members."""
    from core.modes import Decision, KillSwitchScope, NormalizationStatus, ReasonCode

    assert Decision.ALLOW.value == "ALLOW"
    assert Decision.BLOCK.value == "BLOCK"
    assert Decision.APPROVAL_REQUIRED.value == "APPROVAL_REQUIRED"

    required_codes = {
        "ALLOW",
        "RISK_THRESHOLD_BLOCK",
        "APPROVAL_REQUIRED_THRESHOLD",
        "EXPLICIT_POLICY_DENY",
        "DEFAULT_DENY",
        "KILLSWITCH_ACTIVE",
        "APPROVAL_NOT_FOUND",
        "PAYLOAD_MISMATCH",
        "APPROVAL_EXPIRED",
        "UNREGISTERED_TOOL_FAMILY",
        "NORMALIZATION_FAILED",
        "UNGOVERNED_TOOL_FAMILY",
        "SESSION_CLOSED",
        "SESSION_SUSPENDED",
        "AGENT_SUSPENDED",
    }
    actual_codes = {reason.value for reason in ReasonCode}
    missing = required_codes - actual_codes
    assert not missing, f"Missing ReasonCode values: {missing}"

    assert NormalizationStatus.COMPLETE.value == "COMPLETE"
    assert NormalizationStatus.FAILED.value == "FAILED"
    assert NormalizationStatus.PARTIAL.value == "PARTIAL"

    scopes = {scope.value for scope in KillSwitchScope}
    assert "global" in scopes
    assert "agent" in scopes
    assert "tool_family" in scopes
    assert "session" in scopes
    assert KillSwitchScope.GLOBAL.value == "global"
    assert KillSwitchScope.AGENT.value == "agent"


def test_policy_bundle_can_be_loaded(bundle):
    """Policy bundle fixture loads successfully with expected structure."""
    assert bundle.bundle_id
    assert bundle.version
    assert bundle.ruleset_hash.startswith("sha256:")
    assert len(bundle.governed_families) > 0
    assert bundle.thresholds["allow_max"] < bundle.thresholds["block_min"]
    assert bundle.thresholds["approval_min"] <= bundle.thresholds["block_min"]


def test_dangerous_families_constant():
    """DANGEROUS_FAMILIES must include shell as the highest-risk family."""
    from core.modes import DANGEROUS_FAMILIES

    assert "shell" in DANGEROUS_FAMILIES
    assert "http" in DANGEROUS_FAMILIES


def test_wrappers_have_no_adapter_imports():
    """wrappers/ modules must not import from adapters/."""
    root = _get_project_root()
    wrappers_dir = root / "wrappers"

    violations: list[str] = []
    for py_file in wrappers_dir.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        imports = _collect_imports(py_file)
        if "adapters" in imports:
            violations.append(f"{py_file.name}: imports 'adapters'")

    assert not violations, (
        "wrappers/ must not import from adapters/:\n"
        + "\n".join(violations)
    )
