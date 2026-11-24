from __future__ import annotations

import dataclasses
import itertools

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from agent_warrant import scope as scope_module
from agent_warrant.canonical import MAX_SAFE_INTEGER
from agent_warrant.scope import (
    MAX_ENTRIES,
    MAX_PERMISSIONS,
    MAX_TOTAL_ENTRIES,
    CallRefusal,
    Permission,
    check_call,
    entry_covers,
    permissions_narrow,
    permissions_of,
    scope_narrows,
    scope_version,
    validate_entry,
    validate_scope,
    validate_scope_v1,
)


def scope(tools=(), resources=(), cost=10):
    return {"tools": list(tools), "resources": list(resources), "max_cost_per_call": cost}


def permission(tools=("read",), resources=("r",), cost=10):
    return {"tools": list(tools), "resources": list(resources), "max_cost_per_call": cost}


def scope_v2(*items):
    return {"permissions": list(items)}


def allows(value, tool, resource):
    try:
        view = permissions_of(value)
    except ValueError:
        return False
    return check_call(view, tool, resource, 0) is None


@pytest.mark.parametrize(
    "entry",
    ["deploy.prod", "deploy.*", "a:*", "a/*", "a_*", "a-*", "svc/prod/db", "x"],
)
def test_valid_entries(entry):
    assert validate_entry(entry) is None


@pytest.mark.parametrize(
    "entry",
    [
        "*",
        "",
        "deploy*",
        "a.*.b",
        "a*b",
        "**",
        "a.**",
        "has space",
        "tab\t",
        "café",
        "new\nline",
        "a\x00b",
        5,
        None,
        "x" * 129,
    ],
)
def test_invalid_entries(entry):
    assert validate_entry(entry) is not None


def test_prefix_pattern_must_end_at_separator():
    assert validate_entry("deploy*") is not None
    assert validate_entry("deploy.*") is None


@pytest.mark.parametrize(
    "value",
    [
        scope(),
        scope(["a"], ["b"], 0),
        scope(["a.*"], ["r/*"], 5),
    ],
)
def test_valid_scopes(value):
    assert validate_scope_v1(value) is None


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {},
        {"tools": [], "resources": []},
        {"tools": [], "resources": [], "max_cost_per_call": 1, "extra": 1},
        {"tools": "a", "resources": [], "max_cost_per_call": 1},
        {"tools": [], "resources": (), "max_cost_per_call": 1},
        {"tools": ["*"], "resources": [], "max_cost_per_call": 1},
        {"tools": [], "resources": ["deploy*"], "max_cost_per_call": 1},
        {"tools": [], "resources": [], "max_cost_per_call": -1},
        {"tools": [], "resources": [], "max_cost_per_call": True},
        {"tools": [], "resources": [], "max_cost_per_call": 1.5},
        {"tools": [], "resources": [], "max_cost_per_call": 2**53},
        {"tools": ["a"] * (MAX_ENTRIES + 1), "resources": [], "max_cost_per_call": 1},
    ],
)
def test_invalid_scopes(value):
    assert validate_scope_v1(value) is not None


def test_exact_entry_covers_only_itself():
    s = scope(["read"], ["r"])
    assert allows(s, "read", "r")
    assert not allows(s, "read2", "r")
    assert not allows(s, "read", "r2")


def test_prefix_covers_children_not_siblings():
    s = scope(["deploy.*"], ["env/*"])
    assert allows(s, "deploy.prod", "env/prod")
    assert allows(s, "deploy.a.b", "env/x/y")
    assert not allows(s, "deployx", "env/prod")
    assert not allows(s, "deploy", "env/prod")
    assert not allows(s, "deploy.prod", "envx")


def test_deploy_star_without_separator_is_refused_not_matched():
    assert not allows({"tools": ["deploy*"], "resources": ["r"], "max_cost_per_call": 1}, "deploy_prod", "r")


def test_empty_lists_cover_nothing():
    assert not allows(scope(), "a", "b")
    assert not allows(scope(["a"], []), "a", "b")


@pytest.mark.parametrize("tool", ["*", "a.*", "", "a b", "café"])
def test_non_concrete_or_invalid_query_ids_are_not_covered(tool):
    assert not allows(scope(["a.*", "*x"], ["r"]), tool, "r")


def test_invalid_scope_covers_nothing():
    assert not allows({"tools": ["*"], "resources": ["*"], "max_cost_per_call": 1}, "a", "b")


def test_narrows_identical_and_subset():
    parent = scope(["a", "b.*"], ["r/*"], 10)
    assert scope_narrows(parent, parent)
    assert scope_narrows(parent, scope(["a", "b.x", "b.y.*"], ["r/s", "r/s/*"], 5))
    assert scope_narrows(parent, scope([], [], 0))


def test_narrows_refuses_wider_cost():
    assert not scope_narrows(scope(["a"], ["r"], 5), scope(["a"], ["r"], 6))


def test_narrows_refuses_new_entries():
    assert not scope_narrows(scope(["a"], ["r"]), scope(["a", "b"], ["r"]))
    assert not scope_narrows(scope(["a"], ["r"]), scope(["a"], ["r", "s"]))


def test_exact_parent_cannot_be_extended_by_prefix_child():
    assert not scope_narrows(scope(["deploy.prod"], ["r"]), scope(["deploy.*"], ["r"]))


def test_prefix_child_must_extend_parent_prefix():
    parent = scope(["deploy.prod.*"], ["r"])
    assert scope_narrows(parent, scope(["deploy.prod.eu.*"], ["r"]))
    assert not scope_narrows(parent, scope(["deploy.*"], ["r"]))
    assert not scope_narrows(parent, scope(["deploy.pro.*"], ["r"]))


def test_narrowing_does_not_cross_tools_and_resources():
    assert not scope_narrows(scope(["a"], ["b"]), scope(["b"], ["a"]))


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        (None, scope()),
        (scope(), None),
        (scope(), {"tools": ["*"], "resources": [], "max_cost_per_call": 0}),
        ({"tools": ["*"], "resources": ["*"], "max_cost_per_call": 9}, scope(["a"], ["b"], 1)),
        (scope(["a"], ["b"]), {"tools": ["a"], "resources": ["b"]}),
    ],
)
def test_malformed_shape_is_not_narrowing(parent, child):
    assert not scope_narrows(parent, child)


ALPHABET = "ab.:/_-"
concrete_ids = st.text(alphabet="ab.:/_-", min_size=1, max_size=6)
prefixes = st.builds(
    lambda stem, separator: stem + separator + "*",
    st.text(alphabet="ab.:/_-", min_size=0, max_size=4),
    st.sampled_from(list(".:/_-")),
)
entries = st.one_of(concrete_ids, prefixes).filter(lambda entry: validate_entry(entry) is None)
scopes = st.builds(
    lambda tools, resources, cost: {"tools": tools, "resources": resources, "max_cost_per_call": cost},
    st.lists(entries, max_size=4),
    st.lists(entries, max_size=4),
    st.integers(min_value=0, max_value=10),
)


@given(parent=scopes, child=scopes, tool=concrete_ids, resource=concrete_ids)
def test_narrowing_never_widens(parent, child, tool, resource):
    if scope_narrows(parent, child) and allows(child, tool, resource):
        assert allows(parent, tool, resource)


@given(parent=scopes)
def test_scope_narrows_itself(parent):
    assert scope_narrows(parent, parent)


def extend(entry, suffix, keep_pattern):
    if not entry.endswith("*"):
        return entry
    stem = entry[:-1] + suffix
    return stem + "*" if keep_pattern and stem[-1] in ".:/_-" else stem


@given(
    parent=scopes,
    suffix=st.text(alphabet="ab.:/_-", max_size=3),
    keep_pattern=st.booleans(),
    tool=concrete_ids,
    resource=concrete_ids,
)
def test_derived_children_narrow_and_never_widen(parent, suffix, keep_pattern, tool, resource):
    child = {
        "tools": [extend(entry, suffix, keep_pattern) for entry in parent["tools"]],
        "resources": [extend(entry, suffix, keep_pattern) for entry in parent["resources"]],
        "max_cost_per_call": parent["max_cost_per_call"],
    }
    assume(validate_scope_v1(child) is None)
    assert scope_narrows(parent, child)
    if allows(child, tool, resource):
        assert allows(parent, tool, resource)


SMALL = "a.:"
small_ids = st.text(alphabet=SMALL, min_size=1, max_size=4)
small_entries = st.one_of(
    small_ids,
    st.builds(
        lambda stem, separator: stem + separator + "*", st.text(alphabet=SMALL, max_size=3), st.sampled_from([".", ":"])
    ),
)
small_scopes = st.builds(
    lambda tools: {"tools": tools, "resources": ["r"], "max_cost_per_call": 1},
    st.lists(small_entries, max_size=3),
)
ALL_SMALL_IDS = ["".join(chars) for length in range(1, 5) for chars in itertools.product(SMALL, repeat=length)]


@given(parent=small_scopes, child=small_scopes)
def test_narrowing_never_widens_over_every_small_id(parent, child):
    if scope_narrows(parent, child):
        widened = [i for i in ALL_SMALL_IDS if allows(child, i, "r") and not allows(parent, i, "r")]
        assert widened == []


@pytest.mark.parametrize(
    "entry",
    [
        "env/prod/../secret",
        "..",
        ".",
        "env/..",
        "env/./prod",
        "../env",
        "env//prod",
        "/env",
        "env/prod/",
        "env/../*",
        "env/./*",
        "env//*",
        "/*",
        "//*",
    ],
)
def test_path_traversal_and_empty_segments_are_refused(entry):
    assert validate_entry(entry) is not None


@pytest.mark.parametrize("entry", ["env/*", "env/prod/*", "env/prod", "a..b", "env/prod.v1", "a.b/c-d_e", "env/a:b"])
def test_ordinary_slash_paths_are_accepted(entry):
    assert validate_entry(entry) is None


def test_traversal_id_is_never_covered_even_by_a_matching_prefix():
    scope_with_prefix = scope(["read"], ["env/prod/*"])
    assert allows(scope_with_prefix, "read", "env/prod/db")
    assert not allows(scope_with_prefix, "read", "env/prod/../secret")
    assert not allows(scope(["read"], ["env/*"]), "read", "env/../secret")


def test_scope_with_a_traversal_entry_is_invalid():
    assert validate_scope_v1(scope(["read"], ["env/../secret"])) is not None
    assert not scope_narrows(scope(["read"], ["env/*"]), scope(["read"], ["env/../secret"]))


def test_ids_are_opaque_percent_escapes_are_not_resolved():
    assert validate_entry("env/%2e%2e/secret") is None
    assert allows(scope(["read"], ["env/prod/*"]), "read", "env/prod/%2e%2e/secret")


def test_scope_version_by_keys():
    assert scope_version(scope_v2(permission())) == 2
    assert scope_version(scope(["a"], ["b"])) == 1


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {},
        {"permissions": [], "tools": []},
        {"tools": [], "resources": []},
        {"grants": []},
        {"permissions": [], "tools": [], "resources": [], "max_cost_per_call": 1},
    ],
)
def test_scope_version_refuses_unknown_shapes(value):
    with pytest.raises(ValueError):
        scope_version(value)


@pytest.mark.parametrize(
    "value",
    [
        scope_v2(permission()),
        scope_v2(*[permission([f"t{i}"], [f"r{i}"]) for i in range(MAX_PERMISSIONS)]),
        scope_v2(permission([f"t{i}" for i in range(32)], [f"r{i}" for i in range(32)])),
        scope_v2(permission(["read"], ["notes/*"]), permission(["read"], ["todo"])),
        scope_v2(permission(cost=0)),
        scope_v2(permission(cost=MAX_SAFE_INTEGER)),
        scope_v2(permission(["deploy.*"], ["env/*"])),
    ],
)
def test_valid_v2_scopes(value):
    assert validate_scope(value) is None


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (None, "scope must be an object"),
        ([], "scope must be an object"),
        ({}, "scope keys must be exactly ['permissions']"),
        (scope(["a"], ["b"]), "scope keys must be exactly ['permissions']"),
        ({"permissions": [], "extra": 1}, "scope keys must be exactly ['permissions']"),
        ({"permissions": {}}, "permissions must be a list"),
        ({"permissions": ()}, "permissions must be a list"),
        (scope_v2(), "permissions must not be empty"),
        (
            scope_v2(*[permission([f"t{i}"], [f"r{i}"]) for i in range(MAX_PERMISSIONS + 1)]),
            f"permissions has more than {MAX_PERMISSIONS} entries",
        ),
        (
            scope_v2(permission([f"t{i}" for i in range(32)], [f"r{i}" for i in range(33)])),
            f"permissions have more than {MAX_TOTAL_ENTRIES} tool and resource entries in total",
        ),
        (
            scope_v2(*[permission([f"t{i}", f"u{i}"], [f"r{i}", f"s{i}", "x"]) for i in range(13)]),
            f"permissions have more than {MAX_TOTAL_ENTRIES} tool and resource entries in total",
        ),
        (scope_v2(None), "permissions[0]: permission must be an object"),
        (scope_v2(["read"]), "permissions[0]: permission must be an object"),
        (scope_v2(permission(), {"tools": ["a"], "resources": ["b"]}), "permissions[1]: permission keys must be"),
        (scope_v2({**permission(), "extra": 1}), "permissions[0]: permission keys must be"),
        (scope_v2(permission([], ["r"])), "permissions[0]: tools must not be empty"),
        (scope_v2(permission(["a"], [])), "permissions[0]: resources must not be empty"),
        (scope_v2({"tools": "a", "resources": ["r"], "max_cost_per_call": 1}), "permissions[0]: tools must be a list"),
        (
            scope_v2({"tools": ["a"], "resources": ("r",), "max_cost_per_call": 1}),
            "permissions[0]: resources must be a list",
        ),
        (scope_v2(permission(["*"])), "permissions[0]: tools: prefix pattern"),
        (scope_v2(permission(["a"], ["env/../secret"])), "permissions[0]: resources: `.` and `..`"),
        (scope_v2(permission(["a", "a"])), "permissions[0]: tools has duplicate entries"),
        (scope_v2(permission(["a"], ["r", "s", "r"])), "permissions[0]: resources has duplicate entries"),
        (scope_v2(permission(), permission()), "permissions[1]: duplicate permission"),
        (scope_v2(permission(cost=-1)), "permissions[0]: max_cost_per_call must be an integer"),
        (scope_v2(permission(cost=MAX_SAFE_INTEGER + 1)), "permissions[0]: max_cost_per_call must be an integer"),
        (scope_v2(permission(cost=True)), "permissions[0]: max_cost_per_call must be an integer"),
        (scope_v2(permission(cost=1.0)), "permissions[0]: max_cost_per_call must be an integer"),
        (scope_v2(permission(cost=None)), "permissions[0]: max_cost_per_call must be an integer"),
    ],
)
def test_invalid_v2_scopes(value, reason):
    refusal = validate_scope(value)
    assert refusal is not None
    assert refusal.startswith(reason)


def test_total_entry_bound_counts_tools_and_resources_across_permissions():
    at_bound = scope_v2(*[permission([f"t{i}", f"u{i}"], [f"r{i}", f"s{i}"]) for i in range(MAX_PERMISSIONS)])
    assert validate_scope(at_bound) is None
    over = scope_v2(*[permission([f"t{i}", f"u{i}"], [f"r{i}", f"s{i}"]) for i in range(MAX_PERMISSIONS - 1)])
    over["permissions"].append(permission(["w", "x", "y", "z"], ["r"]))
    assert validate_scope(over) == f"permissions have more than {MAX_TOTAL_ENTRIES} tool and resource entries in total"


def test_v1_scope_is_not_a_valid_v2_scope_and_v2_is_not_a_valid_v1_scope():
    assert validate_scope(scope(["a"], ["b"])) is not None
    assert validate_scope_v1(scope_v2(permission())) is not None


def test_permissions_of_v1_is_one_permission():
    assert permissions_of(scope(["a", "b.*"], ["r/*"], 7)) == (Permission(("a", "b.*"), ("r/*",), 7),)


def test_permissions_of_v1_keeps_empty_lists_and_more_than_64_entries():
    wide = scope([f"t{i}" for i in range(MAX_ENTRIES)], [f"r{i}" for i in range(MAX_ENTRIES)], 1)
    (only,) = permissions_of(wide)
    assert len(only.tools) + len(only.resources) == 2 * MAX_ENTRIES
    assert permissions_of(scope()) == (Permission((), (), 10),)


def test_permissions_of_v2_is_one_permission_per_item_in_order():
    value = scope_v2(permission(["read"], ["notes/*"], 1), permission(["write"], ["todo"], 2))
    assert permissions_of(value) == (
        Permission(("read",), ("notes/*",), 1),
        Permission(("write",), ("todo",), 2),
    )


@pytest.mark.parametrize(
    "value",
    [None, {}, scope_v2(), scope_v2(permission(["*"])), scope(["*"], ["r"]), {"grants": []}],
)
def test_permissions_of_refuses_invalid_scopes(value):
    with pytest.raises(ValueError):
        permissions_of(value)


def test_permissions_view_is_immutable_and_detached_from_the_raw_dict():
    raw = scope_v2(permission(["read"], ["notes/*"], 3))
    view = permissions_of(raw)
    raw["permissions"][0]["tools"].append("write")
    raw["permissions"].append(permission(["write"], ["todo"]))
    assert view == (Permission(("read",), ("notes/*",), 3),)
    assert isinstance(view, tuple)
    assert isinstance(view[0].tools, tuple)
    assert isinstance(view[0].resources, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        view[0].max_cost_per_call = 99


def test_permission_coerces_lists_to_tuples():
    built = Permission(["read"], ["r"], 1)
    assert built.tools == ("read",)
    assert built.resources == ("r",)


@pytest.mark.parametrize(
    ("tools", "resources", "cost", "error"),
    [
        ("read", ("r",), 1, TypeError),
        (("read",), "r", 1, TypeError),
        (("*",), ("r",), 1, ValueError),
        (("read",), ("env/../x",), 1, ValueError),
        (("read",), (5,), 1, ValueError),
        (("read",), ("r",), -1, ValueError),
        (("read",), ("r",), MAX_SAFE_INTEGER + 1, ValueError),
        (("read",), ("r",), True, ValueError),
        (("read",), ("r",), 1.0, ValueError),
    ],
)
def test_permission_refuses_invalid_fields(tools, resources, cost, error):
    with pytest.raises(error):
        Permission(tools, resources, cost)


PAIRED = (
    Permission(("read_note",), ("notes/*",), 5),
    Permission(("write_note",), ("todo",), 2),
)


def test_call_refusal_values():
    assert CallRefusal.OUT_OF_SCOPE.value == "out_of_scope"
    assert CallRefusal.COST_OVER_CALL_CAP.value == "cost_over_call_cap"


def test_check_call_allows_a_pair_one_permission_covers():
    assert check_call(PAIRED, "read_note", "notes/a", 5) is None
    assert check_call(PAIRED, "write_note", "todo", 0) is None


def test_check_call_refuses_a_pair_split_across_permissions():
    assert check_call(PAIRED, "write_note", "notes/a", 0) is CallRefusal.OUT_OF_SCOPE
    assert check_call(PAIRED, "read_note", "todo", 0) is CallRefusal.OUT_OF_SCOPE


def test_check_call_refuses_cost_over_the_covering_permission_cap():
    assert check_call(PAIRED, "read_note", "notes/a", 6) is CallRefusal.COST_OVER_CALL_CAP
    assert check_call(PAIRED, "write_note", "todo", 3) is CallRefusal.COST_OVER_CALL_CAP


def test_check_call_uses_the_cap_of_a_covering_permission_only():
    permissions = (Permission(("read",), ("cheap",), 1), Permission(("write",), ("cheap",), 100))
    assert check_call(permissions, "read", "cheap", 2) is CallRefusal.COST_OVER_CALL_CAP


def test_check_call_allows_when_any_covering_permission_has_the_cap_in_any_order():
    low = Permission(("read",), ("r/*",), 1)
    high = Permission(("read",), ("r/x",), 9)
    assert check_call((low, high), "read", "r/x", 9) is None
    assert check_call((high, low), "read", "r/x", 9) is None
    assert check_call((low, high), "read", "r/y", 9) is CallRefusal.COST_OVER_CALL_CAP


def test_check_call_with_no_permissions_is_out_of_scope():
    assert check_call((), "read", "r", 0) is CallRefusal.OUT_OF_SCOPE


def test_check_call_on_a_v1_view_pairs_freely():
    view = permissions_of(scope(["read", "write"], ["notes", "payroll"], 3))
    assert check_call(view, "write", "payroll", 3) is None
    assert check_call(view, "write", "payroll", 4) is CallRefusal.COST_OVER_CALL_CAP


@pytest.mark.parametrize(
    ("tool", "resource"),
    [
        ("read_note", "notes/../payroll"),
        ("read_note", "notes/./a"),
        ("read_note", "notes//a"),
        ("read_note", "notes/*"),
        ("read_note", "*"),
        ("read_note", ""),
        ("*", "notes/a"),
        ("read_*", "notes/a"),
        ("", "notes/a"),
        ("read note", "notes/a"),
        (None, "notes/a"),
        ("read_note", 5),
    ],
)
def test_check_call_refuses_non_concrete_or_invalid_values(tool, resource):
    permissions = (Permission(("read_*", "read_note"), ("notes/*", "x"), 5),)
    assert check_call(permissions, tool, resource, 0) is CallRefusal.OUT_OF_SCOPE


@pytest.mark.parametrize("cost", [True, False, 1.0, "1", None])
def test_check_call_refuses_a_non_integer_cost(cost):
    with pytest.raises(TypeError):
        check_call(PAIRED, "read_note", "notes/a", cost)


@pytest.mark.parametrize("cost", [-1, MAX_SAFE_INTEGER + 1])
def test_check_call_refuses_a_cost_out_of_range(cost):
    with pytest.raises(ValueError):
        check_call(PAIRED, "read_note", "notes/a", cost)


def test_check_call_accepts_the_largest_cost():
    permissions = (Permission(("read",), ("r",), MAX_SAFE_INTEGER),)
    assert check_call(permissions, "read", "r", MAX_SAFE_INTEGER) is None


@pytest.mark.parametrize(
    "permissions",
    [
        scope_v2(permission()),
        [Permission(("read",), ("r",), 1)],
        (permission(),),
        None,
    ],
)
def test_check_call_requires_a_tuple_of_permissions(permissions):
    with pytest.raises(TypeError):
        check_call(permissions, "read", "r", 0)


def test_permission_covers_pairs_its_own_tools_and_resources():
    item = Permission(("read", "deploy.*"), ("env/*", "todo"), 1)
    assert item.covers("read", "todo")
    assert item.covers("deploy.prod", "env/eu/db")
    assert not item.covers("deployx", "todo")
    assert not item.covers("read", "envx")
    assert not item.covers("read", "env/../secret")
    assert not item.covers("deploy.*", "todo")


def test_permission_from_v1_with_empty_lists_covers_nothing():
    assert not Permission((), ("r",), 1).covers("read", "r")
    assert not Permission(("read",), (), 1).covers("read", "r")


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("read", "read", True),
        ("read", "read2", False),
        ("deploy.*", "deploy.prod", True),
        ("deploy.*", "deploy.", True),
        ("deploy.*", "deployx", False),
        ("deploy.*", "deploy.*", True),
        ("env/*", "env/../secret", True),
    ],
)
def test_entry_covers_matches_patterns_without_validating(pattern, value, expected):
    assert entry_covers(pattern, value) is expected


TWO_PAIRS = scope_v2(permission(["read"], ["notes/*"], 5), permission(["write"], ["todo"], 2))


def test_v2_child_inside_one_parent_permission_narrows():
    assert scope_narrows(TWO_PAIRS, TWO_PAIRS)
    assert scope_narrows(TWO_PAIRS, scope_v2(permission(["read"], ["notes/a", "notes/b/*"], 5)))
    assert scope_narrows(TWO_PAIRS, scope_v2(permission(["write"], ["todo"], 0)))
    assert scope_narrows(TWO_PAIRS, scope_v2(permission(["write"], ["todo"], 1), permission(["read"], ["notes/a"], 3)))


def test_v2_child_mixing_two_parent_permissions_is_refused():
    assert not scope_narrows(TWO_PAIRS, scope_v2(permission(["read", "write"], ["todo"], 1)))
    assert not scope_narrows(TWO_PAIRS, scope_v2(permission(["write"], ["notes/a"], 1)))
    assert not scope_narrows(TWO_PAIRS, scope_v2(permission(["read"], ["notes/a", "todo"], 1)))


def test_split_parent_pairs_cannot_be_merged_even_when_every_pair_is_allowed():
    parent = scope_v2(permission(["read"], ["todo"], 1), permission(["read"], ["payroll"], 1))
    assert not scope_narrows(parent, scope_v2(permission(["read"], ["todo", "payroll"], 1)))
    assert scope_narrows(parent, scope_v2(permission(["read"], ["payroll"], 1), permission(["read"], ["todo"], 1)))


def test_v2_child_cap_must_fit_the_containing_parent_permission():
    assert not scope_narrows(TWO_PAIRS, scope_v2(permission(["write"], ["todo"], 3)))
    assert not scope_narrows(TWO_PAIRS, scope_v2(permission(["read"], ["notes/a"], 6)))


def test_child_cap_cannot_borrow_a_higher_cap_from_another_parent_permission():
    parent = scope_v2(permission(["read"], ["cheap"], 1), permission(["read", "write"], ["costly"], 9))
    assert not scope_narrows(parent, scope_v2(permission(["read"], ["cheap"], 9)))
    assert scope_narrows(parent, scope_v2(permission(["read"], ["costly"], 9)))


def test_v1_child_under_v2_parent_is_refused():
    assert not scope_narrows(TWO_PAIRS, scope(["read"], ["notes/a"], 1))
    assert not scope_narrows(TWO_PAIRS, scope([], [], 0))


def test_v2_child_under_v1_parent_narrows_inside_the_single_permission():
    parent = scope(["read", "write"], ["notes/*", "todo"], 5)
    assert scope_narrows(parent, TWO_PAIRS)
    assert not scope_narrows(parent, scope_v2(permission(["delete"], ["todo"], 1)))
    assert not scope_narrows(parent, scope_v2(permission(["read"], ["todo"], 6)))


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        (TWO_PAIRS, scope_v2()),
        (TWO_PAIRS, scope_v2(permission(["read"], ["notes/a"]), permission(["read"], ["notes/a"]))),
        (scope_v2(), scope_v2(permission())),
        (TWO_PAIRS, {"grants": []}),
        ({"grants": []}, TWO_PAIRS),
        (TWO_PAIRS, {**TWO_PAIRS, "tools": []}),
    ],
)
def test_invalid_or_unknown_shapes_do_not_narrow(parent, child):
    assert not scope_narrows(parent, child)


def test_permission_contains():
    parent = Permission(("read", "deploy.*"), ("env/*",), 5)
    assert parent.contains(Permission(("deploy.prod.*",), ("env/eu",), 5))
    assert parent.contains(Permission((), (), 0))
    assert not parent.contains(Permission(("write",), ("env/eu",), 1))
    assert not parent.contains(Permission(("read",), ("envx",), 1))
    assert not parent.contains(Permission(("read",), ("env/eu",), 6))
    assert not Permission(("deploy.prod",), ("r",), 1).contains(Permission(("deploy.*",), ("r",), 1))


v2_permissions = st.builds(
    lambda tools, resources, cost: {"tools": tools, "resources": resources, "max_cost_per_call": cost},
    st.lists(entries, min_size=1, max_size=3, unique=True),
    st.lists(entries, min_size=1, max_size=3, unique=True),
    st.integers(min_value=0, max_value=10),
)
v2_scopes = st.builds(
    lambda items: {"permissions": items},
    st.lists(
        v2_permissions,
        min_size=1,
        max_size=3,
        unique_by=lambda item: (
            tuple(sorted(item["tools"])),
            tuple(sorted(item["resources"])),
            item["max_cost_per_call"],
        ),
    ),
)


@given(parent=v2_scopes, child=v2_scopes, tool=concrete_ids, resource=concrete_ids, cost=st.integers(0, 10))
def test_v2_narrowing_never_widens_a_call(parent, child, tool, resource, cost):
    if scope_narrows(parent, child) and check_call(permissions_of(child), tool, resource, cost) is None:
        assert check_call(permissions_of(parent), tool, resource, cost) is None


@given(parent=v2_scopes)
def test_v2_scope_narrows_itself(parent):
    assert scope_narrows(parent, parent)


def test_covers_is_removed():
    with pytest.raises(ImportError):
        from agent_warrant.scope import covers

        assert covers is None


class AlwaysWithin(int):
    def __le__(self, other):
        return True

    def __ge__(self, other):
        return True

    def __lt__(self, other):
        return True

    def __gt__(self, other):
        return True


class MatchesAnything(str):
    def startswith(self, *args, **kwargs):
        return True

    def __eq__(self, other):
        return True

    def __hash__(self):
        return str.__hash__(self)


SUBCLASS_VIEW = (Permission(("read.*",), ("env/*",), 10),)


def test_check_call_refuses_an_int_subclass_cost():
    with pytest.raises(TypeError, match="cost must be an integer"):
        check_call(SUBCLASS_VIEW, "read.x", "env/x", AlwaysWithin(10**30))


def test_check_call_refuses_str_subclass_ids():
    assert (
        check_call(SUBCLASS_VIEW, MatchesAnything("admin"), MatchesAnything("payroll"), 0) is CallRefusal.OUT_OF_SCOPE
    )
    assert check_call(SUBCLASS_VIEW, MatchesAnything("read.x"), "env/x", 0) is CallRefusal.OUT_OF_SCOPE
    assert check_call(SUBCLASS_VIEW, "read.x", MatchesAnything("env/x"), 0) is CallRefusal.OUT_OF_SCOPE


def test_permission_covers_refuses_str_subclass_ids():
    assert not SUBCLASS_VIEW[0].covers(MatchesAnything("admin"), MatchesAnything("payroll"))


def test_check_call_refuses_a_permission_subclass():
    class CoversEverything(Permission):
        def _matches(self, tool, resource):
            return True

    with pytest.raises(TypeError, match="tuple of Permission"):
        check_call((CoversEverything(("read",), ("r",), 10),), "admin", "payroll", 0)


@pytest.mark.parametrize(
    "tools, resources, cost",
    [
        ((MatchesAnything("read"),), ("r",), 1),
        (("read",), (MatchesAnything("r"),), 1),
        (("read",), ("r",), AlwaysWithin(1)),
    ],
)
def test_permission_refuses_subclassed_fields(tools, resources, cost):
    with pytest.raises(ValueError):
        Permission(tools, resources, cost)


@pytest.mark.parametrize(
    "value",
    [
        scope_v2(permission(tools=[MatchesAnything("read")])),
        scope_v2(permission(resources=[MatchesAnything("r")])),
        scope_v2(permission(cost=AlwaysWithin(1))),
        scope([MatchesAnything("read")], ["r"], 1),
        scope(["read"], ["r"], AlwaysWithin(1)),
    ],
)
def test_validate_scope_refuses_subclassed_entries_and_caps(value):
    validator = validate_scope_v1 if "tools" in value else validate_scope
    assert validator(value) is not None


def test_validate_entry_refuses_a_str_subclass():
    assert validate_entry(MatchesAnything("read")) == "entry must be a non-empty string"


@pytest.fixture
def entry_checks(monkeypatch):
    calls = []
    original = scope_module.validate_entry

    def counting(entry):
        calls.append(entry)
        return original(entry)

    monkeypatch.setattr(scope_module, "validate_entry", counting)
    return calls


def test_validate_scope_refuses_an_oversized_list_before_checking_entries(entry_checks):
    huge = scope_v2(permission(tools=["read"] * 200_000))
    assert validate_scope(huge) == f"permissions have more than {MAX_TOTAL_ENTRIES} tool and resource entries in total"
    assert entry_checks == []


def test_validate_scope_refuses_the_running_total_before_checking_the_next_entries(entry_checks):
    first = permission(tools=[f"t{index}" for index in range(40)], resources=["r"])
    second = permission(tools=[f"u{index}" for index in range(40)], resources=["r"])
    assert validate_scope(scope_v2(first, second)) == (
        f"permissions have more than {MAX_TOTAL_ENTRIES} tool and resource entries in total"
    )
    assert len(entry_checks) == 41


@pytest.mark.parametrize("name", ["tools", "resources"])
def test_permission_refuses_more_than_64_entries_before_checking_them(entry_checks, name):
    lists = {"tools": ("read",), "resources": ("r",)}
    lists[name] = ("x",) * 200_000
    with pytest.raises(ValueError, match=f"{name} has more than {MAX_ENTRIES} entries"):
        Permission(lists["tools"], lists["resources"], 1)
    assert len(entry_checks) <= 1


def test_permission_allows_64_entries_per_list():
    built = Permission(tuple(f"t{index}" for index in range(MAX_ENTRIES)), ("r",), 1)
    assert len(built.tools) == MAX_ENTRIES


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (permission(tools=["read", "write"]), permission(tools=["write", "read"])),
        (permission(tools=["write", "read"]), permission(tools=["read", "write"])),
        (permission(resources=["env/a", "env/b"]), permission(resources=["env/b", "env/a"])),
        (permission(resources=["env/b", "env/a"]), permission(resources=["env/a", "env/b"])),
        (
            permission(tools=["read", "write"], resources=["env/a", "env/b"]),
            permission(tools=["write", "read"], resources=["env/b", "env/a"]),
        ),
    ],
)
def test_validate_scope_refuses_duplicate_permissions_in_any_order(first, second):
    assert validate_scope(scope_v2(first, second)) == "permissions[1]: duplicate permission"


def test_validate_scope_allows_permissions_differing_only_in_cap():
    assert (
        validate_scope(scope_v2(permission(tools=["read", "write"]), permission(tools=["write", "read"], cost=3)))
        is None
    )


def test_permissions_narrow_requires_each_child_permission_inside_one_parent_permission():
    parent = (Permission(("read.*",), ("env/*",), 10), Permission(("admin",), ("payroll",), 1))
    assert permissions_narrow(parent, (Permission(("read.x",), ("env/a",), 10),)) is True
    assert permissions_narrow(parent, (Permission(("admin",), ("payroll",), 1),)) is True
    assert permissions_narrow(parent, ()) is True
    assert permissions_narrow(parent, (Permission(("read.x",), ("payroll",), 1),)) is False
    assert permissions_narrow(parent, (Permission(("admin",), ("payroll",), 2),)) is False


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        ([Permission(("read",), ("r",), 1)], (Permission(("read",), ("r",), 1),)),
        ((Permission(("read",), ("r",), 1),), [Permission(("read",), ("r",), 1)]),
        (({"tools": ["read"], "resources": ["r"], "max_cost_per_call": 1},), ()),
        ((), ("read",)),
    ],
)
def test_permissions_narrow_refuses_anything_but_tuples_of_permission(parent, child):
    with pytest.raises(TypeError, match="must be a tuple of Permission"):
        permissions_narrow(parent, child)
