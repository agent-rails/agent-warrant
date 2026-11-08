from __future__ import annotations

import itertools

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from agent_warrant.scope import MAX_ENTRIES, covers, scope_narrows, validate_entry, validate_scope


def scope(tools=(), resources=(), cost=10):
    return {"tools": list(tools), "resources": list(resources), "max_cost_per_call": cost}


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
    assert validate_scope(value) is None


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
    assert validate_scope(value) is not None


def test_exact_entry_covers_only_itself():
    s = scope(["read"], ["r"])
    assert covers(s, "read", "r")
    assert not covers(s, "read2", "r")
    assert not covers(s, "read", "r2")


def test_prefix_covers_children_not_siblings():
    s = scope(["deploy.*"], ["env/*"])
    assert covers(s, "deploy.prod", "env/prod")
    assert covers(s, "deploy.a.b", "env/x/y")
    assert not covers(s, "deployx", "env/prod")
    assert not covers(s, "deploy", "env/prod")
    assert not covers(s, "deploy.prod", "envx")


def test_deploy_star_without_separator_is_refused_not_matched():
    assert not covers({"tools": ["deploy*"], "resources": ["r"], "max_cost_per_call": 1}, "deploy_prod", "r")


def test_empty_lists_cover_nothing():
    assert not covers(scope(), "a", "b")
    assert not covers(scope(["a"], []), "a", "b")


@pytest.mark.parametrize("tool", ["*", "a.*", "", "a b", "café"])
def test_non_concrete_or_invalid_query_ids_are_not_covered(tool):
    assert not covers(scope(["a.*", "*x"], ["r"]), tool, "r")


def test_invalid_scope_covers_nothing():
    assert not covers({"tools": ["*"], "resources": ["*"], "max_cost_per_call": 1}, "a", "b")


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
    if scope_narrows(parent, child) and covers(child, tool, resource):
        assert covers(parent, tool, resource)


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
    assume(validate_scope(child) is None)
    assert scope_narrows(parent, child)
    if covers(child, tool, resource):
        assert covers(parent, tool, resource)


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
        widened = [i for i in ALL_SMALL_IDS if covers(child, i, "r") and not covers(parent, i, "r")]
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
    assert covers(scope_with_prefix, "read", "env/prod/db")
    assert not covers(scope_with_prefix, "read", "env/prod/../secret")
    assert not covers(scope(["read"], ["env/*"]), "read", "env/../secret")


def test_scope_with_a_traversal_entry_is_invalid():
    assert validate_scope(scope(["read"], ["env/../secret"])) is not None
    assert not scope_narrows(scope(["read"], ["env/*"]), scope(["read"], ["env/../secret"]))


def test_ids_are_opaque_percent_escapes_are_not_resolved():
    assert validate_entry("env/%2e%2e/secret") is None
    assert covers(scope(["read"], ["env/prod/*"]), "read", "env/prod/%2e%2e/secret")
