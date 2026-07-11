#![cfg(all(feature = "async", feature = "blocking"))]

#[test]
fn typed_query_operator_contract() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/trybuild/checked_create_pass.rs");
    tests.compile_fail("tests/trybuild/checked_create_fail_missing_required.rs");
    tests.pass("tests/trybuild/typed_query_pass.rs");
    tests.pass("tests/trybuild/typed_id_borrowed_pass.rs");
    tests.compile_fail("tests/trybuild/typed_query_fail_bool_contains.rs");
    tests.compile_fail("tests/trybuild/typed_id_fail_wrong_resource.rs");
    tests.compile_fail("tests/trybuild/typed_nested_id_fail_wrong_resource.rs");
    tests.compile_fail("tests/trybuild/typed_query_fail_numeric_contains.rs");
    tests.compile_fail("tests/trybuild/typed_query_fail_text_gte.rs");
}
