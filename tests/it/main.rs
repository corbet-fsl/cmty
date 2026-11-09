//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`). `tests/support`, `tests/accounting`, `tests/root_board`,
//! `tests/root_issuance` and `tests/fixtures` move with them, so every `#[path = "…"]` and
//! `include_bytes!("fixtures/…")` string stays as it was.
mod accounting;
mod certificates;
mod community;
mod root_board;
mod root_issuance;
mod storage;
mod support;
