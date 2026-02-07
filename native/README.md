# Rust Crates

This folder contains the core Rust logic for FlatDrop. The entry point is the `hub` library crate. This crate is compiled as a static/dynamic library and integrated into native platform shells (Android/iOS) via UniFFI.

- Do NOT change the name of the `hub` crate. Build scripts and FFI bindings expect the entry library crate to be located at `native/hub`.
- You CAN name crates other than `hub` as you want.
