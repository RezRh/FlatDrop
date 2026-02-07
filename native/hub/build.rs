use std::io::Result;

fn main() -> Result<()> {
    // Generate Rust code from proto file
    prost_build::compile_protos(&["../../proto/messages.proto"], &["../../proto"])?;

    println!("cargo:rerun-if-changed=../../proto/messages.proto");

    Ok(())
}
