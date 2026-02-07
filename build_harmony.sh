#!/bin/bash
# build_harmony.sh
# Script to cross-compile FlatDrop Hub for HarmonyOS (OpenHarmony)

set -e

# Change to the hub directory
cd "$(dirname "$0")/native/hub"

# Targets for HarmonyOS
# Note: These require the OpenHarmony SDK and specifically the llvm-ar/clang for the toolchain
# You must have the OHOS_SDK environment variable set.
TARGET_AARCH64="aarch64-unknown-linux-ohos"
TARGET_ARMV7="armv7-unknown-linux-ohos"

echo "Building for HarmonyOS..."

# Add targets if missing
rustup target add $TARGET_AARCH64 $TARGET_ARMV7 || true

# Function to build for a specific target
build_target() {
    local target=$1
    local out_dir=$2
    
    echo "Compiling for $target..."
    cargo build --target "$target" --release
    
    echo "Copying to $out_dir..."
    mkdir -p "../../harmonyos/entry/libs/$out_dir"
    cp "target/$target/release/libhub.a" "../../harmonyos/entry/libs/$out_dir/"
}

# In a real environment, you need to set up the CC/AR environment variables for the OHOS Clang.
# Example:
# export CC_aarch64_unknown_linux_ohos=$OHOS_SDK/native/llvm/bin/clang
# export AR_aarch64_unknown_linux_ohos=$OHOS_SDK/native/llvm/bin/llvm-ar

echo "Note: This script assumes your environment is configured for OpenHarmony cross-compilation."
echo "If it fails, please ensure you have the OpenHarmony SDK installed and targets added."

# Build for aarch64 (most common for modern HarmonyOS phones)
build_target "$TARGET_AARCH64" "arm64-v8a"

# Build for armv7
# build_target "$TARGET_ARMV7" "armeabi-v7a"

echo "Build complete. Libraries placed in harmonyos/entry/libs/"
