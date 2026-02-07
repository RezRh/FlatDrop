# FlatDrop

**The Ultra-Fast, Secure, Cross-Platform AirDrop Alternative.** 

FlatDrop is a next-generation local file sharing application built with a **"Rust Core, Native Shell"** architecture. It combines the raw performance and safety of Rust with the premium user experience of native platform UIs (SwiftUI, Jetpack Compose).

Designed for privacy-conscious users and power users who demand speed, security, and reliability.

---

## Key Features

### Zero-Trust Security (E2EE)
State-of-the-art cryptography ensures your files are secure, even on untrusted local networks.
- **End-to-End Encryption**: Every file transfer is encrypted using **XChaCha20-Poly1305** with a unique, ephemeral 32-byte session key.
- **Forward Secrecy**: Keys are negotiated using **X25519** Diffie-Hellman key exchange and destroyed immediately after transfer.
- **Identity Verification**: Devices authenticate via **Ed25519** digital signatures to prevent spoofing.

### Blazing Fast & Resumable
Built on top of [Iroh](https://iroh.computer) and [Tokio](https://tokio.rs).
- **Chunked Streaming**: Files are encrypted and decrypted in 64KB chunks, keeping memory usage low even for multi-gigabyte files.
- **Resumable Transfers**: Interrupted transfers can be resumed byte-for-byte without restarting.
- **Multi-Threaded**: Dynamically scales worker threads based on CPU cores (`num_cpus`).

### Premium "Liquid Glass" UI
Aesthetics matter. FlatDrop features a stunning, platform-native design language.
- **iOS/macOS**: SwiftUI with **Metal shaders** for real-time glass refraction and magnetic physics.
- **Android**: Jetpack Compose with custom **RuntimeShaders** for high-fidelity blur and glow effects.

### Truly Cross-Platform
- **Android**: Native Kotlin app.
- **iOS & macOS**: Native Swift app.
- **Windows & Linux**: Tauri (Rust + Webview) desktop app.
- **HarmonyOS**: ArkTS implementation.

---

## Architecture

FlatDrop uses a **Hub & Spoke** architecture:

1.  **The Hub (Rust Core)**:
    - Located in `native/hub`.
    - Handles all business logic: Discovery (mDNS), Networking (Iroh/Quic), Database (libSQL), and Cryptography.
    - Exposes a high-level API via **UniFFI** to native platforms.
    - Runs an asynchronous **Actor System** to manage state without blocking the UI.

2.  **The Native Shells**:
    - **Android**: Calls Rust via JNA/UniFFI. Renders UI.
    - **Apple**: Calls Rust via C-FFI/UniFFI. Renders UI.
    - **HarmonyOS**: Calls Rust via NAPI (Node-API). Renders UI in ArkTS.
    - **Desktop**: Embeds the Rust core directly.

### Directory Structure

```text
.
├── native/
│   └── hub/          # The Brain (Rust Core)
│       ├── src/
│       │   ├── crypto.rs       # X25519/XChaCha20 implementation
│       │   ├── iroh_engine.rs  # P2P Transfer Engine
│       │   ├── discovery.rs    # mDNS Service Discovery
│       │   └── ...
│       └── Cargo.toml
├── android/          # Android App (Kotlin + Compose)
├── apple/            # iOS & macOS App (Swift + SwiftUI)
├── desktop/          # Windows/Linux App (Tauri)
├── harmonyos/        # HarmonyOS App (ArkTS + NAPI)
├── proto/            # Protobuf Definitions for internal messaging
└── ...
```

---

## Getting Started

### Prerequisites

- **Rust Toolchain**: `rustup update stable`
- **Android Studio**: For Android development (NDK required).
- **Xcode**: For iOS/macOS development.
- **Node.js/Bun**: For the desktop frontend.

### 1. Building the Core (Rust)

Before running any platform app, you must build the shared library.

```bash
cd native/hub
# Run tests to ensure everything is stable
cargo test
# Check compilation
cargo check
```

### 2. Android Setup

1.  Install `cargo-ndk`: `cargo install cargo-ndk`
2.  Add Android targets:
    ```bash
    rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
    ```
3.  Open `android/` in Android Studio.
4.  Sync Gradle (this will automatically build the Rust library via the `build.gradle` tasks).
5.  Run on a device or emulator.

### 3. iOS/macOS Setup

1.  Install `cargo-xcode` (optional but recommended) or `cargo-lipo`.
2.  Add iOS targets:
    ```bash
    rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
    ```
3.  Open `apple/FlatDrop.xcodeproj` in Xcode.
4.  Build & Run.

### 4. HarmonyOS Setup (ArkTS + NAPI)

1.  Add HarmonyOS targets:
    ```bash
    rustup target add aarch64-unknown-linux-ohos armv7-unknown-linux-ohos
    ```
2.  Build the Rust core static library:
    ```bash
    chmod +x build_harmony.sh
    ./build_harmony.sh
    ```
3.  Open `harmonyos/` in **DevEco Studio**.
4.  Sync and build. The NAPI bridge (`libentry.so`) will automatically link with the Rust static library.

---

## Advanced Configuration

The Hub can be configured via environment variables or a config file (protobuffered).

| Variable | Description | Default |
| :--- | :--- | :--- |
| `RUST_LOG` | Logging level (`debug`, `info`, `warn`) | `info` |
| `FLATDROP_NAME` | Custom display name (overrides funny name gen) | Random (e.g., "Cosmic Panda") |

---

## Contributing

We believe in **Overkill Engineering**. If it's worth doing, it's worth doing safely, performantly, and beautifully.

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes (`git commit -m 'Add some amazing feature'`).
4.  Push to the branch (`git push origin feature/amazing-feature`).
5.  Open a Pull Request.

### Development Guidelines
- **Rust**: Run `cargo clippy` and `cargo fmt` before committing.
- **Testing**: Add unit tests for any new core logic.
- **Safety**: No `unsafe` code unless absolutely necessary and documented.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.

---

<p align="center">
  Built with 💕 by the Ontologic Team.
</p>
