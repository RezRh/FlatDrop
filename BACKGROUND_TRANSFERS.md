# FlatDrop: AirDrop-Class Background Transfer Architecture

## Overview

This implementation enables FlatDrop to perform uninterrupted file transfers even when the app is backgrounded or the device is locked. This matches the behavior of Apple's AirDrop.

## Architecture Principle

**Rust is the transfer brain, not the OS negotiator.**

```
┌─────────────────────────────────────────────────────────────┐
│                     Native UI (Kotlin/Swift/ArkTS)         │
│                         ↓ (Receives Signal)                 │
│            TransferStateChanged { State::IN_PROGRESS }      │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                       Rust Core                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Single Signal: TransferStateChanged                   │  │
│  │  - PREPARING → Start background service/task           │  │
│  │  - IN_PROGRESS → Update notification                   │  │
│  │  - FINISHED/FAILED → Stop background service           │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Key Rule:** Rust NEVER starts services, background tasks, or power inhibitors. Rust only emits state. Native code decides how to keep the process alive.

## Platform Implementations

### 1. Android (Kotlin) - Foreground Service

**File:** `android/app/src/main/java/com/flatdrop/background/TransferForegroundService.kt`

**Mechanism:**
- When `TransferStateChanged.State.PREPARING` is received:
  - Start `ForegroundService` with `FOREGROUND_SERVICE_TYPE_DATA_SYNC`
  - Display persistent notification with progress
- When `TransferStateChanged.State.FINISHED` is received:
  - Stop foreground service

**Integration:**
```kotlin
// In your MainActivity or ViewModel
val eventBytes = FlatDropCore.hubPollEvent()
val rustEvent = RustEvent.parseFrom(eventBytes)

if (rustEvent.eventCase == RustEvent.EventCase.TRANSFER_STATE_CHANGED) {
    BackgroundTransferManager.handleTransferStateChange(context, rustEvent.transferStateChanged)
}
```

**AndroidManifest.xml additions:**
```xml
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />

<service
    android:name=".background.TransferForegroundService"
    android:enabled="true"
    android:exported="false"
    android:foregroundServiceType="dataSync" />
```

### 2. iOS (Swift) - URLSession Background Transfer

**File:** `ios/FlatDrop/Background/BackgroundTransferManager.swift`

**Mechanism:**
- When `TransferStateChanged.State.PREPARING` is received:
  - Create `URLSessionConfiguration.background`
  - Request background processing time
  - Register with BGTaskScheduler
- iOS owns the transfer lifecycle even if app is suspended
- Transfer survives screen lock and temporary termination
- On completion: Swift notifies Rust to finalize

**Integration:**
```swift
// In AppDelegate.swift
func application(_ application: UIApplication,
                 handleEventsForBackgroundURLSession identifier: String,
                 completionHandler: @escaping () -> Void) {
    BackgroundTransferManager.shared.handleEventsForBackgroundURLSession(
        identifier: identifier,
        completionHandler: completionHandler
    )
}

// In your ViewController
BackgroundTransferManager.shared.pollRustEvents()
```

**Info.plist additions:**
```xml
<key>BGTaskSchedulerPermittedIdentifiers</key>
<array>
    <string>com.flatdrop.transfer</string>
</array>
<key>UIBackgroundModes</key>
<array>
    <string>fetch</string>
    <string>processing</string>
</array>
```

### 3. HarmonyOS (ArkTS) - Continuous Task

**File:** `harmonyos/entry/src/main/ets/background/BackgroundTransferManager.ets`

**Mechanism:**
- When `TransferStateChanged.State.PREPARING` is received:
  - Request `ContinuousTask` for `DATA_TRANSFER`
  - Show required system notification
- Task remains active for transfer duration
- Rust continues streaming normally

**Integration:**
```typescript
// In your EntryAbility
const bgManager = BackgroundTransferManager.getInstance();
// Automatically handles TransferStateChanged events
```

**module.json5 additions:**
```json
{
  "module": {
    "requestPermissions": [
      {
        "name": "ohos.permission.KEEP_BACKGROUND_RUNNING",
        "reason": "$string:keep_background_reason"
      },
      {
        "name": "ohos.permission.NOTIFICATION_CONTROLLER"
      }
    ]
  }
}
```

### 4. Desktop (Rust) - Sleep Inhibitor

**File:** `desktop/src/background/sleep_inhibitor.rs`

**Mechanism:**
- When `TransferStateChanged.State.IN_PROGRESS` is received:
  - Call platform-specific sleep inhibitor
  - Windows: `SetThreadExecutionState`
  - macOS: `IOPMAssertionCreateWithName`
  - Linux: `systemd-inhibit` or `xdg-screensaver`
- When transfer completes: Release inhibition

**Integration:**
```rust
use flatdrop::background::DesktopSleepInhibitor;

let mut inhibitor = DesktopSleepInhibitor::new();

// In your event loop
while let Some(event) = hub.poll_event() {
    if let Some(RustEvent{ event: Some(transfer_state_changed(state)) }) = event {
        inhibitor.handle_transfer_state_change(&state);
    }
}
```

## Protobuf Message Reference

### TransferStateChanged (Single Signal)

```protobuf
message TransferStateChanged {
  enum State {
    IDLE = 0;
    PREPARING = 1;      // → Start background service
    IN_PROGRESS = 2;    // → Update notification
    PAUSED = 3;
    FINISHED = 4;       // → Stop background service
    FAILED = 5;         // → Stop background service
    CANCELLED = 6;      // → Stop background service
  }
  
  State state = 1;
  string transfer_id = 2;
  string description = 3;
  string file_name = 4;
  uint64 total_bytes = 5;
  uint64 bytes_transferred = 6;
  double progress = 7;
  string error_message = 8;
  TransferDirection direction = 9;
  string platform_handle = 10;  // Optional: platform-specific ID
}
```

## Usage Flow

### Starting a Transfer

1. **UI Layer** sends `SendFileRequest` to Rust:
   ```kotlin
   val command = UiCommand.newBuilder()
       .setSendFile(SendFileRequest.newBuilder()
           .setFilePath("/path/to/file.mp4")
           .setTargetDeviceId("device-123")
       )
       .build()
   
   hubSendCommand(command.toByteArray())
   ```

2. **Rust Core** emits `TransferStateChanged.State.PREPARING`:
   ```rust
   self.emit_transfer_state(TransferStateChanged {
       state: State::Preparing as i32,
       transfer_id: id.clone(),
       description: format!("Preparing to send {}", file_name),
       // ...
   }).await;
   ```

3. **Native Shell** starts background mechanism:
   - **Android:** Start ForegroundService
   - **iOS:** Start URLSession background task
   - **HarmonyOS:** Start ContinuousTask
   - **Desktop:** Inhibit sleep

4. **Rust Core** emits `TransferStateChanged.State.IN_PROGRESS` during transfer

5. **Native Shell** updates notification/progress

6. **Rust Core** emits `TransferStateChanged.State.FINISHED` on completion

7. **Native Shell** stops background mechanism and shows completion notification

## Implementation Checklist

### Android
- [ ] Add permissions to `AndroidManifest.xml`
- [ ] Copy `TransferForegroundService.kt`
- [ ] Copy `BackgroundTransferManager.kt`
- [ ] Call `BackgroundTransferManager.handleTransferStateChange()` from your event loop

### iOS
- [ ] Add `BGTaskSchedulerPermittedIdentifiers` to `Info.plist`
- [ ] Copy `BackgroundTransferManager.swift`
- [ ] Add `handleEventsForBackgroundURLSession` to `AppDelegate.swift`
- [ ] Call `BackgroundTransferManager.shared.pollRustEvents()` on app launch

### HarmonyOS
- [ ] Add permissions to `module.json5`
- [ ] Copy `BackgroundTransferManager.ets`
- [ ] Import and use `BackgroundTransferManager.getInstance()`

### Desktop
- [ ] Enable `desktop` feature in `Cargo.toml`
- [ ] Copy `sleep_inhibitor.rs`
- [ ] Use `DesktopSleepInhibitor` in your main loop

## Testing Background Transfers

### Android
```bash
# Start transfer, then immediately background the app
adb shell am start -n com.flatdrop/.MainActivity
# Send file from another device
# Press home button to background app
# Transfer should continue with notification showing progress
```

### iOS
```bash
# Start transfer in simulator
# Press Shift+Cmd+H to go home
# Transfer should continue in background
# Check Console.app for background activity logs
```

### HarmonyOS
```bash
# Start transfer on device
# Press home button or switch to another app
# Transfer should continue
# Check notification for progress
```

### Desktop
```bash
# Start transfer
# Close laptop lid or let display sleep
# Transfer should continue
# Open laptop - transfer should be complete
```

## Why This Works

1. **Aligns with each OS's intended background model**
   - Android wants you to use ForegroundService
   - iOS wants you to use URLSession background
   - HarmonyOS provides ContinuousTask API
   - Desktop just needs sleep inhibition

2. **Avoids fighting platform policies**
   - No workarounds or hacks
   - Uses official APIs only

3. **Keeps Rust portable and testable**
   - Single `TransferStateChanged` signal
   - No platform-specific code in Rust
   - Easy to unit test

4. **Matches production patterns**
   - AirDrop: iOS manages transfers
   - Tailscale: Native background services
   - RustDesk: Platform-specific background handling

## Troubleshooting

### Android: Service killed immediately
- Ensure `FOREGROUND_SERVICE_TYPE_DATA_SYNC` is set (Android 14+)
- Check notification is showing
- Verify permissions granted

### iOS: Transfer pauses when backgrounded
- Ensure `URLSessionConfiguration.background` is used
- Check `handleEventsForBackgroundURLSession` is implemented
- Verify background modes are enabled in Info.plist

### HarmonyOS: Continuous task fails
- Check `ohos.permission.KEEP_BACKGROUND_RUNNING` is granted
- Ensure notification is published
- Verify background mode is requested

### Desktop: System still sleeps
- Check sleep inhibitor is actually created
- Verify inhibitor is held for duration of transfer
- Try using `keepawake` crate directly

## Performance Impact

- **Android:** ~2MB RAM for foreground service
- **iOS:** Minimal - uses system-managed background tasks
- **HarmonyOS:** Minimal - system manages continuous tasks
- **Desktop:** Negligible - just prevents sleep state changes

Battery impact is minimal because:
- Screen can still sleep
- Only Wi-Fi and CPU are kept awake during active transfer
- Transfers complete quickly with modern Wi-Fi (Wi-Fi 6/7)
