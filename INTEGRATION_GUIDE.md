# AirDrop-Class Background Transfer - Integration Guide

## Quick Start

This guide shows you how to integrate the AirDrop-class background transfer system into your native UI shells.

## 1. Rust Core Already Updated ✅

The Rust core now emits `TransferStateChanged` events:
- `PREPARING` → Start background service
- `IN_PROGRESS` → Update progress notification  
- `FINISHED/FAILED/CANCELLED` → Stop background service

## 2. Platform Integration

### Android (Kotlin)

**Add to your Activity:**

```kotlin
class MainActivity : AppCompatActivity() {
    private val coroutineScope = CoroutineScope(Dispatchers.Main + Job())
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Start polling Rust events
        startRustEventPoller()
    }
    
    private fun startRustEventPoller() {
        coroutineScope.launch {
            while (isActive) {
                val eventBytes = FlatDropCore.hubPollEvent()
                
                if (eventBytes.isNotEmpty()) {
                    val rustEvent = RustEvent.parseFrom(eventBytes)
                    
                    // Handle background transfer states
                    if (rustEvent.eventCase == RustEvent.EventCase.TRANSFER_STATE_CHANGED) {
                        BackgroundTransferManager.handleTransferStateChange(
                            this@MainActivity,
                            rustEvent.transferStateChanged
                        )
                    }
                }
                
                delay(100) // Poll every 100ms
            }
        }
    }
}
```

### iOS (Swift)

**Add to your ViewController:**

```swift
class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Start polling Rust events
        BackgroundTransferManager.shared.pollRustEvents()
    }
}
```

**Add to AppDelegate.swift:**

```swift
func application(_ application: UIApplication,
                 handleEventsForBackgroundURLSession identifier: String,
                 completionHandler: @escaping () -> Void) {
    BackgroundTransferManager.shared.handleEventsForBackgroundURLSession(
        identifier: identifier,
        completionHandler: completionHandler
    )
}
```

### HarmonyOS (ArkTS)

**Add to your EntryAbility:**

```typescript
import { BackgroundTransferManager } from '../background/BackgroundTransferManager';

@Entry
@Component
struct TransferPage {
  aboutToAppear() {
    // Initialize background transfer manager
    const bgManager = BackgroundTransferManager.getInstance();
    // It automatically polls Rust events
  }
}
```

### Desktop (Rust)

**Add to your main.rs:**

```rust
use flatdrop::background::DesktopSleepInhibitor;

#[tokio::main]
async fn main() -> Result<()> {
    let hub = FlatDropHub::new(config_bytes).await?;
    let mut inhibitor = DesktopSleepInhibitor::new();
    
    // Poll events
    loop {
        let event_bytes = hub.poll_event().await?;
        
        if !event_bytes.is_empty() {
            let rust_event = RustEvent::decode(&*event_bytes)?;
            
            if let Some(rust_event::Event::TransferStateChanged(state)) = rust_event.event {
                inhibitor.handle_transfer_state_change(&state);
            }
        }
        
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
```

## 3. Sending Files (Same for All Platforms)

```kotlin
// Android example - same protobuf for all platforms
fun sendFile(filePath: String, targetDeviceId: String) {
    val sendCommand = SendFileRequest.newBuilder()
        .setFilePath(filePath)
        .setTargetDeviceId(targetDeviceId)
        .build()
    
    val uiCommand = UiCommand.newBuilder()
        .setSendFile(sendCommand)
        .build()
    
    // Send to Rust - background service starts automatically
    val result = FlatDropCore.hubSendCommand(uiCommand.toByteArray())
}
```

## 4. What Happens Next?

When you call `hubSendCommand` with a file transfer:

1. **Rust Core** emits `TransferStateChanged { state: PREPARING }`
2. **Native Shell** receives event → Starts background service/task
3. **Rust Core** emits `TransferStateChanged { state: IN_PROGRESS, progress: 0.25 }`
4. **Native Shell** updates notification (25% complete)
5. **Rust Core** emits `TransferStateChanged { state: IN_PROGRESS, progress: 0.50 }`
6. **Native Shell** updates notification (50% complete)
7. ... continues until 100%
8. **Rust Core** emits `TransferStateChanged { state: FINISHED }`
9. **Native Shell** stops background service → Shows completion notification

## 5. Testing

### Test Background Transfer

```bash
# 1. Start the app
# 2. Select a large file (100MB+)
# 3. Start sending to another device
# 4. Immediately background the app (home button)
# 5. Wait for completion
# 6. Check notification - should show progress and completion
```

### Expected Behavior

**Android:**
- Persistent notification shows "FlatDrop Transfer" with progress
- Notification stays even when app is backgrounded
- Completion notification appears when done

**iOS:**
- No immediate notification (iOS manages background tasks internally)
- Transfer continues even if app is suspended
- Completion notification when app wakes

**HarmonyOS:**
- System notification shows transfer progress
- Notification stays during continuous task
- Completion notification when done

**Desktop:**
- No notification (sleep inhibition only)
- Screen can sleep but transfer continues
- File appears in download folder when complete

## 6. Common Issues

### Android: Notification doesn't show
```kotlin
// Make sure you call createNotificationChannel() in service onCreate()
override fun onCreate() {
    super.onCreate()
    createNotificationChannel()  // ← Don't forget this!
}
```

### iOS: Transfer pauses when backgrounded
```swift
// Make sure you handle background URL session events
func application(_ application: UIApplication,
                 handleEventsForBackgroundURLSession identifier: String,
                 completionHandler: @escaping () -> Void) {
    // ← This MUST be implemented
}
```

### HarmonyOS: Continuous task fails
```json
// Make sure permissions are in module.json5
{
  "requestPermissions": [
    {
      "name": "ohos.permission.KEEP_BACKGROUND_RUNNING"
    }
  ]
}
```

### Desktop: System sleeps during transfer
```rust
// Make sure DesktopSleepInhibitor is in scope for entire transfer
let mut inhibitor = DesktopSleepInhibitor::new();  // ← Keep this alive!
```

## 7. Files Overview

```
FlatDrop/
├── proto/messages.proto              ← TransferStateChanged added
├── native/hub/src/hub.rs             ← Emits lifecycle events
├── native/hub/src/lib.rs             ← FFI exports
│
├── android/
│   └── app/src/main/java/com/flatdrop/background/
│       ├── TransferForegroundService.kt    ← Foreground service
│       └── BackgroundTransferManager.kt    ← Helper
│
├── ios/FlatDrop/Background/
│   └── BackgroundTransferManager.swift     ← URLSession background
│
├── harmonyos/entry/src/main/ets/background/
│   └── BackgroundTransferManager.ets       ← Continuous task
│
└── desktop/src/background/
    └── sleep_inhibitor.rs                  ← Sleep inhibition
```

## That's It! 🎉

Your FlatDrop app now has AirDrop-class background transfers:
- ✅ Transfers continue when app is backgrounded
- ✅ Works on all platforms (Android, iOS, HarmonyOS, Desktop)
- ✅ Uses official OS APIs (no hacks)
- ✅ Progress notifications visible to user
- ✅ Minimal battery impact

The key insight: **Rust just emits state, native shells handle OS policies.**
