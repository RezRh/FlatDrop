// BackgroundTransferManager.ets
// HarmonyOS Continuous Task for AirDrop-Class Background Transfers

import { continuousTask } from '@kit.BackgroundTasksKit';
import { notificationManager } from '@kit.NotificationKit';
import { FlatDropCore } from '../core/FlatDropCore';
import { TransferStateChanged, TransferState, TransferDirection } from '../proto/messages';

/**
 * AirDrop-Class Background Transfer for HarmonyOS
 * 
 * Uses Continuous Task API for long-running data transfer operations
 * Guarantees uninterrupted transfers even when app is in background
 */
export class BackgroundTransferManager {
  private static instance: BackgroundTransferManager;
  private activeTransfers: Map<string, TransferState> = new Map();
  private continuousTaskId: number | null = null;
  private notificationId: number = 1001;

  private constructor() {
    this.startRustEventPoller();
  }

  public static getInstance(): BackgroundTransferManager {
    if (!BackgroundTransferManager.instance) {
      BackgroundTransferManager.instance = new BackgroundTransferManager();
    }
    return BackgroundTransferManager.instance;
  }

  /**
   * Handle TransferStateChanged events from Rust
   * This is the single signal that triggers background execution
   */
  public handleTransferStateChange(state: TransferStateChanged): void {
    switch (state.state) {
      case TransferStateChanged.State.PREPARING:
        this.startContinuousTask(state);
        break;

      case TransferStateChanged.State.IN_PROGRESS:
        this.updateNotification(state);
        break;

      case TransferStateChanged.State.FINISHED:
      case TransferStateChanged.State.FAILED:
      case TransferStateChanged.State.CANCELLED:
        this.stopContinuousTask(state);
        break;

      default:
        // IDLE or PAUSED - no action needed
        break;
    }
  }

  /**
   * Start HarmonyOS Continuous Task
   * 
   * Mechanism:
   * 1. Request continuous task for data transfer
   * 2. Show required system notification
   * 3. Task remains active for transfer duration
   * 4. Rust continues streaming normally during task lifetime
   */
  private startContinuousTask(state: TransferStateChanged): void {
    const transferId = state.transferId;

    // Store transfer state
    this.activeTransfers.set(transferId, {
      id: transferId,
      fileName: state.fileName,
      totalBytes: state.totalBytes,
      bytesTransferred: 0,
      progress: 0,
      direction: state.direction
    });

    // Only start continuous task if not already running
    if (this.continuousTaskId === null) {
      try {
        // Request continuous task for data transfer
        const taskRequest: continuousTask.Request = {
          taskType: continuousTask.BackgroundMode.DATA_TRANSFER,
          taskName: 'FlatDrop Transfer',
          wantAgent: {
            action: 'com.flatdrop.transfer.START',
            bundleName: 'com.flatdrop.app',
            abilityName: 'EntryAbility'
          }
        };

        this.continuousTaskId = continuousTask.startContinuousTask(taskRequest);
        console.info(`Started continuous task: ${this.continuousTaskId}`);

        // Show notification
        this.showNotification(state, 0);
      } catch (error) {
        console.error('Failed to start continuous task:', error);
      }
    }
  }

  /**
   * Update notification with progress
   */
  private updateNotification(state: TransferStateChanged): void {
    // Update stored state
    const transfer = this.activeTransfers.get(state.transferId);
    if (transfer) {
      transfer.bytesTransferred = state.bytesTransferred;
      transfer.progress = state.progress;
      this.activeTransfers.set(state.transferId, transfer);
    }

    // Update notification
    this.showNotification(state, state.progress);
  }

  /**
   * Stop continuous task
   */
  private stopContinuousTask(state: TransferStateChanged): void {
    const transferId = state.transferId;

    // Remove from active transfers
    this.activeTransfers.delete(transferId);

    // Only stop continuous task when all transfers complete
    if (this.activeTransfers.size === 0 && this.continuousTaskId !== null) {
      try {
        continuousTask.stopContinuousTask(this.continuousTaskId);
        console.info(`Stopped continuous task: ${this.continuousTaskId}`);
        this.continuousTaskId = null;

        // Cancel notification
        notificationManager.cancel(this.notificationId);
      } catch (error) {
        console.error('Failed to stop continuous task:', error);
      }
    }

    // Show completion notification
    this.showCompletionNotification(state);
  }

  /**
   * Show progress notification
   */
  private showNotification(state: TransferStateChanged, progress: number): void {
    const progressPercent = Math.round(Math.min(100, Math.max(0, progress * 100)));
    const content = `${state.fileName} - ${progressPercent}%`;

    const notificationRequest: notificationManager.NotificationRequest = {
      id: this.notificationId,
      content: {
        contentType: notificationManager.ContentType.NOTIFICATION_CONTENT_BASIC_TEXT,
        normal: {
          title: 'FlatDrop Transfer',
          text: content,
          additionalText: this.formatBytes(state.bytesTransferred) + ' / ' + this.formatBytes(state.totalBytes)
        }
      },
      notificationSlotType: notificationManager.SlotType.SOCIAL_COMMUNICATION,
      showBadge: false
    };

    try {
      notificationManager.publish(notificationRequest);
    } catch (error) {
      console.error('Failed to publish notification:', error);
    }
  }

  /**
   * Show completion notification
   */
  private showCompletionNotification(state: TransferStateChanged): void {
    const title = state.state === TransferStateChanged.State.FINISHED 
      ? 'Transfer Complete' 
      : 'Transfer Failed';

    const notificationRequest: notificationManager.NotificationRequest = {
      id: this.notificationId + 1, // Different ID from progress notification
      content: {
        contentType: notificationManager.ContentType.NOTIFICATION_CONTENT_BASIC_TEXT,
        normal: {
          title: title,
          text: state.fileName,
          additionalText: state.errorMessage || ''
        }
      },
      notificationSlotType: notificationManager.SlotType.SOCIAL_COMMUNICATION,
      showBadge: true
    };

    try {
      notificationManager.publish(notificationRequest);
    } catch (error) {
      console.error('Failed to publish notification:', error);
    }
  }

  /**
   * Poll for TransferStateChanged events from Rust
   */
  private startRustEventPoller(): void {
    setInterval(() => {
      try {
        const eventBytes = FlatDropCore.hubPollEvent();

        if (eventBytes.length > 0) {
          const rustEvent = RustEvent.decode(eventBytes);

          if (rustEvent.event?.$case === 'transferStateChanged') {
            this.handleTransferStateChange(rustEvent.event.transferStateChanged);
          }
        }
      } catch (error) {
        console.error('Error polling Rust events:', error);
      }
    }, 100); // Poll every 100ms
  }

  /**
   * Format bytes to human-readable string
   */
  private formatBytes(bytes: number): string {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(2)} ${units[unitIndex]}`;
  }
}

// Transfer state interface
interface TransferState {
  id: string;
  fileName: string;
  totalBytes: number;
  bytesTransferred: number;
  progress: number;
  direction: TransferDirection;
}

/**
 * Usage in EntryAbility:
 * 
 * import { BackgroundTransferManager } from '../background/BackgroundTransferManager';
 * 
 * // In your UI component or ability:
 * const bgManager = BackgroundTransferManager.getInstance();
 * 
 * // The manager automatically handles TransferStateChanged events
 * // from Rust and manages the continuous task lifecycle
 */
