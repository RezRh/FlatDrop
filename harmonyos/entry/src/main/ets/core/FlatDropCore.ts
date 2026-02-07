import entry from "libentry.so";
import { InitializeRequest, InitializeResponse } from "../proto/messages";

type NativeEntry = {
  hubStart(config: Uint8Array): Promise<Uint8Array>;
  hubStop(): Promise<Uint8Array>;
  hubIsInitialized(): boolean;
  hubSendCommand(cmd: Uint8Array): Promise<Uint8Array>;
  hubPollEvent(timeoutMs: number): Promise<Uint8Array>;
  hubSubscribeEvents(cb: (ev: Uint8Array) => void, pollTimeoutMs?: number): boolean;
  hubUnsubscribeEvents(): boolean;
};

function assertUint8Array(x: unknown, name: string): asserts x is Uint8Array {
  if (!(x instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

function encodeInitRequest(config: unknown): Uint8Array {
  const req = InitializeRequest.create({ config });
  const bytes = InitializeRequest.encode(req).finish();
  if (!(bytes instanceof Uint8Array)) {
    throw new Error("InitializeRequest.encode(...).finish() did not return Uint8Array");
  }
  return bytes;
}

function decodeInitResponse(bytes: Uint8Array): InitializeResponse {
  return InitializeResponse.decode(bytes);
}

export class FlatDropCore {
  private static startInFlight: Promise<string> | null = null;
  private static stopInFlight: Promise<void> | null = null;
  private static readonly native: NativeEntry = entry as unknown as NativeEntry;

  public static isInitialized(): boolean {
    return this.native.hubIsInitialized();
  }

  public static async start(config: unknown): Promise<string> {
    if (this.startInFlight) return this.startInFlight;

    if (this.native.hubIsInitialized()) {
      return "";
    }

    this.startInFlight = (async () => {
      const configBytes = encodeInitRequest(config);
      assertUint8Array(configBytes, "configBytes");

      const resultBytes = await this.native.hubStart(configBytes);
      assertUint8Array(resultBytes, "hubStart result");

      const resp = decodeInitResponse(resultBytes);

      if (!resp.success) {
        throw new Error(resp.error_message || "hubStart failed");
      }

      return resp.node_id || "";
    })()
      .finally(() => {
        this.startInFlight = null;
      });

    return this.startInFlight;
  }

  public static async stop(): Promise<void> {
    if (this.stopInFlight) return this.stopInFlight;

    this.stopInFlight = (async () => {
      try {
        await this.native.hubStop();
      } finally {
        this.native.hubUnsubscribeEvents();
      }
    })().finally(() => {
      this.stopInFlight = null;
    });

    return this.stopInFlight;
  }

  public static async pollEvent(timeoutMs = 100): Promise<Uint8Array> {
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
      throw new RangeError("timeoutMs must be a finite number >= 0");
    }

    const out = await this.native.hubPollEvent(timeoutMs);
    assertUint8Array(out, "hubPollEvent result");
    return out;
  }

  public static async sendCommand(commandBytes: Uint8Array): Promise<Uint8Array> {
    assertUint8Array(commandBytes, "commandBytes");
    if (commandBytes.length === 0) {
      throw new RangeError("commandBytes must not be empty");
    }

    const out = await this.native.hubSendCommand(commandBytes);
    assertUint8Array(out, "hubSendCommand result");
    return out;
  }

  public static subscribeEvents(
    onEvent: (evBytes: Uint8Array) => void,
    pollTimeoutMs = 1000
  ): void {
    if (typeof onEvent !== "function") {
      throw new TypeError("onEvent must be a function");
    }
    if (!Number.isFinite(pollTimeoutMs) || pollTimeoutMs < 1) {
      throw new RangeError("pollTimeoutMs must be a finite number >= 1");
    }

    const ok = this.native.hubSubscribeEvents((ev: Uint8Array) => {
      if (!(ev instanceof Uint8Array)) return;
      onEvent(ev);
    }, pollTimeoutMs);

    if (!ok) {
      throw new Error("Failed to subscribe to events");
    }
  }

  public static unsubscribeEvents(): void {
    this.native.hubUnsubscribeEvents();
  }
}