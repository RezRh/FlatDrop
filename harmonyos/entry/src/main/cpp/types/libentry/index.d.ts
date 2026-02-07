export const hubStart: (config: Uint8Array) => Uint8Array;
export const hubStop: () => Uint8Array;
export const hubIsInitialized: () => boolean;
export const hubSendCommand: (cmd: Uint8Array) => Uint8Array;
export const hubPollEvent: (timeoutMs: number) => Uint8Array;
