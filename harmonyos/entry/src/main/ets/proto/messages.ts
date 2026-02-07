export enum DiscoveryEventType {
    EVENT_UNSPECIFIED = 0,
    DEVICE_FOUND = 1,
    DEVICE_LOST = 2,
    ERROR = 3
}

export enum TransferState {
    IDLE = 0,
    PREPARING = 1,
    IN_PROGRESS = 2,
    PAUSED = 3,
    FINISHED = 4,
    FAILED = 5,
    CANCELLED = 6
}

export enum TransferDirection {
    DIRECTION_UNSPECIFIED = 0,
    OUTGOING = 1,
    INCOMING = 2
}

export class TransferStateChanged {
    static State = TransferState;

    state: TransferState = TransferState.IDLE;
    transferId: string = "";
    description: string = "";
    fileName: string = "";
    totalBytes: number = 0;
    bytesTransferred: number = 0;
    progress: number = 0;
    errorMessage: string = "";
    direction: TransferDirection = TransferDirection.DIRECTION_UNSPECIFIED;

    constructor(obj?: Partial<TransferStateChanged>) {
        if (obj) Object.assign(this, obj);
    }
}

export class RustEvent {
    event?: { $case: 'transferStateChanged', transferStateChanged: TransferStateChanged }
        | { $case: 'discovery', discovery: any }; // Add other cases as needed

    static decode(buffer: Uint8Array): RustEvent {
        // TODO: Replace with actual Protobuf decoding logic or use a library
        // This is a placeholder that returns a mock event for testing
        // You MUST generate this file using protoc --ts_out or similar
        console.warn("Using mock RustEvent.decode - implement real protobuf decoding");
        return new RustEvent();
    }

    static encode(message: RustEvent): Uint8Array {
        return new Uint8Array();
    }
}

export class InitializeRequest {
    config: any;
    static encode(req: InitializeRequest): Uint8Array { return new Uint8Array(); }
}

export class InitializeResponse {
    success: boolean = false;
    error_message: string = "";
    node_id: string = "";

    static decode(buffer: Uint8Array): InitializeResponse {
        return new InitializeResponse();
    }
}
