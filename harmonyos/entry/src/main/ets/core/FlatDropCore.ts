import entry from 'libentry.so';
import { InitializeRequest, InitializeResponse } from '../proto/messages';

export class FlatDropCore {
    private static isInitialized = false;

    /**
     * Start the FlatDrop Hub
     * @param config The configuration object
     * @returns The node ID if successful
     */
    public static async start(config: any): Promise<string> {
        if (this.isInitialized) {
            console.warn("FlatDrop Core already initialized");
            return "";
        }

        try {
            console.debug("Starting FlatDrop Core...");
            const req = new InitializeRequest();
            req.config = config;

            const configBytes = InitializeRequest.encode(req);
            // In a real implementation we would encode the config protobuf
            // For now, let's pass an empty buffer or a simple serialized JSON if needed
            // But the FFI expects protobuf

            const resultBytes = entry.hubStart(configBytes);
            const response = InitializeResponse.decode(resultBytes);

            if (response.success) {
                console.info(`FlatDrop Core started with Node ID: ${response.node_id}`);
                this.isInitialized = true;
                return response.node_id;
            } else {
                console.error(`Failed to start FlatDrop Core: ${response.error_message}`);
                throw new Error(response.error_message);
            }
        } catch (error) {
            console.error("Exception in FlatDropCore.start:", error);
            throw error;
        }
    }

    /**
     * Stop the FlatDrop Hub
     */
    public static stop(): void {
        try {
            entry.hubStop();
            this.isInitialized = false;
            console.info("FlatDrop Core stopped");
        } catch (error) {
            console.error("Error stopping FlatDrop Core:", error);
        }
    }

    /**
     * Poll for events from the Rust Core
     * @param timeoutMs Timeout in milliseconds
     * @returns Byte array containing the serialized RustEvent
     */
    public static hubPollEvent(timeoutMs: number = 100): Uint8Array {
        try {
            return entry.hubPollEvent(timeoutMs);
        } catch (error) {
            console.error("Error polling event:", error);
            return new Uint8Array(0);
        }
    }

    /**
     * Send a command to the Rust Core
     * @param commandBytes Serialized command protobuf
     * @returns Serialized response protobuf
     */
    public static sendCommand(commandBytes: Uint8Array): Uint8Array {
        try {
            return entry.hubSendCommand(commandBytes);
        } catch (error) {
            console.error("Error sending command:", error);
            return new Uint8Array(0);
        }
    }
}
