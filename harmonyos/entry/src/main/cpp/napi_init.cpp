#include "napi/native_api.h"
#include <string>
#include <vector>
#include <cstring>

// Import Rust FFI declarations
extern "C" {
    typedef struct {
        uint8_t* ptr;
        size_t len;
        size_t cap;
    } ByteBuffer;

    void hub_free_byte_buffer(ByteBuffer buffer);
    ByteBuffer ffi_hub_start(const uint8_t* config_ptr, size_t config_len);
    ByteBuffer ffi_hub_stop();
    bool ffi_hub_is_initialized();
    ByteBuffer ffi_hub_send_command(const uint8_t* cmd_ptr, size_t cmd_len);
    ByteBuffer ffi_hub_poll_event(uint64_t timeout_ms);
}

// Helper to convert ByteBuffer to NAPI Uint8Array
napi_value ByteBufferToJs(napi_env env, ByteBuffer buffer) {
    void* data;
    napi_value arraybuffer;
    napi_value result;
    
    if (buffer.len == 0) {
        napi_create_arraybuffer(env, 0, &data, &arraybuffer);
        napi_create_typedarray(env, napi_uint8_array, 0, arraybuffer, 0, &result);
        hub_free_byte_buffer(buffer);
        return result;
    }

    // Copy data to NAPI managed memory
    napi_create_arraybuffer(env, buffer.len, &data, &arraybuffer);
    memcpy(data, buffer.ptr, buffer.len);
    napi_create_typedarray(env, napi_uint8_array, buffer.len, arraybuffer, 0, &result);
    
    // Free Rust memory
    hub_free_byte_buffer(buffer);
    
    return result;
}

// Helper to convert NAPI Uint8Array to byte vector
std::vector<uint8_t> JsToBytes(napi_env env, napi_value js_array) {
    bool is_typedarray;
    napi_is_typedarray(env, js_array, &is_typedarray);
    if (!is_typedarray) return {};

    napi_typedarray_type type;
    size_t length;
    void* data;
    napi_value arraybuffer;
    size_t byte_offset;
    
    napi_get_typedarray_info(env, js_array, &type, &length, &data, &arraybuffer, &byte_offset);
    
    if (type != napi_uint8_array) return {};
    
    std::vector<uint8_t> result(length);
    memcpy(result.data(), data, length);
    return result;
}

static napi_value HubStart(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    std::vector<uint8_t> config = JsToBytes(env, args[0]);
    ByteBuffer result = ffi_hub_start(config.data(), config.size());
    
    return ByteBufferToJs(env, result);
}

static napi_value HubStop(napi_env env, napi_callback_info info) {
    ByteBuffer result = ffi_hub_stop();
    return ByteBufferToJs(env, result);
}

static napi_value HubIsInitialized(napi_env env, napi_callback_info info) {
    bool result = ffi_hub_is_initialized();
    napi_value js_result;
    napi_get_boolean(env, result, &js_result);
    return js_result;
}

static napi_value HubSendCommand(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    std::vector<uint8_t> cmd = JsToBytes(env, args[0]);
    ByteBuffer result = ffi_hub_send_command(cmd.data(), cmd.size());
    
    return ByteBufferToJs(env, result);
}

static napi_value HubPollEvent(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    int64_t timeout_ms;
    napi_get_value_int64(env, args[0], &timeout_ms);
    
    ByteBuffer result = ffi_hub_poll_event(static_cast<uint64_t>(timeout_ms));
    
    return ByteBufferToJs(env, result);
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        { "hubStart", nullptr, HubStart, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "hubStop", nullptr, HubStop, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "hubIsInitialized", nullptr, HubIsInitialized, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "hubSendCommand", nullptr, HubSendCommand, nullptr, nullptr, nullptr, napi_default, nullptr },
        { "hubPollEvent", nullptr, HubPollEvent, nullptr, nullptr, nullptr, napi_default, nullptr }
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "entry",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void) {
    napi_module_register(&demoModule);
}
