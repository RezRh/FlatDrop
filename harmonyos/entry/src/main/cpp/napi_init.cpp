#include <node_api.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

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

static constexpr size_t MAX_CONFIG_BYTES = 16 * 1024 * 1024;
static constexpr size_t MAX_COMMAND_BYTES = 64 * 1024 * 1024;
static constexpr size_t MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
static constexpr uint64_t MAX_TIMEOUT_MS = 60'000;

static std::mutex g_ffi_mu;

static inline bool rust_buf_nonempty_or_allocated(const ByteBuffer& b) {
  return b.ptr != nullptr || b.len != 0 || b.cap != 0;
}

static inline void free_rust_buf(ByteBuffer b) {
  if (rust_buf_nonempty_or_allocated(b)) {
    hub_free_byte_buffer(b);
  }
}

static void throw_napi_last_error(napi_env env, const char* prefix) {
  const napi_extended_error_info* info = nullptr;
  napi_get_last_error_info(env, &info);
  const char* msg = (info && info->error_message) ? info->error_message : "unknown N-API error";
  std::string full = std::string(prefix) + ": " + msg;
  napi_throw_error(env, nullptr, full.c_str());
}

#define NAPI_OK_RET(env, expr, ret)            \
  do {                                         \
    napi_status _s = (expr);                   \
    if (_s != napi_ok) {                       \
      throw_napi_last_error((env), #expr);     \
      return (ret);                            \
    }                                          \
  } while (0)

#define NAPI_OK_VOID(env, expr)                \
  do {                                         \
    napi_status _s = (expr);                   \
    if (_s != napi_ok) {                       \
      throw_napi_last_error((env), #expr);     \
      return;                                  \
    }                                          \
  } while (0)

static napi_value make_js_error(napi_env env, const std::string& msg) {
  napi_value err_msg;
  NAPI_OK_RET(env, napi_create_string_utf8(env, msg.c_str(), msg.size(), &err_msg), nullptr);
  napi_value err;
  NAPI_OK_RET(env, napi_create_error(env, nullptr, err_msg, &err), nullptr);
  return err;
}

static void finalize_rust_bytebuffer(napi_env /*env*/, void* /*finalize_data*/, void* finalize_hint) {
  auto* bb = static_cast<ByteBuffer*>(finalize_hint);
  if (bb) {
    free_rust_buf(*bb);
    delete bb;
  }
}

static napi_value consume_bytebuffer_to_uint8array(napi_env env, ByteBuffer* b) {
  if (!b) {
    napi_throw_error(env, nullptr, "internal error: null ByteBuffer");
    return nullptr;
  }

  if (b->len > MAX_OUTPUT_BYTES) {
    ByteBuffer tmp = *b;
    b->ptr = nullptr; b->len = 0; b->cap = 0;
    free_rust_buf(tmp);
    napi_throw_range_error(env, nullptr, "FFI output too large");
    return nullptr;
  }

  if (b->len == 0) {
    ByteBuffer tmp = *b;
    b->ptr = nullptr; b->len = 0; b->cap = 0;
    free_rust_buf(tmp);

    napi_value ab, ta;
    void* data = nullptr;
    NAPI_OK_RET(env, napi_create_arraybuffer(env, 0, &data, &ab), nullptr);
    NAPI_OK_RET(env, napi_create_typedarray(env, napi_uint8_array, 0, ab, 0, &ta), nullptr);
    return ta;
  }

  if (b->ptr == nullptr) {
    ByteBuffer tmp = *b;
    b->ptr = nullptr; b->len = 0; b->cap = 0;
    free_rust_buf(tmp);
    napi_throw_error(env, nullptr, "FFI returned null ptr with non-zero len");
    return nullptr;
  }

  auto* heap = new ByteBuffer(*b);
  b->ptr = nullptr; b->len = 0; b->cap = 0;

  napi_value ab;
  napi_status s = napi_create_external_arraybuffer(
      env,
      heap->ptr,
      heap->len,
      finalize_rust_bytebuffer,
      heap,
      &ab);

  if (s != napi_ok) {
    free_rust_buf(*heap);
    delete heap;
    throw_napi_last_error(env, "napi_create_external_arraybuffer");
    return nullptr;
  }

  napi_value ta;
  s = napi_create_typedarray(env, napi_uint8_array, heap->len, ab, 0, &ta);
  if (s != napi_ok) {
    free_rust_buf(*heap);
    delete heap;
    throw_napi_last_error(env, "napi_create_typedarray");
    return nullptr;
  }

  return ta;
}

static bool get_uint8array_copy(napi_env env, napi_value v, size_t max_len, std::vector<uint8_t>* out) {
  if (!out) {
    napi_throw_error(env, nullptr, "internal error");
    return false;
  }

  bool is_typedarray = false;
  NAPI_OK_RET(env, napi_is_typedarray(env, v, &is_typedarray), false);
  if (!is_typedarray) {
    napi_throw_type_error(env, nullptr, "Expected Uint8Array");
    return false;
  }

  napi_typedarray_type type;
  size_t length = 0;
  void* data = nullptr;
  napi_value arraybuffer;
  size_t byte_offset = 0;

  NAPI_OK_RET(env, napi_get_typedarray_info(env, v, &type, &length, &data, &arraybuffer, &byte_offset), false);

  if (type != napi_uint8_array) {
    napi_throw_type_error(env, nullptr, "Expected Uint8Array");
    return false;
  }

  if (length > max_len) {
    napi_throw_range_error(env, nullptr, "Input too large");
    return false;
  }

  if (length > 0 && data == nullptr) {
    napi_throw_error(env, nullptr, "Invalid typed array data");
    return false;
  }

  out->assign(reinterpret_cast<uint8_t*>(data), reinterpret_cast<uint8_t*>(data) + length);
  return true;
}

static bool get_u64_timeout_ms(napi_env env, napi_value v, uint64_t* out) {
  if (!out) return false;

  napi_valuetype t;
  NAPI_OK_RET(env, napi_typeof(env, v, &t), false);
  if (t != napi_number) {
    napi_throw_type_error(env, nullptr, "Expected number timeout_ms");
    return false;
  }

  int64_t tmp = 0;
  NAPI_OK_RET(env, napi_get_value_int64(env, v, &tmp), false);

  if (tmp < 0) {
    napi_throw_range_error(env, nullptr, "timeout_ms must be >= 0");
    return false;
  }

  uint64_t u = static_cast<uint64_t>(tmp);
  if (u > MAX_TIMEOUT_MS) u = MAX_TIMEOUT_MS;
  *out = u;
  return true;
}

struct AsyncWorkBase {
  napi_env env{nullptr};
  napi_async_work work{nullptr};
  napi_deferred deferred{nullptr};
  std::string err;
  ByteBuffer out{nullptr, 0, 0};
  bool has_out{false};

  virtual ~AsyncWorkBase() = default;
  virtual void exec() = 0;

  void cleanup() {
    if (work) {
      napi_delete_async_work(env, work);
      work = nullptr;
    }
    if (has_out) {
      free_rust_buf(out);
      out = {nullptr, 0, 0};
      has_out = false;
    }
  }
};

static void async_execute(napi_env /*env*/, void* data) {
  auto* w = static_cast<AsyncWorkBase*>(data);
  try {
    w->exec();
  } catch (const std::exception& e) {
    w->err = e.what();
  } catch (...) {
    w->err = "unknown error";
  }
}

static void async_complete(napi_env env, napi_status status, void* data) {
  std::unique_ptr<AsyncWorkBase> w(static_cast<AsyncWorkBase*>(data));

  if (status != napi_ok) {
    w->err = "async work failed";
  }

  if (!w->err.empty()) {
    napi_value err = make_js_error(env, w->err);
    if (err) {
      napi_reject_deferred(env, w->deferred, err);
    }
    w->cleanup();
    return;
  }

  if (!w->has_out) {
    napi_value err = make_js_error(env, "no output");
    if (err) napi_reject_deferred(env, w->deferred, err);
    w->cleanup();
    return;
  }

  napi_value val = consume_bytebuffer_to_uint8array(env, &w->out);
  w->has_out = false;

  if (!val) {
    napi_value err = make_js_error(env, "failed to create Uint8Array result");
    if (err) napi_reject_deferred(env, w->deferred, err);
    w->cleanup();
    return;
  }

  napi_resolve_deferred(env, w->deferred, val);
  w->cleanup();
}

template <typename WorkT>
static napi_value queue_work(napi_env env, const char* name, std::unique_ptr<WorkT> w) {
  napi_value promise;
  NAPI_OK_RET(env, napi_create_promise(env, &w->deferred, &promise), nullptr);

  napi_value resource_name;
  NAPI_OK_RET(env, napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resource_name), nullptr);

  w->env = env;

  NAPI_OK_RET(
      env,
      napi_create_async_work(env, nullptr, resource_name, async_execute, async_complete, w.get(), &w->work),
      nullptr);

  NAPI_OK_RET(env, napi_queue_async_work(env, w->work), nullptr);

  (void)w.release();
  return promise;
}

struct StartWork final : AsyncWorkBase {
  std::vector<uint8_t> config;

  void exec() override {
    if (config.empty()) {
      err = "config cannot be empty";
      return;
    }
    ByteBuffer b;
    {
      std::lock_guard<std::mutex> lk(g_ffi_mu);
      const uint8_t* ptr = config.data();
      b = ffi_hub_start(ptr, config.size());
    }
    out = b;
    has_out = true;
  }
};

struct StopWork final : AsyncWorkBase {
  void exec() override {
    ByteBuffer b;
    {
      std::lock_guard<std::mutex> lk(g_ffi_mu);
      b = ffi_hub_stop();
    }
    out = b;
    has_out = true;
  }
};

struct SendCommandWork final : AsyncWorkBase {
  std::vector<uint8_t> cmd;

  void exec() override {
    if (cmd.empty()) {
      err = "command cannot be empty";
      return;
    }
    ByteBuffer b;
    {
      std::lock_guard<std::mutex> lk(g_ffi_mu);
      const uint8_t* ptr = cmd.data();
      b = ffi_hub_send_command(ptr, cmd.size());
    }
    out = b;
    has_out = true;
  }
};

struct PollEventWork final : AsyncWorkBase {
  uint64_t timeout_ms{0};

  void exec() override {
    ByteBuffer b;
    {
      std::lock_guard<std::mutex> lk(g_ffi_mu);
      b = ffi_hub_poll_event(timeout_ms);
    }
    out = b;
    has_out = true;
  }
};

static napi_value HubStart(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  NAPI_OK_RET(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr), nullptr);

  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "hubStart(config: Uint8Array) requires 1 argument");
    return nullptr;
  }

  auto w = std::make_unique<StartWork>();
  if (!get_uint8array_copy(env, args[0], MAX_CONFIG_BYTES, &w->config)) {
    return nullptr;
  }

  return queue_work(env, "hubStart", std::move(w));
}

static napi_value HubStop(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  NAPI_OK_RET(env, napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr), nullptr);

  auto w = std::make_unique<StopWork>();
  return queue_work(env, "hubStop", std::move(w));
}

static napi_value HubIsInitialized(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  NAPI_OK_RET(env, napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr), nullptr);

  bool result = false;
  {
    std::lock_guard<std::mutex> lk(g_ffi_mu);
    result = ffi_hub_is_initialized();
  }

  napi_value js_result;
  NAPI_OK_RET(env, napi_get_boolean(env, result, &js_result), nullptr);
  return js_result;
}

static napi_value HubSendCommand(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  NAPI_OK_RET(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr), nullptr);

  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "hubSendCommand(cmd: Uint8Array) requires 1 argument");
    return nullptr;
  }

  auto w = std::make_unique<SendCommandWork>();
  if (!get_uint8array_copy(env, args[0], MAX_COMMAND_BYTES, &w->cmd)) {
    return nullptr;
  }

  return queue_work(env, "hubSendCommand", std::move(w));
}

static napi_value HubPollEvent(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  NAPI_OK_RET(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr), nullptr);

  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "hubPollEvent(timeoutMs: number) requires 1 argument");
    return nullptr;
  }

  auto w = std::make_unique<PollEventWork>();
  if (!get_u64_timeout_ms(env, args[0], &w->timeout_ms)) {
    return nullptr;
  }

  return queue_work(env, "hubPollEvent", std::move(w));
}

struct EventSub {
  napi_env env{nullptr};
  napi_threadsafe_function tsfn{nullptr};
  std::atomic<bool> running{false};
  std::thread th;
  uint64_t poll_timeout_ms{1000};
};

static std::mutex g_sub_mu;
static std::unique_ptr<EventSub> g_sub;

static void tsfn_call_js(napi_env env, napi_value js_cb, void* /*context*/, void* data) {
  std::unique_ptr<ByteBuffer> bb(static_cast<ByteBuffer*>(data));
  if (!bb) return;

  if (env == nullptr) {
    free_rust_buf(*bb);
    return;
  }

  napi_value undefined;
  NAPI_OK_VOID(env, napi_get_undefined(env, &undefined));

  napi_value arg = consume_bytebuffer_to_uint8array(env, bb.get());
  if (!arg) {
    return;
  }

  napi_value argv[1] = {arg};
  napi_value ignored;
  napi_status s = napi_call_function(env, undefined, js_cb, 1, argv, &ignored);
  if (s != napi_ok) {
    throw_napi_last_error(env, "napi_call_function");
    return;
  }
}

static void stop_subscription_locked() {
  if (!g_sub) return;

  g_sub->running.store(false);

  if (g_sub->th.joinable()) {
    g_sub->th.join();
  }

  if (g_sub->tsfn) {
    napi_release_threadsafe_function(g_sub->tsfn, napi_tsfn_abort);
    g_sub->tsfn = nullptr;
  }

  g_sub.reset();
}

static napi_value HubSubscribeEvents(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value args[2];
  NAPI_OK_RET(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr), nullptr);

  if (argc < 1) {
    napi_throw_type_error(env, nullptr, "hubSubscribeEvents(cb: function, pollTimeoutMs?: number)");
    return nullptr;
  }

  napi_valuetype cb_type;
  NAPI_OK_RET(env, napi_typeof(env, args[0], &cb_type), nullptr);
  if (cb_type != napi_function) {
    napi_throw_type_error(env, nullptr, "First argument must be a function");
    return nullptr;
  }

  uint64_t poll_timeout_ms = 1000;
  if (argc >= 2) {
    if (!get_u64_timeout_ms(env, args[1], &poll_timeout_ms)) {
      return nullptr;
    }
    if (poll_timeout_ms == 0) poll_timeout_ms = 1;
    if (poll_timeout_ms > 5000) poll_timeout_ms = 5000;
  }

  std::lock_guard<std::mutex> lk(g_sub_mu);
  if (g_sub) {
    napi_throw_error(env, nullptr, "Already subscribed");
    return nullptr;
  }

  auto sub = std::make_unique<EventSub>();
  sub->env = env;
  sub->poll_timeout_ms = poll_timeout_ms;

  napi_value resource_name;
  NAPI_OK_RET(env, napi_create_string_utf8(env, "FlatDropHubEvents", NAPI_AUTO_LENGTH, &resource_name), nullptr);

  NAPI_OK_RET(
      env,
      napi_create_threadsafe_function(
          env,
          args[0],
          nullptr,
          resource_name,
          1024,
          1,
          nullptr,
          nullptr,
          nullptr,
          tsfn_call_js,
          &sub->tsfn),
      nullptr);

  sub->running.store(true);
  sub->th = std::thread([tsfn = sub->tsfn, running = &sub->running, poll_timeout_ms]() {
    while (running->load()) {
      ByteBuffer b;
      {
        std::lock_guard<std::mutex> lk(g_ffi_mu);
        b = ffi_hub_poll_event(poll_timeout_ms);
      }

      if (!running->load()) {
        free_rust_buf(b);
        break;
      }

      if (b.len == 0) {
        free_rust_buf(b);
        continue;
      }

      if (b.len > MAX_OUTPUT_BYTES) {
        free_rust_buf(b);
        continue;
      }

      auto* heap = new ByteBuffer(b);
      napi_status s = napi_call_threadsafe_function(tsfn, heap, napi_tsfn_nonblocking);
      if (s != napi_ok) {
        free_rust_buf(*heap);
        delete heap;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    }
  });

  g_sub = std::move(sub);

  napi_value js_true;
  NAPI_OK_RET(env, napi_get_boolean(env, true, &js_true), nullptr);
  return js_true;
}

static napi_value HubUnsubscribeEvents(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  NAPI_OK_RET(env, napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr), nullptr);

  std::lock_guard<std::mutex> lk(g_sub_mu);
  stop_subscription_locked();

  napi_value js_true;
  NAPI_OK_RET(env, napi_get_boolean(env, true, &js_true), nullptr);
  return js_true;
}

static napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor desc[] = {
      {"hubStart", nullptr, HubStart, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"hubStop", nullptr, HubStop, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"hubIsInitialized", nullptr, HubIsInitialized, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"hubSendCommand", nullptr, HubSendCommand, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"hubPollEvent", nullptr, HubPollEvent, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"hubSubscribeEvents", nullptr, HubSubscribeEvents, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"hubUnsubscribeEvents", nullptr, HubUnsubscribeEvents, nullptr, nullptr, nullptr, napi_default, nullptr},
  };

  NAPI_OK_RET(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc), nullptr);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)