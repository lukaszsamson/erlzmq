// -*- coding:utf-8;Mode:C;tab-width:2;c-basic-offset:2;indent-tabs-mode:nil -*-
// ex: set softtabstop=2 tabstop=2 shiftwidth=2 expandtab fileencoding=utf-8:
//
// Copyright (c) 2020 Łukasz Samson
// Copyright (c) 2019 erlang solutions ltd
// Copyright (c) 2011 Yurii Rashkovskii, Evax Software and Michael Truog
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include "zmq.h"
#if ZMQ_VERSION_MAJOR < 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR < 1
#include "zmq_utils.h"
#endif
#include "erl_nif.h"
#include "erl_driver.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <inttypes.h>
#include <sys/resource.h>
#include <time.h>

#ifndef ZMQ_ROUTING_ID
#define ZMQ_ROUTING_ID ZMQ_IDENTITY
#endif

#ifndef ZMQ_CONNECT_ROUTING_ID
#define ZMQ_CONNECT_ROUTING_ID ZMQ_CONNECT_RID
#endif

#ifndef ZMQ_IMMEDIATE
#define ZMQ_IMMEDIATE ZMQ_DELAY_ATTACH_ON_CONNECT
#endif

static ErlNifResourceType* erlzmq_nif_resource_context;
static ErlNifResourceType* erlzmq_nif_resource_socket;

typedef struct erlzmq_context {
  void * context_zmq;
  uint64_t socket_index;
  ErlNifMutex * mutex;
  int status;
} erlzmq_context_t;

struct erlzmq_socket;

typedef enum erlzmq_socket_reply_kind {
  ERLZMQ_SOCKET_REPLY_NONE = 0,
  ERLZMQ_SOCKET_REPLY_INT,
  ERLZMQ_SOCKET_REPLY_INT64,
  ERLZMQ_SOCKET_REPLY_UINT64,
  ERLZMQ_SOCKET_REPLY_BYTES,
  ERLZMQ_SOCKET_REPLY_MULTIPART,
} erlzmq_socket_reply_kind_t;

typedef struct erlzmq_socket_request {
  int command_id;
  union {
    struct {
      char *endpoint;
      size_t endpoint_len;
    } endpoint;
    struct {
      uint8_t *data;
      size_t size;
      int flags;
    } send;
    struct {
      uint8_t **parts;
      size_t *sizes;
      size_t part_count;
      int flags;
    } send_multipart;
    struct {
      int flags;
    } recv;
    struct {
      int flags;
    } recv_multipart;
    struct {
      short events;
      long timeout;
    } poll;
    struct {
      int option_name;
    } getsockopt;
    struct {
      int option_name;
      int kind; /* 0=int, 1=int64, 2=uint64, 3=bytes */
      union {
        int i32;
        int64_t i64;
        uint64_t u64;
        struct {
          uint8_t *data;
          size_t size;
        } bytes;
      } value;
      size_t option_len;
    } setsockopt;
  } in;
} erlzmq_socket_request_t;

typedef struct erlzmq_socket_reply {
  int ok;
  int err;
  erlzmq_socket_reply_kind_t kind;
  union {
    int i32;
    int64_t i64;
    uint64_t u64;
    struct {
      uint8_t *data;
      size_t size;
    } bytes;
    struct {
      uint8_t **parts;
      size_t *sizes;
      size_t part_count;
    } multipart;
  } out;
} erlzmq_socket_reply_t;

typedef struct erlzmq_socket {
  erlzmq_context_t * context;
  uint64_t socket_index;
  ErlNifMutex * mutex;
  int status;
  int socket_type;
  void* socket_zmq;
  ErlNifTid socket_thread;
  ErlNifCond * socket_command_cond;
  ErlNifMutex * socket_command_mutex;
  ErlNifCond * socket_command_result_cond;
  int command_pending;
  int result_ready;
  int init_done;
  int init_errno;
  int shutdown;  // Signal for thread to exit during cleanup
  erlzmq_socket_request_t request;
  erlzmq_socket_reply_t reply;
} erlzmq_socket_t;

#define ERLZMQ_SOCKET_STATUS_READY   0
#define ERLZMQ_SOCKET_STATUS_CLOSED  1

#define ERLZMQ_CONTEXT_STATUS_READY       0
#define ERLZMQ_CONTEXT_STATUS_TERMINATING 1
#define ERLZMQ_CONTEXT_STATUS_TERMINATED  2

// Prototypes
#define NIF(name) \
  ERL_NIF_TERM name(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])

NIF(erlzmq_nif_context);
NIF(erlzmq_nif_socket);
NIF(erlzmq_nif_socket_command);
NIF(erlzmq_nif_term);
NIF(erlzmq_nif_ctx_get);
NIF(erlzmq_nif_ctx_set);
NIF(erlzmq_nif_curve_keypair);
NIF(erlzmq_nif_z85_decode);
NIF(erlzmq_nif_z85_encode);
NIF(erlzmq_nif_has);
NIF(erlzmq_nif_version);

static ERL_NIF_TERM return_zmq_errno(ErlNifEnv* env, int const value);
static void clear_socket_request(erlzmq_socket_request_t *request);
static void clear_socket_reply(erlzmq_socket_reply_t *reply);
static void free_socket_request(erlzmq_socket_request_t *request);
static void free_socket_reply(erlzmq_socket_reply_t *reply);
static void socket_exec_request(erlzmq_socket_t *socket, const erlzmq_socket_request_t *request, erlzmq_socket_reply_t *reply);
static void* socket_thread(erlzmq_socket_t *socket);

static ErlNifFunc nif_funcs[] = {
  // non blocking
  {"context", 1, erlzmq_nif_context, 0},
  // can block on context mutex
  {"socket", 2, erlzmq_nif_socket, ERL_NIF_DIRTY_JOB_IO_BOUND},
  // can block on socket mutex
  {"socket_command", 3, erlzmq_nif_socket_command, ERL_NIF_DIRTY_JOB_IO_BOUND},
  // can block on zmq_term or context mutex
  {"term", 1, erlzmq_nif_term, ERL_NIF_DIRTY_JOB_IO_BOUND},
  // can block on context mutex
  {"ctx_get", 2, erlzmq_nif_ctx_get, ERL_NIF_DIRTY_JOB_IO_BOUND},
  // can block on context mutex
  {"ctx_set", 3, erlzmq_nif_ctx_set, ERL_NIF_DIRTY_JOB_IO_BOUND},
  // non blocking
  {"curve_keypair", 0, erlzmq_nif_curve_keypair, 0},
  // non blocking
  {"z85_decode", 1, erlzmq_nif_z85_decode, 0},
  // non blocking
  {"z85_encode", 1, erlzmq_nif_z85_encode, 0},
  // non blocking
  {"has", 1, erlzmq_nif_has, 0},
  // non blocking
  {"version", 0, erlzmq_nif_version, 0}
};

#define SOCKET_COMMANDS_COUNT 12

NIF(erlzmq_nif_context)
{
  int thread_count;

  if (! enif_get_int(env, argv[0], &thread_count)) {
    return enif_make_badarg(env);
  }

  erlzmq_context_t * context = (erlzmq_context_t *)enif_alloc_resource(erlzmq_nif_resource_context,
                                                   sizeof(erlzmq_context_t));
  if (!context) {
    return return_zmq_errno(env, ENOMEM);
  }

  context->status = ERLZMQ_CONTEXT_STATUS_TERMINATED;
  context->context_zmq = 0;
  context->mutex = enif_mutex_create("erlzmq_context_t_mutex");
  if (!context->mutex) {
    enif_release_resource(context);
    return return_zmq_errno(env, ENOMEM);
  }
  context->context_zmq = zmq_init(thread_count);
  if (! context->context_zmq) {
    enif_release_resource(context);
    return return_zmq_errno(env, zmq_errno());
  }

  context->socket_index = 0;
  context->status = ERLZMQ_CONTEXT_STATUS_READY;

  ERL_NIF_TERM result = enif_make_tuple2(env, enif_make_atom(env, "ok"),
                          enif_make_resource(env, context));
  // Release our reference - Erlang now owns the resource.
  // When Erlang's reference is GC'd, the destructor will be called.
  enif_release_resource(context);
  return result;
}

NIF(erlzmq_nif_socket)
{
  erlzmq_context_t * context;
  int socket_type;

  if (! enif_get_resource(env, argv[0], erlzmq_nif_resource_context,
                          (void **) &context)) {
    return enif_make_badarg(env);
  }

  if (! enif_get_int(env, argv[1], &socket_type)) {
    return enif_make_badarg(env);
  }

  erlzmq_socket_t * socket = (erlzmq_socket_t *)enif_alloc_resource(erlzmq_nif_resource_socket,
                                                 sizeof(erlzmq_socket_t));
  if (!socket) {
    return return_zmq_errno(env, ENOMEM);
  }
  socket->context = context;
  socket->socket_index = 0;
  socket->socket_zmq = 0;
  socket->mutex = 0;
  socket->socket_thread = 0;
  socket->socket_command_mutex = 0;
  socket->socket_command_cond = 0;
  socket->socket_command_result_cond = 0;
  socket->status = ERLZMQ_SOCKET_STATUS_CLOSED;
  socket->socket_type = socket_type;
  socket->command_pending = 0;
  socket->result_ready = 0;
  socket->init_done = 0;
  socket->init_errno = 0;
  socket->shutdown = 0;
  clear_socket_request(&socket->request);
  clear_socket_reply(&socket->reply);

  enif_keep_resource(socket->context);

  assert(context->mutex);
  enif_mutex_lock(context->mutex);
  if (context->status != ERLZMQ_CONTEXT_STATUS_READY) {
    enif_mutex_unlock(context->mutex);
    enif_release_resource(socket);
    return return_zmq_errno(env, ETERM);
  }

  socket->socket_index = context->socket_index++;
  enif_mutex_unlock(context->mutex);

  char buffer[64];
  
  sprintf(buffer, "erlzmq_socket_t_mutex_%" PRIu64, socket->socket_index);
  socket->mutex = enif_mutex_create(buffer);
  if (!socket->mutex) {
    enif_release_resource(socket);
    return return_zmq_errno(env, ENOMEM);
  }

  sprintf(buffer, "erlzmq_socket_t_socket_command_mutex_%" PRIu64, socket->socket_index);
  socket->socket_command_mutex = enif_mutex_create(buffer);
  if (!socket->socket_command_mutex) {
    enif_release_resource(socket);
    return return_zmq_errno(env, ENOMEM);
  }

  sprintf(buffer, "erlzmq_socket_t_socket_command_cond_%" PRIu64, socket->socket_index);
  socket->socket_command_cond = enif_cond_create(buffer);
  if (!socket->socket_command_cond) {
    enif_release_resource(socket);
    return return_zmq_errno(env, ENOMEM);
  }

  sprintf(buffer, "erlzmq_socket_t_socket_command_result_cond_%" PRIu64, socket->socket_index);
  socket->socket_command_result_cond = enif_cond_create(buffer);
  if (!socket->socket_command_result_cond) {
    enif_release_resource(socket);
    return return_zmq_errno(env, ENOMEM);
  }

  sprintf(buffer, "erlzmq_socket_t_thread_%" PRIu64, socket->socket_index);

  enif_mutex_lock(socket->socket_command_mutex);
  int value_errno = enif_thread_create(buffer, &socket->socket_thread, (void * (*)(void*))socket_thread, (void*)socket, NULL);
  if (value_errno != 0) {
    enif_mutex_unlock(socket->socket_command_mutex);
    enif_release_resource(socket);
    return return_zmq_errno(env, value_errno);
  }

  while (!socket->init_done) {
    enif_cond_wait(socket->socket_command_result_cond, socket->socket_command_mutex);
  }
  int init_errno = socket->init_errno;
  enif_mutex_unlock(socket->socket_command_mutex);

  if (init_errno != 0) {
    if (socket->socket_thread) {
      const int join_errno = enif_thread_join(socket->socket_thread, NULL);
      (void)join_errno;
      socket->socket_thread = 0;
    }
    enif_release_resource(socket);
    return return_zmq_errno(env, init_errno);
  }

  socket->status = ERLZMQ_SOCKET_STATUS_READY;

  ERL_NIF_TERM result = enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_tuple2(env,
                          enif_make_uint64(env, socket->socket_index),
                          enif_make_resource(env, socket)));
  // Release our reference - Erlang now owns the resource.
  // When Erlang's reference is GC'd, the destructor will be called.
  enif_release_resource(socket);
  return result;
}

NIF(erlzmq_nif_socket_command)
{
  erlzmq_socket_t * socket;
  if (! enif_get_resource(env, argv[0], erlzmq_nif_resource_socket,
                            (void **) &socket)) {
    return enif_make_badarg(env);
  }

  int command_id;

  if (! enif_get_int(env, argv[1], &command_id) || command_id < 0 || command_id >= SOCKET_COMMANDS_COUNT) {
    return enif_make_badarg(env);
  }

  int command_argc;
  const ERL_NIF_TERM* command_argv;

  if (! enif_get_tuple(env, argv[2], &command_argc, &command_argv)) {
    return enif_make_badarg(env);
  }

  enif_mutex_lock(socket->mutex);
  enif_mutex_lock(socket->socket_command_mutex);
  if (socket->status != ERLZMQ_SOCKET_STATUS_READY) {
    enif_mutex_unlock(socket->socket_command_mutex);
    enif_mutex_unlock(socket->mutex);
    return return_zmq_errno(env, ENOTSOCK);
  }
  if (socket->command_pending || socket->result_ready) {
    enif_mutex_unlock(socket->socket_command_mutex);
    enif_mutex_unlock(socket->mutex);
    return return_zmq_errno(env, EBUSY);
  }
  enif_mutex_unlock(socket->socket_command_mutex);

  erlzmq_socket_request_t req;
  clear_socket_request(&req);
  req.command_id = command_id;

  // Decode args in the calling thread (env/terms are not thread-safe).
  switch (command_id) {
    case 0: // bind
    case 1: // unbind
    case 2: // connect
    case 3: // disconnect
    {
      if (command_argc != 1) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      ErlNifBinary endpoint_bin;
      if (!enif_inspect_iolist_as_binary(env, command_argv[0], &endpoint_bin)) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      req.in.endpoint.endpoint = (char *) enif_alloc(endpoint_bin.size + 1);
      if (!req.in.endpoint.endpoint) {
        enif_mutex_unlock(socket->mutex);
        return return_zmq_errno(env, ENOMEM);
      }
      memcpy(req.in.endpoint.endpoint, endpoint_bin.data, endpoint_bin.size);
      req.in.endpoint.endpoint[endpoint_bin.size] = 0;
      req.in.endpoint.endpoint_len = endpoint_bin.size;
      break;
    }
    case 4: // send
    {
      if (command_argc != 2) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      ErlNifBinary binary;
      int flags;
      if (!enif_inspect_iolist_as_binary(env, command_argv[0], &binary)) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      if (!enif_get_int(env, command_argv[1], &flags)) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      req.in.send.data = (uint8_t *) enif_alloc(binary.size);
      if (!req.in.send.data && binary.size != 0) {
        enif_mutex_unlock(socket->mutex);
        return return_zmq_errno(env, ENOMEM);
      }
      if (binary.size != 0) {
        memcpy(req.in.send.data, binary.data, binary.size);
      }
      req.in.send.size = binary.size;
      req.in.send.flags = flags;
      break;
    }
    case 5: // recv
    {
      if (command_argc != 1) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      int flags;
      if (!enif_get_int(env, command_argv[0], &flags)) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      req.in.recv.flags = flags;
      break;
    }
    case 6: // setsockopt
    {
      if (command_argc != 2) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }

      int option_name;
      if (!enif_get_int(env, command_argv[0], &option_name)) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      req.in.setsockopt.option_name = option_name;

      ErlNifUInt64 value_uint64;
      ErlNifSInt64 value_int64;
      ErlNifBinary value_binary;
      int value_int;

      switch (option_name) {
        // uint64_t
        case ZMQ_AFFINITY:
        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
        case ZMQ_VMCI_BUFFER_SIZE:
        case ZMQ_VMCI_BUFFER_MIN_SIZE:
        case ZMQ_VMCI_BUFFER_MAX_SIZE:
        #endif
          if (!enif_get_uint64(env, command_argv[1], &value_uint64)) {
            free_socket_request(&req);
            enif_mutex_unlock(socket->mutex);
            return enif_make_badarg(env);
          }
          req.in.setsockopt.kind = 2;
          req.in.setsockopt.value.u64 = (uint64_t) value_uint64;
          req.in.setsockopt.option_len = sizeof(uint64_t);
          break;

        // int64_t
        case ZMQ_MAXMSGSIZE:
          if (!enif_get_int64(env, command_argv[1], &value_int64)) {
            free_socket_request(&req);
            enif_mutex_unlock(socket->mutex);
            return enif_make_badarg(env);
          }
          req.in.setsockopt.kind = 1;
          req.in.setsockopt.value.i64 = (int64_t) value_int64;
          req.in.setsockopt.option_len = sizeof(int64_t);
          break;

        // binary
        case ZMQ_CONNECT_ROUTING_ID:
        case ZMQ_ROUTING_ID:
        case ZMQ_SUBSCRIBE:
        case ZMQ_UNSUBSCRIBE:

        // deprecated
        case ZMQ_TCP_ACCEPT_FILTER:

        // character string
        case ZMQ_GSSAPI_PRINCIPAL:
        case ZMQ_GSSAPI_SERVICE_PRINCIPAL:

        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 3
        // string
        case ZMQ_BINDTODEVICE:
        #endif

        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
        // string
        case ZMQ_SOCKS_PROXY:
        // binary
        case ZMQ_XPUB_WELCOME_MSG:
        #endif

        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 0
        // string
        case ZMQ_ZAP_DOMAIN:
        case ZMQ_PLAIN_PASSWORD:
        case ZMQ_PLAIN_USERNAME:
        #endif
          if (!enif_inspect_iolist_as_binary(env, command_argv[1], &value_binary)) {
            free_socket_request(&req);
            enif_mutex_unlock(socket->mutex);
            return enif_make_badarg(env);
          }
          req.in.setsockopt.kind = 3;
          req.in.setsockopt.value.bytes.data = (uint8_t *) enif_alloc(value_binary.size);
          if (!req.in.setsockopt.value.bytes.data && value_binary.size != 0) {
            free_socket_request(&req);
            enif_mutex_unlock(socket->mutex);
            return return_zmq_errno(env, ENOMEM);
          }
          if (value_binary.size != 0) {
            memcpy(req.in.setsockopt.value.bytes.data, value_binary.data, value_binary.size);
          }
          req.in.setsockopt.value.bytes.size = value_binary.size;
          req.in.setsockopt.option_len = value_binary.size;
          break;

        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 0
        // binary or Z85 string
        case ZMQ_CURVE_PUBLICKEY:
        case ZMQ_CURVE_SECRETKEY:
        case ZMQ_CURVE_SERVERKEY:
        #endif
          if (!enif_inspect_iolist_as_binary(env, command_argv[1], &value_binary)) {
            free_socket_request(&req);
            enif_mutex_unlock(socket->mutex);
            return enif_make_badarg(env);
          }
          if (value_binary.size == 32) {
            req.in.setsockopt.kind = 3;
            req.in.setsockopt.value.bytes.data = (uint8_t *) enif_alloc(32);
            if (!req.in.setsockopt.value.bytes.data) {
              free_socket_request(&req);
              enif_mutex_unlock(socket->mutex);
              return return_zmq_errno(env, ENOMEM);
            }
            memcpy(req.in.setsockopt.value.bytes.data, value_binary.data, 32);
            req.in.setsockopt.value.bytes.size = 32;
            req.in.setsockopt.option_len = 32;
          } else if (value_binary.size == 40) {
            req.in.setsockopt.kind = 3;
            req.in.setsockopt.value.bytes.data = (uint8_t *) enif_alloc(41);
            if (!req.in.setsockopt.value.bytes.data) {
              free_socket_request(&req);
              enif_mutex_unlock(socket->mutex);
              return return_zmq_errno(env, ENOMEM);
            }
            memcpy(req.in.setsockopt.value.bytes.data, value_binary.data, 40);
            req.in.setsockopt.value.bytes.data[40] = 0;
            req.in.setsockopt.value.bytes.size = 41;
            req.in.setsockopt.option_len = 40;
          } else {
            free_socket_request(&req);
            enif_mutex_unlock(socket->mutex);
            return enif_make_badarg(env);
          }
          break;

        // int
        case ZMQ_BACKLOG:
        case ZMQ_LINGER:
        case ZMQ_MULTICAST_HOPS:
        case ZMQ_RATE:
        case ZMQ_RCVBUF:
        case ZMQ_RCVHWM:
        case ZMQ_RCVTIMEO:
        case ZMQ_RECONNECT_IVL:
        case ZMQ_RECONNECT_IVL_MAX:
        case ZMQ_RECOVERY_IVL:
        case ZMQ_ROUTER_MANDATORY:
        case ZMQ_SNDBUF:
        case ZMQ_SNDHWM:
        case ZMQ_SNDTIMEO:
        case ZMQ_TCP_KEEPALIVE:
        case ZMQ_TCP_KEEPALIVE_CNT:
        case ZMQ_TCP_KEEPALIVE_IDLE:
        case ZMQ_TCP_KEEPALIVE_INTVL:

        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 3
        case ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE:
        case ZMQ_GSSAPI_PRINCIPAL_NAMETYPE:
        #endif

        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
        case ZMQ_USE_FD:
        case ZMQ_VMCI_CONNECT_TIMEOUT:
        case ZMQ_MULTICAST_MAXTPDU:
        case ZMQ_TCP_MAXRT:
        case ZMQ_CONNECT_TIMEOUT:
        case ZMQ_XPUB_VERBOSER:
        case ZMQ_HEARTBEAT_TIMEOUT:
        case ZMQ_HEARTBEAT_TTL:
        case ZMQ_HEARTBEAT_IVL:
        case ZMQ_INVERT_MATCHING:
        case ZMQ_STREAM_NOTIFY:
        case ZMQ_XPUB_MANUAL:
        case ZMQ_HANDSHAKE_IVL:
        case ZMQ_XPUB_NODROP:
        #endif

        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 1
        case ZMQ_TOS:
        case ZMQ_ROUTER_HANDOVER:
        #endif

        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 0
        case ZMQ_ROUTER_RAW:
        case ZMQ_GSSAPI_PLAINTEXT:
        case ZMQ_GSSAPI_SERVER:
        case ZMQ_IMMEDIATE:
        case ZMQ_IPV6:
        case ZMQ_CURVE_SERVER:
        case ZMQ_CONFLATE:
        case ZMQ_REQ_RELAXED:
        case ZMQ_REQ_CORRELATE:
        case ZMQ_PROBE_ROUTER:
        case ZMQ_PLAIN_SERVER:
        #endif

        // deprecated
        case ZMQ_IPV4ONLY:
          if (!enif_get_int(env, command_argv[1], &value_int)) {
            free_socket_request(&req);
            enif_mutex_unlock(socket->mutex);
            return enif_make_badarg(env);
          }
          req.in.setsockopt.kind = 0;
          req.in.setsockopt.value.i32 = value_int;
          req.in.setsockopt.option_len = sizeof(int);
          break;
        default:
          free_socket_request(&req);
          enif_mutex_unlock(socket->mutex);
          return enif_make_badarg(env);
      }
      break;
    }
    case 7: // getsockopt
    {
      if (command_argc != 1) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      int option_name;
      if (!enif_get_int(env, command_argv[0], &option_name)) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      req.in.getsockopt.option_name = option_name;
      break;
    }
    case 8: // close
      if (command_argc != 0) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      break;
    case 9: // poll
    {
      if (command_argc != 2) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      int flags;
      ErlNifSInt64 timeout64;
      if (!enif_get_int(env, command_argv[0], &flags)) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      if (!enif_get_int64(env, command_argv[1], &timeout64)) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      req.in.poll.events = (short) flags;
      req.in.poll.timeout = (long) timeout64;
      break;
    }
    case 10: // send_multipart
    {
      if (command_argc != 2) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      unsigned n;
      if (!enif_get_list_length(env, command_argv[0], &n) || n == 0) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      int flags;
      if (!enif_get_int(env, command_argv[1], &flags)) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }

      req.in.send_multipart.parts = (uint8_t **) enif_alloc(sizeof(uint8_t *) * n);
      req.in.send_multipart.sizes = (size_t *) enif_alloc(sizeof(size_t) * n);
      if (!req.in.send_multipart.parts || !req.in.send_multipart.sizes) {
        free_socket_request(&req);
        enif_mutex_unlock(socket->mutex);
        return return_zmq_errno(env, ENOMEM);
      }
      memset(req.in.send_multipart.parts, 0, sizeof(uint8_t *) * n);
      memset(req.in.send_multipart.sizes, 0, sizeof(size_t) * n);
      req.in.send_multipart.part_count = n;
      req.in.send_multipart.flags = flags;

      ERL_NIF_TERM head, tail = command_argv[0];
      for (unsigned i = 0; i < n; i++) {
        if (!enif_get_list_cell(env, tail, &head, &tail)) {
          free_socket_request(&req);
          enif_mutex_unlock(socket->mutex);
          return enif_make_badarg(env);
        }
        ErlNifBinary binary;
        if (!enif_inspect_iolist_as_binary(env, head, &binary)) {
          free_socket_request(&req);
          enif_mutex_unlock(socket->mutex);
          return enif_make_badarg(env);
        }
        req.in.send_multipart.parts[i] = (uint8_t *) enif_alloc(binary.size);
        if (!req.in.send_multipart.parts[i] && binary.size != 0) {
          free_socket_request(&req);
          enif_mutex_unlock(socket->mutex);
          return return_zmq_errno(env, ENOMEM);
        }
        if (binary.size != 0) {
          memcpy(req.in.send_multipart.parts[i], binary.data, binary.size);
        }
        req.in.send_multipart.sizes[i] = binary.size;
      }
      break;
    }
    case 11: // recv_multipart
    {
      if (command_argc != 1) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      int flags;
      if (!enif_get_int(env, command_argv[0], &flags)) {
        enif_mutex_unlock(socket->mutex);
        return enif_make_badarg(env);
      }
      req.in.recv_multipart.flags = flags;
      break;
    }
    default:
      enif_mutex_unlock(socket->mutex);
      return enif_make_badarg(env);
  }

  enif_mutex_lock(socket->socket_command_mutex);
  socket->request = req;
  clear_socket_request(&req);
  socket->command_pending = 1;
  socket->result_ready = 0;
  enif_cond_signal(socket->socket_command_cond);

  while (!socket->result_ready) {
    enif_cond_wait(socket->socket_command_result_cond, socket->socket_command_mutex);
  }

  erlzmq_socket_reply_t reply = socket->reply;
  clear_socket_reply(&socket->reply);
  erlzmq_socket_request_t req_cleanup = socket->request;
  clear_socket_request(&socket->request);
  socket->result_ready = 0;

  enif_mutex_unlock(socket->socket_command_mutex);

  ERL_NIF_TERM result = 0;
  if (!reply.ok) {
    result = return_zmq_errno(env, reply.err);
  } else {
    switch (reply.kind) {
      case ERLZMQ_SOCKET_REPLY_NONE:
        result = enif_make_atom(env, "ok");
        break;
      case ERLZMQ_SOCKET_REPLY_INT:
        result = enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_int(env, reply.out.i32));
        break;
      case ERLZMQ_SOCKET_REPLY_INT64:
        result = enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_int64(env, reply.out.i64));
        break;
      case ERLZMQ_SOCKET_REPLY_UINT64:
        result = enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_uint64(env, reply.out.u64));
        break;
      case ERLZMQ_SOCKET_REPLY_BYTES:
      {
        ERL_NIF_TERM binary_term;
        unsigned char *binary = enif_make_new_binary(env, reply.out.bytes.size, &binary_term);
        if (!binary && reply.out.bytes.size != 0) {
          result = return_zmq_errno(env, ENOMEM);
          break;
        }
        if (reply.out.bytes.size != 0) {
          memcpy(binary, reply.out.bytes.data, reply.out.bytes.size);
        }
        result = enif_make_tuple2(env, enif_make_atom(env, "ok"), binary_term);
        break;
      }
      case ERLZMQ_SOCKET_REPLY_MULTIPART:
      {
        ERL_NIF_TERM list = enif_make_list_from_array(env, NULL, 0);
        for (size_t i = reply.out.multipart.part_count; i-- > 0;) {
          ERL_NIF_TERM binary_term;
          unsigned char *binary = enif_make_new_binary(env, reply.out.multipart.sizes[i], &binary_term);
          if (!binary && reply.out.multipart.sizes[i] != 0) {
            result = return_zmq_errno(env, ENOMEM);
            break;
          }
          if (reply.out.multipart.sizes[i] != 0) {
            memcpy(binary, reply.out.multipart.parts[i], reply.out.multipart.sizes[i]);
          }
          list = enif_make_list_cell(env, binary_term, list);
        }
        if (result == 0) {
          result = enif_make_tuple2(env, enif_make_atom(env, "ok"), list);
        }
        break;
      }
      default:
        result = return_zmq_errno(env, EINVAL);
        break;
    }
  }

  // Don't release here - Erlang GC will call the destructor
  free_socket_request(&req_cleanup);
  free_socket_reply(&reply);

  enif_mutex_unlock(socket->mutex);
  return result;
}

#if 0
// Legacy per-socket-thread command implementations that used ErlNifEnv/ERL_NIF_TERM
// from another OS thread. Kept for reference only; do not compile or use.
SOCKET_COMMAND(erlzmq_socket_command_bind)
{
  assert(argc == 1);
  unsigned endpoint_length;

  if (! enif_get_list_length(env, argv[0], &endpoint_length)) {
    return enif_make_badarg(env);
  }

  char * endpoint = (char *) malloc(endpoint_length + 1);
  if (!endpoint) {
    return return_zmq_errno(env, ENOMEM);
  }
  if (! enif_get_string(env, argv[0], endpoint, endpoint_length + 1,
                        ERL_NIF_LATIN1)) {
    free(endpoint);
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM result;
  assert(socket->socket_zmq);
  if (zmq_bind(socket->socket_zmq, endpoint)) {
    result = return_zmq_errno(env, zmq_errno());
  }
  else {
    result = enif_make_atom(env, "ok");
  }

  free(endpoint);

  return result;
}

SOCKET_COMMAND(erlzmq_socket_command_unbind)
{
  assert(argc == 1);
  unsigned endpoint_length;

  if (! enif_get_list_length(env, argv[0], &endpoint_length)) {
    return enif_make_badarg(env);
  }

  char * endpoint = (char *) malloc(endpoint_length + 1);
  if (!endpoint) {
    return return_zmq_errno(env, ENOMEM);
  }
  if (! enif_get_string(env, argv[0], endpoint, endpoint_length + 1,
                        ERL_NIF_LATIN1)) {
    free(endpoint);
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM result;
  assert(socket->socket_zmq);
  if (zmq_unbind(socket->socket_zmq, endpoint)) {
    result = return_zmq_errno(env, zmq_errno());
  }
  else {
    result = enif_make_atom(env, "ok");
  }

  free(endpoint);

  return result;
}

SOCKET_COMMAND(erlzmq_socket_command_connect)
{
  assert(argc == 1);
  unsigned endpoint_length;

  if (! enif_get_list_length(env, argv[0], &endpoint_length)) {
    return enif_make_badarg(env);
  }

  char * endpoint = (char *) malloc(endpoint_length + 1);
  if (!endpoint) {
    return return_zmq_errno(env, ENOMEM);
  }
  if (! enif_get_string(env, argv[0], endpoint, endpoint_length + 1,
                        ERL_NIF_LATIN1)) {
    free(endpoint);
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM result;
  assert(socket->socket_zmq);
  if (zmq_connect(socket->socket_zmq, endpoint)) {
    result = return_zmq_errno(env, zmq_errno());
  }
  else {
    result = enif_make_atom(env, "ok");
  }

  free(endpoint);

  return result;
}

SOCKET_COMMAND(erlzmq_socket_command_disconnect)
{
  assert(argc == 1);
  unsigned endpoint_length;

  if (! enif_get_list_length(env, argv[0], &endpoint_length)) {
    return enif_make_badarg(env);
  }

  char * endpoint = (char *) malloc(endpoint_length + 1);
  if (!endpoint) {
    return return_zmq_errno(env, ENOMEM);
  }
  if (! enif_get_string(env, argv[0], endpoint, endpoint_length + 1,
                        ERL_NIF_LATIN1)) {
    free(endpoint);
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM result;
  assert(socket->socket_zmq);
  if (zmq_disconnect(socket->socket_zmq, endpoint)) {
    result = return_zmq_errno(env, zmq_errno());
  }
  else {
    result = enif_make_atom(env, "ok");
  }

  free(endpoint);

  return result;
}

SOCKET_COMMAND(erlzmq_socket_command_setsockopt)
{
  assert(argc == 2);
  int option_name;

  if (! enif_get_int(env, argv[0], &option_name)) {
    return enif_make_badarg(env);
  }

  ErlNifUInt64 value_uint64;
  ErlNifSInt64 value_int64;
  ErlNifBinary value_binary;
  uint8_t z85_str[41];
  int value_int;
  void *option_value;
  size_t option_len;
  switch (option_name) {
    // uint64_t
    case ZMQ_AFFINITY:

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
    case ZMQ_VMCI_BUFFER_SIZE:
    case ZMQ_VMCI_BUFFER_MIN_SIZE:
    case ZMQ_VMCI_BUFFER_MAX_SIZE:
    #endif
      if (! enif_get_uint64(env, argv[1], &value_uint64)) {
        return enif_make_badarg(env);
      }
      option_value = &value_uint64;
      option_len = sizeof(int64_t);
      break;

    // int64_t
    case ZMQ_MAXMSGSIZE:
      if (! enif_get_int64(env, argv[1], &value_int64)) {
        return enif_make_badarg(env);
      }
      option_value = &value_int64;
      option_len = sizeof(int64_t);
      break;

    // binary
    case ZMQ_CONNECT_ROUTING_ID:
    case ZMQ_ROUTING_ID:
    case ZMQ_SUBSCRIBE:
    case ZMQ_UNSUBSCRIBE:

    // deprecated
    case ZMQ_TCP_ACCEPT_FILTER:
    
    // character string
    case ZMQ_GSSAPI_PRINCIPAL:
    case ZMQ_GSSAPI_SERVICE_PRINCIPAL:

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 3
    // string
    case ZMQ_BINDTODEVICE:
    #endif

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
    // string
    case ZMQ_SOCKS_PROXY:
    // binary
    case ZMQ_XPUB_WELCOME_MSG:
    #endif

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 0
    // string
    case ZMQ_ZAP_DOMAIN:
    case ZMQ_PLAIN_PASSWORD:
    case ZMQ_PLAIN_USERNAME:
    #endif
      if (! enif_inspect_iolist_as_binary(env, argv[1], &value_binary)) {
        return enif_make_badarg(env);
      }
      option_value = value_binary.data;
      option_len = value_binary.size;
      break;
    
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 0
    // binary or Z85 string
    case ZMQ_CURVE_PUBLICKEY:
    case ZMQ_CURVE_SECRETKEY:
    case ZMQ_CURVE_SERVERKEY:
    #endif
      if (! enif_inspect_iolist_as_binary(env, argv[1], &value_binary)) {
        return enif_make_badarg(env);
      }
      if (value_binary.size == 32) {
        // binary
        option_value = value_binary.data;
        option_len = value_binary.size;
      } else if (value_binary.size == 40) {
        // z85-encoded
        memcpy(z85_str, value_binary.data, 40);
        z85_str[40] = 0;
        option_value = z85_str;
        option_len = 40;
      } else {
        // XXX Perhaps should give reason for failure
        return enif_make_badarg(env);
      }
      break;
      
    // int
    case ZMQ_BACKLOG:
    case ZMQ_LINGER:
    case ZMQ_MULTICAST_HOPS:
    case ZMQ_RATE:
    case ZMQ_RCVBUF:
    case ZMQ_RCVHWM:
    case ZMQ_RCVTIMEO:
    case ZMQ_RECONNECT_IVL:
    case ZMQ_RECONNECT_IVL_MAX:
    case ZMQ_RECOVERY_IVL:
    case ZMQ_ROUTER_MANDATORY:
    case ZMQ_SNDBUF:
    case ZMQ_SNDHWM:
    case ZMQ_SNDTIMEO:
    case ZMQ_TCP_KEEPALIVE:
    case ZMQ_TCP_KEEPALIVE_CNT:
    case ZMQ_TCP_KEEPALIVE_IDLE:
    case ZMQ_TCP_KEEPALIVE_INTVL:
    case ZMQ_XPUB_VERBOSE:
    
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 3
    case ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE:
    case ZMQ_GSSAPI_PRINCIPAL_NAMETYPE:
    #endif

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
    case ZMQ_USE_FD:
    case ZMQ_VMCI_CONNECT_TIMEOUT:
    case ZMQ_MULTICAST_MAXTPDU:
    case ZMQ_TCP_MAXRT:
    case ZMQ_CONNECT_TIMEOUT:
    case ZMQ_XPUB_VERBOSER:
    case ZMQ_HEARTBEAT_TIMEOUT:
    case ZMQ_HEARTBEAT_TTL:
    case ZMQ_HEARTBEAT_IVL:
    case ZMQ_INVERT_MATCHING:
    case ZMQ_STREAM_NOTIFY:
    case ZMQ_XPUB_MANUAL:
    case ZMQ_HANDSHAKE_IVL:
    case ZMQ_XPUB_NODROP:
    #endif

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 1
    case ZMQ_TOS:
    case ZMQ_ROUTER_HANDOVER:
    #endif

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 0
    case ZMQ_ROUTER_RAW:
    case ZMQ_GSSAPI_PLAINTEXT:
    case ZMQ_GSSAPI_SERVER:
    case ZMQ_IMMEDIATE:
    case ZMQ_IPV6:
    case ZMQ_CURVE_SERVER:
    case ZMQ_CONFLATE:
    case ZMQ_REQ_RELAXED:
    case ZMQ_REQ_CORRELATE:
    case ZMQ_PROBE_ROUTER:
    case ZMQ_PLAIN_SERVER:
    #endif

    // deprecated
    case ZMQ_IPV4ONLY:
      if (! enif_get_int(env, argv[1], &value_int)) {
        return enif_make_badarg(env);
      }
      option_value = &value_int;
      option_len = sizeof(int);
      break;
    default:
      return enif_make_badarg(env);
  }

  assert(socket->socket_zmq);
  if (zmq_setsockopt(socket->socket_zmq, option_name,
                          option_value, option_len)) {
    return return_zmq_errno(env, zmq_errno());
  }
  else {
    return enif_make_atom(env, "ok");
  }
}

SOCKET_COMMAND(erlzmq_socket_command_getsockopt)
{
  assert(argc == 1);
  int option_name;

  if (! enif_get_int(env, argv[0], &option_name)) {
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM value_binary_term;
  unsigned char *value_binary;
  int64_t value_int64;
  uint64_t value_uint64;
  char option_value[256];
  int value_int;
  size_t option_len;

  switch(option_name) {
    // int64_t
    case ZMQ_MAXMSGSIZE:
      option_len = sizeof(value_int64);
      assert(socket->socket_zmq);
      if (zmq_getsockopt(socket->socket_zmq, option_name,
                              &value_int64, &option_len)) {
        return return_zmq_errno(env, zmq_errno());
      }
      return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                              enif_make_int64(env, value_int64));
    // uint64_t
    case ZMQ_AFFINITY:
    
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
    case ZMQ_VMCI_BUFFER_SIZE:
    case ZMQ_VMCI_BUFFER_MIN_SIZE:
    case ZMQ_VMCI_BUFFER_MAX_SIZE:
    #endif
      option_len = sizeof(value_uint64);
      assert(socket->socket_zmq);
      if (zmq_getsockopt(socket->socket_zmq, option_name,
                              &value_uint64, &option_len)) {
        return return_zmq_errno(env, zmq_errno());
      }
      return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                              enif_make_uint64(env, value_uint64));
    // binary
    case ZMQ_ROUTING_ID:

    // string
    case ZMQ_GSSAPI_PRINCIPAL:
    case ZMQ_GSSAPI_SERVICE_PRINCIPAL:
    case ZMQ_LAST_ENDPOINT:
    
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 3
    // string
    case ZMQ_BINDTODEVICE:
    #endif
    
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
    // string
    case ZMQ_SOCKS_PROXY:
    #endif

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 0
    // string
    case ZMQ_ZAP_DOMAIN:
    case ZMQ_PLAIN_PASSWORD:
    case ZMQ_PLAIN_USERNAME:
    
    // binary or Z85 string
    case ZMQ_CURVE_PUBLICKEY:
    case ZMQ_CURVE_SECRETKEY:
    case ZMQ_CURVE_SERVERKEY:
    #endif
      option_len = sizeof(option_value);
      assert(socket->socket_zmq);
      if (zmq_getsockopt(socket->socket_zmq, option_name,
                              option_value, &option_len)) {
        return return_zmq_errno(env, zmq_errno());
      }
      value_binary = enif_make_new_binary(env, option_len, &value_binary_term);
      if (!value_binary) {
        return return_zmq_errno(env, ENOMEM);
      }
      memcpy(value_binary, option_value, option_len);
      return enif_make_tuple2(env, enif_make_atom(env, "ok"), value_binary_term);
    // int
    case ZMQ_BACKLOG:
    case ZMQ_LINGER:
    case ZMQ_MULTICAST_HOPS:
    case ZMQ_RATE:
    case ZMQ_RCVBUF:
    case ZMQ_RCVHWM:
    case ZMQ_RCVTIMEO:
    case ZMQ_RECONNECT_IVL:
    case ZMQ_RECONNECT_IVL_MAX:
    case ZMQ_RECOVERY_IVL:
    case ZMQ_SNDBUF:
    case ZMQ_SNDHWM:
    case ZMQ_SNDTIMEO:
    case ZMQ_TCP_KEEPALIVE:
    case ZMQ_TCP_KEEPALIVE_CNT:
    case ZMQ_TCP_KEEPALIVE_IDLE:
    case ZMQ_TCP_KEEPALIVE_INTVL:
    case ZMQ_RCVMORE:
    case ZMQ_EVENTS:
    case ZMQ_TYPE:
    
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 3
    case ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE:
    case ZMQ_GSSAPI_PRINCIPAL_NAMETYPE:
    #endif

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
    case ZMQ_USE_FD:
    case ZMQ_VMCI_CONNECT_TIMEOUT:
    case ZMQ_MULTICAST_MAXTPDU:
    case ZMQ_THREAD_SAFE:
    case ZMQ_TCP_MAXRT:
    case ZMQ_CONNECT_TIMEOUT:
    case ZMQ_INVERT_MATCHING:
    case ZMQ_HANDSHAKE_IVL:
    #endif

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 1
    case ZMQ_TOS:
    #endif

    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 0
    case ZMQ_IMMEDIATE:
    case ZMQ_IPV6:
    case ZMQ_CURVE_SERVER:
    case ZMQ_GSSAPI_PLAINTEXT:
    case ZMQ_GSSAPI_SERVER:
    case ZMQ_PLAIN_SERVER:
    case ZMQ_MECHANISM:
    #endif
    // FIXME SOCKET on Windows, int on POSIX
    case ZMQ_FD:

    // deprecated
    case ZMQ_IPV4ONLY:
      option_len = sizeof(value_int);
      assert(socket->socket_zmq);
      if (zmq_getsockopt(socket->socket_zmq, option_name,
                              &value_int, &option_len)) {
        return return_zmq_errno(env, zmq_errno());
      }
      return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                              enif_make_int(env, value_int));
    default:
      return enif_make_badarg(env);
  }
}

SOCKET_COMMAND(erlzmq_socket_command_send)
{
  assert(argc == 2);
  ErlNifBinary binary;
  int flags;
  zmq_msg_t msg;

  if (! enif_inspect_iolist_as_binary(env, argv[0], &binary)) {
    return enif_make_badarg(env);
  }

  if (! enif_get_int(env, argv[1], &flags)) {
    return enif_make_badarg(env);
  }

  if (zmq_msg_init_size(&msg, binary.size)) {
    return return_zmq_errno(env, zmq_errno());
  }

  memcpy(zmq_msg_data(&msg), binary.data, binary.size);

  ERL_NIF_TERM result;
  assert(socket->socket_zmq);
  if (zmq_msg_send(&msg, socket->socket_zmq, flags) == -1) {
    int const error = zmq_errno();
    const int ret = zmq_msg_close(&msg);
    assert(ret == 0);
    result = return_zmq_errno(env, error);
  }
  else {
    // You do not need to call zmq_msg_close() after a successful zmq_msg_send().
    result = enif_make_atom(env, "ok");
  }

  return result;
}

SOCKET_COMMAND(erlzmq_socket_command_send_multipart)
{
  assert(argc == 2);
  int flags;

  assert(socket->socket_zmq);

  unsigned n;
  if (! enif_get_list_length(env, argv[0], &n) || n == 0) {
    return enif_make_badarg(env);
  }

  if (! enif_get_int(env, argv[1], &flags)) {
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM result = enif_make_atom(env, "ok");
  ERL_NIF_TERM head, tail;

  unsigned int initialized_messages = 0, sent_messages = 0;
  zmq_msg_t *msg = enif_alloc(n * sizeof(zmq_msg_t));
  if (! msg) {
    return return_zmq_errno(env, ENOMEM);
  }

  enif_get_list_cell(env, argv[0], &head, &tail);
  for (unsigned int i = 0; i < n; i++) {
    ErlNifBinary binary;
    if (! enif_inspect_iolist_as_binary(env, head, &binary)) {
      result = enif_make_badarg(env);
      goto cleanup;
    }
    if (zmq_msg_init_size(&msg[i], binary.size)) {
      result = return_zmq_errno(env, zmq_errno());
      goto cleanup;
    }
    initialized_messages++;
    memcpy(zmq_msg_data(&msg[i]), binary.data, binary.size);
    enif_get_list_cell(env, tail, &head, &tail);
  }

  for (; sent_messages < n;) {
    int sndmore = (sent_messages < n - 1) ? ZMQ_SNDMORE : 0;
    if (zmq_msg_send(&msg[sent_messages], socket->socket_zmq, flags|sndmore) == -1) {
      if (zmq_errno() == EINTR && sent_messages>0)
        continue;
      result = return_zmq_errno(env, zmq_errno());
      goto cleanup;
    }
    sent_messages++;
  }

 cleanup:
  // You do not need to call zmq_msg_close() after a successful zmq_msg_send().
  for (unsigned int i = sent_messages; i < initialized_messages; i++) {
    const int ret = zmq_msg_close(&msg[i]);
    assert(ret == 0);
  }
  enif_free(msg);
  return result;
}

SOCKET_COMMAND(erlzmq_socket_command_recv)
{
  assert(argc == 1);
  int flags;

  if (! enif_get_int(env, argv[0], &flags)) {
    return enif_make_badarg(env);
  }

  zmq_msg_t msg;
  if (zmq_msg_init(&msg)) {
    return return_zmq_errno(env, zmq_errno());
  }

  ERL_NIF_TERM result;

  assert(socket->socket_zmq);
  if (zmq_msg_recv(&msg, socket->socket_zmq, flags) == -1) {
    int const error = zmq_errno();
    result = return_zmq_errno(env, error);
  }
  else {
    ERL_NIF_TERM binary_term;
    unsigned char *binary = enif_make_new_binary(env, zmq_msg_size(&msg), &binary_term);
    if (! binary) {
      const int ret = zmq_msg_close(&msg);
      assert(ret == 0);
      return return_zmq_errno(env, ENOMEM);
    }

    memcpy(binary, zmq_msg_data(&msg), zmq_msg_size(&msg));

    result = enif_make_tuple2(env, enif_make_atom(env, "ok"), binary_term);
  }

  const int ret = zmq_msg_close(&msg);
  assert(ret == 0);

  return result;
}

SOCKET_COMMAND(erlzmq_socket_command_recv_multipart)
{
  assert(argc == 1);
  int flags;

  if (! enif_get_int(env, argv[0], &flags)) {
    return enif_make_badarg(env);
  }

  assert(socket->socket_zmq);

  ERL_NIF_TERM list = enif_make_list_from_array(env, NULL, 0);

  for (int i = 0;;) {
    zmq_msg_t msg;
    if (zmq_msg_init(&msg)) {
      return return_zmq_errno(env, zmq_errno());
    }

    if (zmq_msg_recv(&msg, socket->socket_zmq, flags) == -1) {
      const int ret = zmq_msg_close(&msg);
      assert(ret == 0);
      if (zmq_errno() == EINTR && i > 0) {
        continue;
      }
      return return_zmq_errno(env, zmq_errno());
    }
    i++;

    int msg_size = zmq_msg_size(&msg);
    ERL_NIF_TERM binary_term;
    unsigned char *binary = enif_make_new_binary(env, msg_size, &binary_term);
    if (!binary) {
      const int ret = zmq_msg_close(&msg);
      assert(ret == 0);
      return return_zmq_errno(env, ENOMEM);
    }

    memcpy(binary, zmq_msg_data(&msg), msg_size);
    list = enif_make_list_cell(env, binary_term, list);

    zmq_msg_close(&msg);

    int rcvmore;
    size_t len = sizeof(int);
    if (zmq_getsockopt(socket->socket_zmq, ZMQ_RCVMORE, &rcvmore, &len)) {
      return return_zmq_errno(env, zmq_errno());
    }

    if (! rcvmore)
      break;
  }

  ERL_NIF_TERM result;
  enif_make_reverse_list(env, list, &result);
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), result);
}

SOCKET_COMMAND(erlzmq_socket_command_poll)
{
  assert(argc == 2);
  int flags;
  long timeout;

  if (! enif_get_int(env, argv[0], &flags)) {
    return enif_make_badarg(env);
  }

  if (! enif_get_int64(env, argv[1], &timeout)) {
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM result;
  zmq_pollitem_t items [1];

  assert(socket->socket_zmq);
  items[0].socket = socket->socket_zmq;
  items[0].events = (short)flags;

  int res = zmq_poll(items, 1, timeout);
  if (res == -1) {
    int const error = zmq_errno();
    result = return_zmq_errno(env, error);
  }
  else {
    result = enif_make_tuple2(env, enif_make_atom(env, "ok"),
                            enif_make_int(env, items[0].revents));
  }

  return result;
}

SOCKET_COMMAND(erlzmq_socket_command_close)
{
  assert(argc == 0);
  assert(socket->socket_zmq);

  if (zmq_close(socket->socket_zmq) != 0) {
    int const error = zmq_errno();
    return return_zmq_errno(env, error);
  }
  else {
    socket->socket_zmq = 0;
    socket->status = ERLZMQ_SOCKET_STATUS_CLOSED;

    enif_release_resource(socket);

    return enif_make_atom(env, "ok");
  }
}
#endif

NIF(erlzmq_nif_term)
{
  erlzmq_context_t * context;

  if (! enif_get_resource(env, argv[0], erlzmq_nif_resource_context,
                          (void **) &context)) {
    return enif_make_badarg(env);
  }

  assert(context->mutex);
  enif_mutex_lock(context->mutex);

  if (context->status != ERLZMQ_CONTEXT_STATUS_READY) {
    enif_mutex_unlock(context->mutex);
    return return_zmq_errno(env, ETERM);
  }

  context->status = ERLZMQ_CONTEXT_STATUS_TERMINATING;

  enif_mutex_unlock(context->mutex);

  if (zmq_term(context->context_zmq) != 0) {
    int const error = zmq_errno();
    
    enif_mutex_lock(context->mutex);
    context->status = ERLZMQ_CONTEXT_STATUS_READY;
    enif_mutex_unlock(context->mutex);

    return return_zmq_errno(env, error);
  }
  else {
    enif_mutex_lock(context->mutex);
    context->status = ERLZMQ_CONTEXT_STATUS_TERMINATED;
    context->context_zmq = NULL;
    enif_mutex_unlock(context->mutex);

    // Don't release here - Erlang GC will call the destructor
    return enif_make_atom(env, "ok");
  }
}

NIF(erlzmq_nif_ctx_set)
{
  erlzmq_context_t * context;

  if (! enif_get_resource(env, argv[0], erlzmq_nif_resource_context,
                          (void **) &context)) {
    return enif_make_badarg(env);
  }

  int option_name;

  if (! enif_get_int(env, argv[1], &option_name)) {
    return enif_make_badarg(env);
  }

  int value_int;
  switch (option_name) {
    // int
    case ZMQ_IO_THREADS:
    case ZMQ_MAX_SOCKETS:
    case ZMQ_IPV6:
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 1
    case ZMQ_THREAD_SCHED_POLICY:
    case ZMQ_THREAD_PRIORITY:
    #endif
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
    case ZMQ_BLOCKY:
    case ZMQ_MAX_MSGSZ:
    #endif
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 3
    case ZMQ_THREAD_AFFINITY_CPU_ADD:
    case ZMQ_THREAD_AFFINITY_CPU_REMOVE:
    case ZMQ_THREAD_NAME_PREFIX:
    #endif
      if (! enif_get_int(env, argv[2], &value_int)) {
        return enif_make_badarg(env);
      }
      break;
    default:
      return enif_make_badarg(env);
  }

  assert(context->mutex);
  enif_mutex_lock(context->mutex);
  if (context->status != ERLZMQ_CONTEXT_STATUS_READY) {
    enif_mutex_unlock(context->mutex);
    return return_zmq_errno(env, ETERM);
  }
  assert(context->context_zmq);
  if (zmq_ctx_set(context->context_zmq, option_name,
                          value_int)) {
    enif_mutex_unlock(context->mutex);
    return return_zmq_errno(env, zmq_errno());
  }
  else {
    enif_mutex_unlock(context->mutex);
    return enif_make_atom(env, "ok");
  }
}

NIF(erlzmq_nif_ctx_get)
{
  erlzmq_context_t * context;
  int option_name;

  if (! enif_get_resource(env, argv[0], erlzmq_nif_resource_context,
                          (void **) &context)) {
    return enif_make_badarg(env);
  }

  if (! enif_get_int(env, argv[1], &option_name)) {
    return enif_make_badarg(env);
  }

  int value_int;
  switch(option_name) {
    // int
    case ZMQ_IO_THREADS:
    case ZMQ_MAX_SOCKETS:
    case ZMQ_IPV6:
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 1
    case ZMQ_SOCKET_LIMIT:
    case ZMQ_THREAD_SCHED_POLICY:
    #endif
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
    case ZMQ_MAX_MSGSZ:
    case ZMQ_BLOCKY:
    #endif
    #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 3
    case ZMQ_THREAD_NAME_PREFIX:
    case ZMQ_MSG_T_SIZE:
    #endif
      assert(context->mutex);
      enif_mutex_lock(context->mutex);
      if (context->status != ERLZMQ_CONTEXT_STATUS_READY) {
        enif_mutex_unlock(context->mutex);
        return return_zmq_errno(env, ETERM);
      }
      assert(context->context_zmq);
      value_int = zmq_ctx_get(context->context_zmq, option_name);
      if (value_int == -1) {
        enif_mutex_unlock(context->mutex);
        return return_zmq_errno(env, zmq_errno());
      }

      enif_mutex_unlock(context->mutex);
      return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                              enif_make_int(env, value_int));
    default:
      return enif_make_badarg(env);
  }
}

NIF(erlzmq_nif_curve_keypair)
{
  char public[41];
  char secret[41];
  ERL_NIF_TERM pub_bin_term;
  ERL_NIF_TERM sec_bin_term;
  if (zmq_curve_keypair(public, secret)) {
    return return_zmq_errno(env, zmq_errno());
  }
  unsigned char *pub_bin = enif_make_new_binary(env, 40, &pub_bin_term);
  if (!pub_bin) {
      return return_zmq_errno(env, ENOMEM);
  }
  unsigned char *sec_bin = enif_make_new_binary(env, 40, &sec_bin_term);
  if (!sec_bin) {
      return return_zmq_errno(env, ENOMEM);
  }
  memcpy(pub_bin, public, 40);
  memcpy(sec_bin, secret, 40);
  return enif_make_tuple3(env, enif_make_atom(env, "ok"), pub_bin_term, sec_bin_term);
}

NIF(erlzmq_nif_z85_decode)
{
  ErlNifBinary value_binary;
  if (! enif_inspect_iolist_as_binary(env, argv[0], &value_binary)) {
    return enif_make_badarg(env);
  }
  if (value_binary.size % 5 != 0) { 
    return enif_make_badarg(env);
  }
  // 0-terminate the string
  size_t z85_size = value_binary.size;
  size_t dec_size = z85_size / 5 * 4;
  char *z85buf = (char*) malloc(z85_size+1);
  if (!z85buf) {
      return return_zmq_errno(env, ENOMEM);
  }
  memcpy(z85buf, value_binary.data, value_binary.size);
  z85buf[value_binary.size] = 0;

  ERL_NIF_TERM dec_bin_term;
  ERL_NIF_TERM ret;
  unsigned char *dec_bin = enif_make_new_binary(env, dec_size, &dec_bin_term);
  if (!dec_bin) {
      free(z85buf);
      return return_zmq_errno(env, ENOMEM);
  }
  if (zmq_z85_decode (dec_bin, z85buf) == NULL) {
    ret = return_zmq_errno(env, zmq_errno());
  } else {
    ret = enif_make_tuple2(env, enif_make_atom(env, "ok"), dec_bin_term);
  }
  free(z85buf);
  return ret;
}

NIF(erlzmq_nif_z85_encode)
{
  ErlNifBinary value_binary;
  if (! enif_inspect_iolist_as_binary(env, argv[0], &value_binary)) {
    return enif_make_badarg(env);
  }
  if (value_binary.size % 4 != 0) { 
    return enif_make_badarg(env);
  }

  size_t z85_size = value_binary.size;
  size_t enc_size = z85_size / 4 * 5;

  // need to accomodate NULL terminator
  char *z85buf = (char*) malloc(enc_size+1);
  if (!z85buf) {
    return return_zmq_errno(env, ENOMEM);
  }

  ERL_NIF_TERM ret;

  if (zmq_z85_encode(z85buf, value_binary.data, value_binary.size) == NULL) {
    ret = return_zmq_errno(env, zmq_errno());
  } else {
    ERL_NIF_TERM enc_bin_term;
    unsigned char *enc_bin = enif_make_new_binary(env, enc_size, &enc_bin_term);
    if (!enc_bin) {
      free(z85buf);
      return return_zmq_errno(env, ENOMEM);
    }

    // drop NULL terminator
    memcpy(enc_bin, z85buf, enc_size);
    ret = enif_make_tuple2(env, enif_make_atom(env, "ok"), enc_bin_term);
  }
  free(z85buf);
  return ret;
}

NIF(erlzmq_nif_has)
{
  unsigned capability_length;

  if (! enif_get_atom_length(env, argv[0], &capability_length, ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }

  char * capability = (char *) malloc(capability_length + 1);
  if (!capability) {
    return return_zmq_errno(env, ENOMEM);
  }
  if (! enif_get_atom(env, argv[0], capability, capability_length + 1,
                        ERL_NIF_LATIN1)) {
    free(capability);
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM result;
#ifdef ZMQ_HAS_CAPABILITIES
  if (zmq_has(capability) == 1) {
    result = enif_make_atom(env, "true");
  }
  else {
    result = enif_make_atom(env, "false");
  }
#else
  // version < 4.1
  result = enif_make_atom(env, "unknown");
#endif

  free(capability);

  return result;
}

NIF(erlzmq_nif_version)
{
  int major, minor, patch;
  zmq_version(&major, &minor, &patch);
  return enif_make_tuple3(env, enif_make_int(env, major),
                          enif_make_int(env, minor),
                          enif_make_int(env, patch));
}

static ERL_NIF_TERM return_zmq_errno(ErlNifEnv* env, int const value)
{
  switch (value) {
    case EPERM:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eperm"));
    case ENOENT:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enoent"));
    case ESRCH:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "esrch"));
    case EINTR:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eintr"));
    case EIO:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eio"));
    case ENXIO:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enxio"));
    case ENOEXEC:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enoexec"));
    case EBADF:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "ebadf"));
    case ECHILD:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "echild"));
    case EDEADLK:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "edeadlk"));
    case ENOMEM:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enomem"));
    case EACCES:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eacces"));
    case EFAULT:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "efault"));
    case ENOTBLK:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enotblk"));
    case EBUSY:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "ebusy"));
    case EEXIST:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eexist"));
    case EXDEV:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "exdev"));
    case ENODEV:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enodev"));
    case ENOTDIR:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enotdir"));
    case EISDIR:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eisdir"));
    case EINVAL:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "einval"));
    case ENFILE:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enfile"));
    case EMFILE:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "emfile"));
    case ETXTBSY:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "etxtbsy"));
    case EFBIG:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "efbig"));
    case ENOSPC:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enospc"));
    case ESPIPE:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "espipe"));
    case EROFS:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "erofs"));
    case EMLINK:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "emlink"));
    case EPIPE:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "epipe"));
    case EAGAIN:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eagain"));
    case EINPROGRESS:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "einprogress"));
    case EALREADY:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "ealready"));
    case ENOTSOCK:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enotsock"));
    case EDESTADDRREQ:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "edestaddrreq"));
    case EMSGSIZE:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "emsgsize"));
    case EPROTOTYPE:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eprototype"));
    case ENOPROTOOPT:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eprotoopt"));
    case EPROTONOSUPPORT:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eprotonosupport"));
    case ESOCKTNOSUPPORT:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "esocktnosupport"));
    case ENOTSUP:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enotsup"));
    case EPFNOSUPPORT:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "epfnosupport"));
    case EAFNOSUPPORT:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eafnosupport"));
    case EADDRINUSE:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eaddrinuse"));
    case EADDRNOTAVAIL:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eaddrnotavail"));
    case ENETDOWN:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enetdown"));
    case ENETUNREACH:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enetunreach"));
    case ENETRESET:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enetreset"));
    case ECONNABORTED:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "econnaborted"));
    case ECONNRESET:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "econnreset"));
    case ENOBUFS:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enobufs"));
    case EISCONN:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eisconn"));
    case ENOTCONN:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enotconn"));
    case ESHUTDOWN:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eshutdown"));
    case ETOOMANYREFS:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "etoomanyrefs"));
    case ETIMEDOUT:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "etimedout"));
    case EHOSTUNREACH:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "ehostunreach"));
    case ECONNREFUSED:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "econnrefused"));
    case ELOOP:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eloop"));
    case ENAMETOOLONG:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enametoolong"));
    case EFSM:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "efsm"));
    case ENOCOMPATPROTO:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "enocompatproto"));
    case ETERM:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "eterm"));
    case EMTHREAD:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "emthread"));
    default:
      return enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, erl_errno_id(value)));
  }
}

static void context_destructor(ErlNifEnv * env, erlzmq_context_t * context) {
  // Handle cleanup even if term() wasn't called (best-effort cleanup)
  if (context->status != ERLZMQ_CONTEXT_STATUS_TERMINATED) {
    // Context wasn't properly terminated - try to clean up
    // Note: zmq_ctx_term may block if sockets are still open
    if (context->context_zmq) {
      zmq_ctx_term(context->context_zmq);
      context->context_zmq = NULL;
    }
    context->status = ERLZMQ_CONTEXT_STATUS_TERMINATED;
  }

  if (context->mutex) {
    enif_mutex_destroy(context->mutex);
    context->mutex = NULL;
  }
}

static void socket_destructor(ErlNifEnv * env, erlzmq_socket_t * socket) {
  // Handle cleanup even if close() wasn't called (best-effort cleanup)
  if (socket->status != ERLZMQ_SOCKET_STATUS_CLOSED) {
    // Socket wasn't properly closed - need to signal thread and clean up
    if (socket->socket_command_mutex) {
      enif_mutex_lock(socket->socket_command_mutex);

      // Close the zmq socket to unblock any blocking operations
      if (socket->socket_zmq) {
        zmq_close(socket->socket_zmq);
        socket->socket_zmq = NULL;
      }

      // Signal thread to exit
      socket->shutdown = 1;
      socket->status = ERLZMQ_SOCKET_STATUS_CLOSED;

      if (socket->socket_command_cond) {
        enif_cond_signal(socket->socket_command_cond);
      }

      enif_mutex_unlock(socket->socket_command_mutex);
    }
  }

  // Join the thread if it exists
  if (socket->socket_thread) {
    int value_errno = enif_thread_join(socket->socket_thread, NULL);
    (void)value_errno;  // Ignore errors - best effort cleanup
    socket->socket_thread = 0;
  }

  // Release context reference
  if (socket->context) {
    enif_release_resource(socket->context);
    socket->context = NULL;
  }

  free_socket_request(&socket->request);
  free_socket_reply(&socket->reply);

  if (socket->mutex) {
    enif_mutex_destroy(socket->mutex);
    socket->mutex = NULL;
  }

  if (socket->socket_command_mutex) {
    enif_mutex_destroy(socket->socket_command_mutex);
    socket->socket_command_mutex = NULL;
  }

  if (socket->socket_command_cond) {
    enif_cond_destroy(socket->socket_command_cond);
    socket->socket_command_cond = NULL;
  }

  if (socket->socket_command_result_cond) {
    enif_cond_destroy(socket->socket_command_result_cond);
    socket->socket_command_result_cond = NULL;
  }
}

static int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
  erlzmq_nif_resource_context =
    enif_open_resource_type(env, NULL,
                            "erlzmq_nif_resource_context",
                            (ErlNifResourceDtor*)context_destructor,
                            ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
                            0);
  erlzmq_nif_resource_socket =
    enif_open_resource_type(env, NULL,
                            "erlzmq_nif_resource_socket",
                            (ErlNifResourceDtor*)socket_destructor,
                            ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
                            0);

  if (!erlzmq_nif_resource_context || !erlzmq_nif_resource_socket) {
    return -1;
  }
  else {
    return 0;
  }
}

static void on_unload(ErlNifEnv* env, void* priv_data) {
}

ERL_NIF_INIT(erlzmq_nif, nif_funcs, &on_load, NULL, NULL, &on_unload)

static void clear_socket_request(erlzmq_socket_request_t *request) {
  memset(request, 0, sizeof(*request));
  request->command_id = -1;
}

static void clear_socket_reply(erlzmq_socket_reply_t *reply) {
  memset(reply, 0, sizeof(*reply));
  reply->ok = 0;
  reply->err = 0;
  reply->kind = ERLZMQ_SOCKET_REPLY_NONE;
}

static void free_socket_request(erlzmq_socket_request_t *request) {
  if (!request) {
    return;
  }
  switch (request->command_id) {
    case 0: // bind
    case 1: // unbind
    case 2: // connect
    case 3: // disconnect
      if (request->in.endpoint.endpoint) {
        enif_free(request->in.endpoint.endpoint);
        request->in.endpoint.endpoint = 0;
      }
      break;
    case 4: // send
      if (request->in.send.data) {
        enif_free(request->in.send.data);
        request->in.send.data = 0;
      }
      break;
    case 6: // setsockopt
      if (request->in.setsockopt.kind == 3 && request->in.setsockopt.value.bytes.data) {
        enif_free(request->in.setsockopt.value.bytes.data);
        request->in.setsockopt.value.bytes.data = 0;
      }
      break;
    case 10: // send_multipart
      if (request->in.send_multipart.parts) {
        for (size_t i = 0; i < request->in.send_multipart.part_count; i++) {
          if (request->in.send_multipart.parts[i]) {
            enif_free(request->in.send_multipart.parts[i]);
            request->in.send_multipart.parts[i] = 0;
          }
        }
        enif_free(request->in.send_multipart.parts);
        request->in.send_multipart.parts = 0;
      }
      if (request->in.send_multipart.sizes) {
        enif_free(request->in.send_multipart.sizes);
        request->in.send_multipart.sizes = 0;
      }
      break;
    default:
      break;
  }
  clear_socket_request(request);
}

static void free_socket_reply(erlzmq_socket_reply_t *reply) {
  if (!reply) {
    return;
  }
  switch (reply->kind) {
    case ERLZMQ_SOCKET_REPLY_BYTES:
      if (reply->out.bytes.data) {
        enif_free(reply->out.bytes.data);
        reply->out.bytes.data = 0;
      }
      break;
    case ERLZMQ_SOCKET_REPLY_MULTIPART:
      if (reply->out.multipart.parts) {
        for (size_t i = 0; i < reply->out.multipart.part_count; i++) {
          if (reply->out.multipart.parts[i]) {
            enif_free(reply->out.multipart.parts[i]);
            reply->out.multipart.parts[i] = 0;
          }
        }
        enif_free(reply->out.multipart.parts);
        reply->out.multipart.parts = 0;
      }
      if (reply->out.multipart.sizes) {
        enif_free(reply->out.multipart.sizes);
        reply->out.multipart.sizes = 0;
      }
      break;
    default:
      break;
  }
  clear_socket_reply(reply);
}

static void socket_exec_request(erlzmq_socket_t *socket, const erlzmq_socket_request_t *request, erlzmq_socket_reply_t *reply) {
  clear_socket_reply(reply);
  reply->ok = 0;
  reply->err = EINVAL;

  assert(socket);
  assert(request);

  if (!socket->socket_zmq && request->command_id != 8) {
    reply->err = ENOTSOCK;
    return;
  }

  switch (request->command_id) {
    case 0: // bind
      if (zmq_bind(socket->socket_zmq, request->in.endpoint.endpoint) != 0) {
        reply->err = zmq_errno();
        return;
      }
      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_NONE;
      return;
    case 1: // unbind
      if (zmq_unbind(socket->socket_zmq, request->in.endpoint.endpoint) != 0) {
        reply->err = zmq_errno();
        return;
      }
      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_NONE;
      return;
    case 2: // connect
      if (zmq_connect(socket->socket_zmq, request->in.endpoint.endpoint) != 0) {
        reply->err = zmq_errno();
        return;
      }
      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_NONE;
      return;
    case 3: // disconnect
      if (zmq_disconnect(socket->socket_zmq, request->in.endpoint.endpoint) != 0) {
        reply->err = zmq_errno();
        return;
      }
      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_NONE;
      return;
    case 4: // send
    {
      zmq_msg_t msg;
      if (zmq_msg_init_size(&msg, request->in.send.size) != 0) {
        reply->err = zmq_errno();
        return;
      }
      if (request->in.send.size != 0) {
        memcpy(zmq_msg_data(&msg), request->in.send.data, request->in.send.size);
      }
      int rc;
      do {
        rc = zmq_msg_send(&msg, socket->socket_zmq, request->in.send.flags);
      } while (rc == -1 && zmq_errno() == EINTR);

      int send_err = (rc == -1) ? zmq_errno() : 0;
      const int close_rc = zmq_msg_close(&msg);
      (void)close_rc;

      if (rc == -1) {
        reply->err = send_err;
        return;
      }
      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_NONE;
      return;
    }
    case 5: // recv
    {
      zmq_msg_t msg;
      if (zmq_msg_init(&msg) != 0) {
        reply->err = zmq_errno();
        return;
      }
      int rc;
      do {
        rc = zmq_msg_recv(&msg, socket->socket_zmq, request->in.recv.flags);
      } while (rc == -1 && zmq_errno() == EINTR);
      if (rc == -1) {
        reply->err = zmq_errno();
        const int close_rc = zmq_msg_close(&msg);
        (void)close_rc;
        return;
      }
      size_t msg_size = zmq_msg_size(&msg);
      reply->out.bytes.data = (uint8_t *) enif_alloc(msg_size);
      if (!reply->out.bytes.data && msg_size != 0) {
        reply->err = ENOMEM;
        const int close_rc = zmq_msg_close(&msg);
        (void)close_rc;
        return;
      }
      if (msg_size != 0) {
        memcpy(reply->out.bytes.data, zmq_msg_data(&msg), msg_size);
      }
      reply->out.bytes.size = msg_size;
      const int close_rc = zmq_msg_close(&msg);
      (void)close_rc;
      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_BYTES;
      return;
    }
    case 6: // setsockopt
    {
      void *option_value = 0;
      size_t option_len = request->in.setsockopt.option_len;
      int i32;
      int64_t i64;
      uint64_t u64;

      switch (request->in.setsockopt.kind) {
        case 0:
          i32 = request->in.setsockopt.value.i32;
          option_value = &i32;
          break;
        case 1:
          i64 = request->in.setsockopt.value.i64;
          option_value = &i64;
          break;
        case 2:
          u64 = request->in.setsockopt.value.u64;
          option_value = &u64;
          break;
        case 3:
          option_value = request->in.setsockopt.value.bytes.data;
          break;
        default:
          reply->err = EINVAL;
          return;
      }

      if (zmq_setsockopt(socket->socket_zmq, request->in.setsockopt.option_name, option_value, option_len) != 0) {
        reply->err = zmq_errno();
        return;
      }
      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_NONE;
      return;
    }
    case 7: // getsockopt
    {
      int option_name = request->in.getsockopt.option_name;
      int64_t value_int64;
      uint64_t value_uint64;
      int value_int;
      // Buffer for string/binary options. 1024 bytes handles long IPC paths
      // and other string options (ZMQ_LAST_ENDPOINT, ZMQ_ZAP_DOMAIN, etc.)
      char option_value[1024];
      size_t option_len;

      switch (option_name) {
        case ZMQ_MAXMSGSIZE:
          option_len = sizeof(value_int64);
          if (zmq_getsockopt(socket->socket_zmq, option_name, &value_int64, &option_len) != 0) {
            reply->err = zmq_errno();
            return;
          }
          reply->ok = 1;
          reply->kind = ERLZMQ_SOCKET_REPLY_INT64;
          reply->out.i64 = value_int64;
          return;
        case ZMQ_AFFINITY:
        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
        case ZMQ_VMCI_BUFFER_SIZE:
        case ZMQ_VMCI_BUFFER_MIN_SIZE:
        case ZMQ_VMCI_BUFFER_MAX_SIZE:
        #endif
          option_len = sizeof(value_uint64);
          if (zmq_getsockopt(socket->socket_zmq, option_name, &value_uint64, &option_len) != 0) {
            reply->err = zmq_errno();
            return;
          }
          reply->ok = 1;
          reply->kind = ERLZMQ_SOCKET_REPLY_UINT64;
          reply->out.u64 = value_uint64;
          return;
        case ZMQ_ROUTING_ID:
        case ZMQ_GSSAPI_PRINCIPAL:
        case ZMQ_GSSAPI_SERVICE_PRINCIPAL:
        case ZMQ_LAST_ENDPOINT:
        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 3
        case ZMQ_BINDTODEVICE:
        #endif
        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
        case ZMQ_SOCKS_PROXY:
        #endif
        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 0
        case ZMQ_ZAP_DOMAIN:
        case ZMQ_PLAIN_PASSWORD:
        case ZMQ_PLAIN_USERNAME:
        case ZMQ_CURVE_PUBLICKEY:
        case ZMQ_CURVE_SECRETKEY:
        case ZMQ_CURVE_SERVERKEY:
        #endif
          option_len = sizeof(option_value);
          if (zmq_getsockopt(socket->socket_zmq, option_name, option_value, &option_len) != 0) {
            reply->err = zmq_errno();
            return;
          }
          reply->out.bytes.data = (uint8_t *) enif_alloc(option_len);
          if (!reply->out.bytes.data && option_len != 0) {
            reply->err = ENOMEM;
            return;
          }
          if (option_len != 0) {
            memcpy(reply->out.bytes.data, option_value, option_len);
          }
          reply->out.bytes.size = option_len;
          reply->ok = 1;
          reply->kind = ERLZMQ_SOCKET_REPLY_BYTES;
          return;
        case ZMQ_BACKLOG:
        case ZMQ_LINGER:
        case ZMQ_MULTICAST_HOPS:
        case ZMQ_RATE:
        case ZMQ_RCVBUF:
        case ZMQ_RCVHWM:
        case ZMQ_RCVTIMEO:
        case ZMQ_RECONNECT_IVL:
        case ZMQ_RECONNECT_IVL_MAX:
        case ZMQ_RECOVERY_IVL:
        case ZMQ_SNDBUF:
        case ZMQ_SNDHWM:
        case ZMQ_SNDTIMEO:
        case ZMQ_TCP_KEEPALIVE:
        case ZMQ_TCP_KEEPALIVE_CNT:
        case ZMQ_TCP_KEEPALIVE_IDLE:
        case ZMQ_TCP_KEEPALIVE_INTVL:
        case ZMQ_RCVMORE:
        case ZMQ_EVENTS:
        case ZMQ_TYPE:
        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 3
        case ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE:
        case ZMQ_GSSAPI_PRINCIPAL_NAMETYPE:
        #endif
        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 2
        case ZMQ_USE_FD:
        case ZMQ_VMCI_CONNECT_TIMEOUT:
        case ZMQ_MULTICAST_MAXTPDU:
        case ZMQ_THREAD_SAFE:
        case ZMQ_TCP_MAXRT:
        case ZMQ_CONNECT_TIMEOUT:
        case ZMQ_INVERT_MATCHING:
        case ZMQ_HANDSHAKE_IVL:
        #endif
        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 1
        case ZMQ_TOS:
        #endif
        #if ZMQ_VERSION_MAJOR > 4 || ZMQ_VERSION_MAJOR == 4 && ZMQ_VERSION_MINOR >= 0
        case ZMQ_IMMEDIATE:
        case ZMQ_IPV6:
        case ZMQ_CURVE_SERVER:
        case ZMQ_GSSAPI_PLAINTEXT:
        case ZMQ_GSSAPI_SERVER:
        case ZMQ_PLAIN_SERVER:
        case ZMQ_MECHANISM:
        #endif
        case ZMQ_IPV4ONLY:
          option_len = sizeof(value_int);
          if (zmq_getsockopt(socket->socket_zmq, option_name, &value_int, &option_len) != 0) {
            reply->err = zmq_errno();
            return;
          }
          reply->ok = 1;
          reply->kind = ERLZMQ_SOCKET_REPLY_INT;
          reply->out.i32 = value_int;
          return;
        case ZMQ_FD:
        #if defined(_WIN32)
          // On Windows, ZMQ_FD returns SOCKET type (UINT_PTR)
          {
            uint64_t value_socket;
            option_len = sizeof(value_socket);
            if (zmq_getsockopt(socket->socket_zmq, option_name, &value_socket, &option_len) != 0) {
              reply->err = zmq_errno();
              return;
            }
            reply->ok = 1;
            reply->kind = ERLZMQ_SOCKET_REPLY_UINT64;
            reply->out.u64 = value_socket;
            return;
          }
        #else
          // On POSIX, ZMQ_FD returns int (file descriptor)
          option_len = sizeof(value_int);
          if (zmq_getsockopt(socket->socket_zmq, option_name, &value_int, &option_len) != 0) {
            reply->err = zmq_errno();
            return;
          }
          reply->ok = 1;
          reply->kind = ERLZMQ_SOCKET_REPLY_INT;
          reply->out.i32 = value_int;
          return;
        #endif
        default:
          reply->err = EINVAL;
          return;
      }
    }
    case 8: // close
      if (socket->socket_zmq && zmq_close(socket->socket_zmq) != 0) {
        reply->err = zmq_errno();
        return;
      }
      socket->socket_zmq = 0;
      socket->status = ERLZMQ_SOCKET_STATUS_CLOSED;
      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_NONE;
      return;
    case 9: // poll
    {
      zmq_pollitem_t items[1];
      items[0].socket = socket->socket_zmq;
      items[0].events = request->in.poll.events;
      const int rc = zmq_poll(items, 1, request->in.poll.timeout);
      if (rc == -1) {
        reply->err = zmq_errno();
        return;
      }
      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_INT;
      reply->out.i32 = (int) items[0].revents;
      return;
    }
    case 10: // send_multipart
    {
      size_t n = request->in.send_multipart.part_count;
      for (size_t i = 0; i < n; i++) {
        zmq_msg_t msg;
        if (zmq_msg_init_size(&msg, request->in.send_multipart.sizes[i]) != 0) {
          reply->err = zmq_errno();
          return;
        }
        if (request->in.send_multipart.sizes[i] != 0) {
          memcpy(zmq_msg_data(&msg), request->in.send_multipart.parts[i], request->in.send_multipart.sizes[i]);
        }
        int flags = request->in.send_multipart.flags;
        if (i + 1 < n) {
          flags |= ZMQ_SNDMORE;
        }
        int rc;
        do {
          rc = zmq_msg_send(&msg, socket->socket_zmq, flags);
        } while (rc == -1 && zmq_errno() == EINTR);
        int send_err = (rc == -1) ? zmq_errno() : 0;
        const int close_rc = zmq_msg_close(&msg);
        (void)close_rc;
        if (rc == -1) {
          reply->err = send_err;
          return;
        }
      }
      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_NONE;
      return;
    }
    case 11: // recv_multipart
    {
      size_t cap = 4;
      size_t n = 0;
      uint8_t **parts = (uint8_t **) enif_alloc(sizeof(uint8_t *) * cap);
      size_t *sizes = (size_t *) enif_alloc(sizeof(size_t) * cap);
      if (!parts || !sizes) {
        if (parts) enif_free(parts);
        if (sizes) enif_free(sizes);
        reply->err = ENOMEM;
        return;
      }
      memset(parts, 0, sizeof(uint8_t *) * cap);
      memset(sizes, 0, sizeof(size_t) * cap);

      for (;;) {
        zmq_msg_t msg;
        if (zmq_msg_init(&msg) != 0) {
          reply->err = zmq_errno();
          goto multipart_fail;
        }
        int rc;
        do {
          rc = zmq_msg_recv(&msg, socket->socket_zmq, request->in.recv_multipart.flags);
        } while (rc == -1 && zmq_errno() == EINTR);
        if (rc == -1) {
          reply->err = zmq_errno();
          const int close_rc = zmq_msg_close(&msg);
          (void)close_rc;
          goto multipart_fail;
        }

        size_t msg_size = zmq_msg_size(&msg);
        uint8_t *buf = (uint8_t *) enif_alloc(msg_size);
        if (!buf && msg_size != 0) {
          reply->err = ENOMEM;
          const int close_rc = zmq_msg_close(&msg);
          (void)close_rc;
          goto multipart_fail;
        }
        if (msg_size != 0) {
          memcpy(buf, zmq_msg_data(&msg), msg_size);
        }
        const int close_rc = zmq_msg_close(&msg);
        (void)close_rc;

        if (n == cap) {
          size_t new_cap = cap * 2;
          uint8_t **new_parts = (uint8_t **) enif_realloc(parts, sizeof(uint8_t *) * new_cap);
          size_t *new_sizes = (size_t *) enif_realloc(sizes, sizeof(size_t) * new_cap);
          if (!new_parts || !new_sizes) {
            if (new_parts) parts = new_parts;
            if (new_sizes) sizes = new_sizes;
            enif_free(buf);
            reply->err = ENOMEM;
            goto multipart_fail;
          }
          parts = new_parts;
          sizes = new_sizes;
          memset(parts + cap, 0, sizeof(uint8_t *) * (new_cap - cap));
          memset(sizes + cap, 0, sizeof(size_t) * (new_cap - cap));
          cap = new_cap;
        }
        parts[n] = buf;
        sizes[n] = msg_size;
        n++;

        int rcvmore = 0;
        size_t len = sizeof(int);
        if (zmq_getsockopt(socket->socket_zmq, ZMQ_RCVMORE, &rcvmore, &len) != 0) {
          reply->err = zmq_errno();
          goto multipart_fail;
        }
        if (!rcvmore) {
          break;
        }
      }

      reply->ok = 1;
      reply->kind = ERLZMQ_SOCKET_REPLY_MULTIPART;
      reply->out.multipart.parts = parts;
      reply->out.multipart.sizes = sizes;
      reply->out.multipart.part_count = n;
      return;

multipart_fail:
      for (size_t i = 0; i < n; i++) {
        if (parts[i]) enif_free(parts[i]);
      }
      enif_free(parts);
      enif_free(sizes);
      return;
    }
    default:
      reply->err = EINVAL;
      return;
  }
}

static void* socket_thread(erlzmq_socket_t *socket) {
  enif_mutex_lock(socket->socket_command_mutex);

  socket->socket_zmq = zmq_socket(socket->context->context_zmq, socket->socket_type);
  socket->init_errno = socket->socket_zmq ? 0 : zmq_errno();
  socket->init_done = 1;
  enif_cond_signal(socket->socket_command_result_cond);

  if (!socket->socket_zmq) {
    enif_mutex_unlock(socket->socket_command_mutex);
    return NULL;
  }

  for (;;) {
    while (!socket->command_pending && !socket->shutdown) {
      enif_cond_wait(socket->socket_command_cond, socket->socket_command_mutex);
    }

    // Check for shutdown signal from destructor
    if (socket->shutdown) {
      enif_mutex_unlock(socket->socket_command_mutex);
      break;
    }

    erlzmq_socket_request_t request = socket->request;
    socket->command_pending = 0;
    erlzmq_socket_reply_t reply;
    socket_exec_request(socket, &request, &reply);
    socket->reply = reply;
    socket->result_ready = 1;
    enif_cond_signal(socket->socket_command_result_cond);

    if (request.command_id == 8 && reply.ok) {
      enif_mutex_unlock(socket->socket_command_mutex);
      break;
    }
  }

  return NULL;
}
