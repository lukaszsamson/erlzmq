-define('ZMQ_PAIR',         0).
-define('ZMQ_PUB',          1).
-define('ZMQ_SUB',          2).
-define('ZMQ_REQ',          3).
-define('ZMQ_REP',          4).
-define('ZMQ_DEALER',       5).
-define('ZMQ_ROUTER',       6).
-define('ZMQ_PULL',         7).
-define('ZMQ_PUSH',         8).
-define('ZMQ_XPUB',         9).
-define('ZMQ_XSUB',        10).
-define('ZMQ_STREAM',      11).
% deprecated
-define('ZMQ_XREQ',         ?'ZMQ_DEALER').
-define('ZMQ_XREP',         ?'ZMQ_ROUTER').

% ZMQ socket options.
-define('ZMQ_AFFINITY', 4).
-define('ZMQ_ROUTING_ID', 5).
-define('ZMQ_SUBSCRIBE', 6).
-define('ZMQ_UNSUBSCRIBE', 7).
-define('ZMQ_RATE', 8).
-define('ZMQ_RECOVERY_IVL', 9).
-define('ZMQ_SNDBUF', 11).
-define('ZMQ_RCVBUF', 12).
-define('ZMQ_RCVMORE', 13).
-define('ZMQ_FD', 14).
-define('ZMQ_EVENTS', 15).
-define('ZMQ_TYPE', 16).
-define('ZMQ_LINGER', 17).
-define('ZMQ_RECONNECT_IVL', 18).
-define('ZMQ_BACKLOG', 19).
-define('ZMQ_RECONNECT_IVL_MAX', 21).
-define('ZMQ_MAXMSGSIZE', 22).
-define('ZMQ_SNDHWM', 23).
-define('ZMQ_RCVHWM', 24).
-define('ZMQ_MULTICAST_HOPS', 25).
-define('ZMQ_RCVTIMEO', 27).
-define('ZMQ_SNDTIMEO', 28).
-define('ZMQ_LAST_ENDPOINT', 32).
-define('ZMQ_ROUTER_MANDATORY', 33).
-define('ZMQ_TCP_KEEPALIVE', 34).
-define('ZMQ_TCP_KEEPALIVE_CNT', 35).
-define('ZMQ_TCP_KEEPALIVE_IDLE', 36).
-define('ZMQ_TCP_KEEPALIVE_INTVL', 37).
-define('ZMQ_IMMEDIATE', 39).
-define('ZMQ_XPUB_VERBOSE', 40).
-define('ZMQ_ROUTER_RAW', 41).
-define('ZMQ_IPV6', 42).
-define('ZMQ_MECHANISM', 43).
-define('ZMQ_PLAIN_SERVER', 44).
-define('ZMQ_PLAIN_USERNAME', 45).
-define('ZMQ_PLAIN_PASSWORD', 46).
-define('ZMQ_CURVE_SERVER', 47).
-define('ZMQ_CURVE_PUBLICKEY', 48).
-define('ZMQ_CURVE_SECRETKEY', 49).
-define('ZMQ_CURVE_SERVERKEY', 50).
-define('ZMQ_PROBE_ROUTER', 51).
-define('ZMQ_REQ_CORRELATE', 52).
-define('ZMQ_REQ_RELAXED', 53).
-define('ZMQ_CONFLATE', 54).
-define('ZMQ_ZAP_DOMAIN', 55).
-define('ZMQ_ROUTER_HANDOVER', 56).
-define('ZMQ_TOS', 57).
-define('ZMQ_CONNECT_ROUTING_ID', 61).
-define('ZMQ_GSSAPI_SERVER', 62).
-define('ZMQ_GSSAPI_PRINCIPAL', 63).
-define('ZMQ_GSSAPI_SERVICE_PRINCIPAL', 64).
-define('ZMQ_GSSAPI_PLAINTEXT', 65).
-define('ZMQ_HANDSHAKE_IVL', 66).
-define('ZMQ_SOCKS_PROXY', 68).
-define('ZMQ_XPUB_NODROP', 69).
% blocky is a context option but for some reason is defined along with socket options in zmq.h
-define('ZMQ_BLOCKY', 70).
-define('ZMQ_XPUB_MANUAL', 71).
-define('ZMQ_XPUB_WELCOME_MSG', 72).
-define('ZMQ_STREAM_NOTIFY', 73).
-define('ZMQ_INVERT_MATCHING', 74).
-define('ZMQ_HEARTBEAT_IVL', 75).
-define('ZMQ_HEARTBEAT_TTL', 76).
-define('ZMQ_HEARTBEAT_TIMEOUT', 77).
-define('ZMQ_XPUB_VERBOSER', 78).
-define('ZMQ_CONNECT_TIMEOUT', 79).
-define('ZMQ_TCP_MAXRT', 80).
-define('ZMQ_THREAD_SAFE', 81).
-define('ZMQ_MULTICAST_MAXTPDU', 84).
-define('ZMQ_VMCI_BUFFER_SIZE', 85).
-define('ZMQ_VMCI_BUFFER_MIN_SIZE', 86).
-define('ZMQ_VMCI_BUFFER_MAX_SIZE', 87).
-define('ZMQ_VMCI_CONNECT_TIMEOUT', 88).
-define('ZMQ_USE_FD', 89).
-define('ZMQ_GSSAPI_PRINCIPAL_NAMETYPE', 90).
-define('ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE', 91).
-define('ZMQ_BINDTODEVICE', 92).
% deprecated
-define('ZMQ_TCP_ACCEPT_FILTER', 38).
-define('ZMQ_IPV4ONLY', 31).
-define('ZMQ_IDENTITY', ?'ZMQ_ROUTING_ID').
-define('ZMQ_CONNECT_RID', ?'ZMQ_CONNECT_ROUTING_ID').
-define('ZMQ_DELAY_ATTACH_ON_CONNECT', ?'ZMQ_IMMEDIATE').
-define('ZMQ_NOBLOCK', ?'ZMQ_DONTWAIT').
-define('ZMQ_FAIL_UNROUTABLE', ?'ZMQ_ROUTER_MANDATORY').
-define('ZMQ_ROUTER_BEHAVIOR', ?'ZMQ_ROUTER_MANDATORY').

%  Message options
-define('ZMQ_MORE',  1).
-define('ZMQ_SHARED',  3).
% deprecated
-define('ZMQ_SRCFD',  2).

% ZMQ send/recv flags
-define('ZMQ_DONTWAIT',    1).
-define('ZMQ_SNDMORE',     2).

% ZMQ Context options
-define('ZMQ_IO_THREADS', 1).
-define('ZMQ_MAX_SOCKETS', 2).
-define('ZMQ_SOCKET_LIMIT', 3).
-define('ZMQ_THREAD_PRIORITY', 3).
-define('ZMQ_THREAD_SCHED_POLICY', 4).
-define('ZMQ_MAX_MSGSZ', 5).
-define('ZMQ_MSG_T_SIZE', 6).
-define('ZMQ_THREAD_AFFINITY_CPU_ADD', 7).
-define('ZMQ_THREAD_AFFINITY_CPU_REMOVE', 8).
-define('ZMQ_THREAD_NAME_PREFIX', 9).

% ZMQ Context options
-define('ERLZMQ_SOCKET_COMMAND_BIND', 0).
-define('ERLZMQ_SOCKET_COMMAND_UNBIND', 1).
-define('ERLZMQ_SOCKET_COMMAND_CONNECT', 2).
-define('ERLZMQ_SOCKET_COMMAND_DISCONNECT', 3).
-define('ERLZMQ_SOCKET_COMMAND_SEND', 4).
-define('ERLZMQ_SOCKET_COMMAND_RECV', 5).
-define('ERLZMQ_SOCKET_COMMAND_SETSOCKOPT', 6).
-define('ERLZMQ_SOCKET_COMMAND_GETSOCKOPT', 7).
-define('ERLZMQ_SOCKET_COMMAND_CLOSE', 8).
-define('ERLZMQ_SOCKET_COMMAND_POLL', 9).
-define('ERLZMQ_SOCKET_COMMAND_SEND_MULTIPART', 10).
-define('ERLZMQ_SOCKET_COMMAND_RECV_MULTIPART', 11).


% ZMQ poll event flags
-define('ZMQ_POLLIN', 1).
-define('ZMQ_POLLOUT', 2).
-define('ZMQ_POLLERR', 4).
-define('ZMQ_POLLPRI', 8).
%% Types

%% Possible types for an erlzmq socket.<br />
%% <i>For more information see
%% <a href="http://api.zeromq.org/master:zmq_socket">zmq_socket</a></i>
-type erlzmq_socket_type() :: pair | pub | sub | req | rep | dealer | router | xreq | xrep |
                            pull | push | xpub | xsub | stream.

%% The endpoint argument is a string consisting of two parts:
%% <b>transport://address</b><br />
%% The following transports are defined:
%% <b>inproc</b>, <b>ipc</b>, <b>tcp</b>, <b>pgm</b>, <b>epgm</b>.<br />
%% The meaning of address is transport specific.<br />
%% <i>For more information see
%% <a href="http://api.zeromq.org/master:zmq_bind">zmq_bind</a> or
%% <a href="http://api.zeromq.org/master:zmq_connect">zmq_connect</a></i>
-type erlzmq_endpoint() :: string() | binary().

%% Standard error atoms.
-type errno() :: eperm | enoent | srch | eintr | eio | enxio | ebad |
                 echild | edeadlk | enomem | eacces | efault | enotblk |
                 ebusy | eexist | exdev | enodev | enotdir | eisdir |
                 einval | enfile | emfile | enotty | etxtbsy | efbig |
                 enospc | espipe | erofs | emlink | epipe | eagain |
                 einprogress | ealready | enotsock | edestaddrreq |
                 emsgsize | eprototype | enoprotoopt | eprotonosupport |
                 esocktnosupport | enotsup | epfnosupport | eafnosupport |
                 eaddrinuse | eaddrnotavail | enetdown | enetunreach |
                 enetreset | econnaborted | econnreset | enobufs | eisconn |
                 enotconn | eshutdown | etoomanyrefs | ehostunreach |
                 etimedout | econnrefused | eloop | enametoolong | eaddnotavail.

%% Possible error types.
-type erlzmq_error_type() :: efsm | enocompatproto | eterm |
                           emthread | errno() | unknown.

%% Error tuples returned by most API functions.
-type erlzmq_error() :: {error, erlzmq_error_type()}.

%% Data to be sent with {@link erlzmq:send/3. send/3} or received with
%% {@link erlzmq:recv/2. recv/2}
-type erlzmq_data() :: iolist().

%% An opaque handle to an erlzmq context.
-opaque erlzmq_context() :: binary().

%% An opaque handle to an erlzmq socket.
-opaque erlzmq_socket() :: {pos_integer(), binary()}.

%% The individual flags to use with {@link erlzmq:send/3. send/3}
%% and {@link erlzmq:recv/2. recv/2}.<br />
%% <i>For more information see
%% <a href="http://api.zeromq.org/master:zmq_send">zmq_send</a> or
%% <a href="http://api.zeromq.org/master:zmq_recv">zmq_recv</a></i>
-type erlzmq_send_recv_flag() :: dontwait | sndmore | recvmore.

%% A list of flags to use with {@link ezqm:send/3. send/3} and
%% {@link erlzmq:recv/2. recv/2}
-type erlzmq_send_recv_flags() :: list(erlzmq_send_recv_flag()).

%% Available options for {@link erlzmq:setsockopt/3. setsockopt/3}
%% and {@link erlzmq:getsockopt/2. getsockopt/2}.<br />
%% <i>For more information see
%% <a href="http://api.zeromq.org/master:zmq_setsockopt">zmq_setsockopt</a>
%% and <a href="http://api.zeromq.org/master:zmq_getsockopt">zmq_getsockopt</a></i>
-type erlzmq_sockopt() :: 
    affinity |
    routing_id |
    subscribe |
    unsubscribe |
    rate |
    recovery_ivl |
    sndbuf |
    rcvbuf |
    rcvmore |
    fd |
    events |
    type |
    linger |
    reconnect_ivl |
    backlog |
    reconnect_ivl_max |
    maxmsgsize |
    sndhwm |
    rcvhwm |
    multicast_hops |
    rcvtimeo |
    sndtimeo |
    last_endpoint |
    router_mandatory |
    tcp_keepalive |
    tcp_keepalive_cnt |
    tcp_keepalive_idle |
    tcp_keepalive_intvl |
    immediate |
    xpub_verbose |
    router_raw |
    ipv6 |
    mechanism |
    plain_server |
    plain_username |
    plain_password |
    curve_server |
    curve_publickey |
    curve_secretkey |
    curve_serverkey |
    probe_router |
    req_correlate |
    req_relaxed |
    conflate |
    zap_domain |
    router_handover |
    tos |
    connect_routing_id |
    gssapi_server |
    gssapi_principal |
    gssapi_service_principal |
    gssapi_plaintext |
    handshake_ivl |
    socks_proxy |
    xpub_nodrop |
    xpub_manual |
    xpub_welcome_msg |
    stream_notify |
    invert_matching |
    heartbeat_ivl |
    heartbeat_ttl |
    heartbeat_timeout |
    xpub_verboser |
    connect_timeout |
    tcp_maxrt |
    thread_safe |
    multicast_maxtpdu |
    vmci_buffer_size |
    vmci_buffer_min_size |
    vmci_buffer_max_size |
    vmci_connect_timeout |
    use_fd |
    gssapi_principal_nametype |
    gssapi_service_principal_nametype |
    bindtodevice |
    % deprecated
    ipv4only |
    tcp_accept_filter |
    connect_rid |
    delay_attach_on_connect |
    noblock |
    fail_unroutable |
    router_behavior |
    identity.


%% Possible option values for {@link erlzmq:setsockopt/3. setsockopt/3}.
-type erlzmq_sockopt_value() :: integer() | iolist().

%% Available options for {@link erlzmq:ctx_set/3. ctx_set/3}
%% and {@link erlzmq:ctx_get/2. ctx_get/2}.<br />
%% <i>For more information see
%% <a href="http://api.zeromq.org/master:zmq_ctx_set">zmq_ctx_set</a>
%% and <a href="http://api.zeromq.org/master:zmq_ctx_get">zmq_ctx_get</a></i>

-type erlzmq_ctxopt() ::
    blocky |
    io_threads |
    thread_sched_policy |
    thread_priority |
    thread_affinity_cpu_add |
    thread_affinity_cpu_remove |
    thread_name_prefix |
    max_msgsz |
    msg_t_size |
    socket_limit |
    max_sockets |
    ipv6.

%% 0MQ library capabilities {@link erlzmq:has/1. has/1}.
-type erlzmq_capability() ::
    ipc |
    pgm |
    tipc |
    norm |
    curve |
    gssapi |
    draft.

%% 0MQ library poll event types {@link erlzmq:poll/2. poll/2}.
-type erlzmq_poll_event() ::
    pollin |
    pollout |
    pollerr |
    pollpri.
