%% @hidden
-module(erlzmq_nif).

-export([context/2,
         socket/4,
         bind/2,
         connect/2,
         send/3,
         recv/2,
         setsockopt/3,
         getsockopt/2,
         close/1,
         term/1,
         ctx_get/2,
         ctx_set/3,
         curve_keypair/0,
         z85_decode/1,
         z85_encode/1,
         version/0]).

-on_load(init/0).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.


init() ->
    PrivDir = case code:priv_dir(?MODULE) of
                  {error, _} ->
                      EbinDir = filename:dirname(code:which(?MODULE)),
                      AppPath = filename:dirname(EbinDir),
                      filename:join(AppPath, "priv");
                  Path ->
                      Path
              end,
    erlang:load_nif(filename:join(PrivDir, "erlzmq_nif"), 0).


context(_Threads, _Opts) ->
    erlang:nif_error(not_loaded).

socket(_Context, _Type, _Active, _ActivePid) ->
    erlang:nif_error(not_loaded).

bind(_Socket, _Endpoint) ->
    erlang:nif_error(not_loaded).

connect(_Socket, _Endpoint) ->
    erlang:nif_error(not_loaded).

send(_Socket, _Binary, _Flags) ->
    erlang:nif_error(not_loaded).

recv(_Socket, _Flags) ->
    erlang:nif_error(not_loaded).

setsockopt(_Socket, _OptionName, _OptionValue) ->
    erlang:nif_error(not_loaded).

getsockopt(_Socket, _OptionName) ->
    erlang:nif_error(not_loaded).

close(_Socket) ->
    erlang:nif_error(not_loaded).

term(_Context) ->
    erlang:nif_error(not_loaded).

ctx_get(_Context, _OptionName) ->
    erlang:nif_error(not_loaded).

ctx_set(_Context, _OptionName, _OptionValue) ->
    erlang:nif_error(not_loaded).

curve_keypair() ->
    erlang:nif_error(not_loaded).

z85_decode(_Z85) ->
    erlang:nif_error(not_loaded).

z85_encode(_Binary) ->
    erlang:nif_error(not_loaded).

version() ->
    erlang:nif_error(not_loaded).
