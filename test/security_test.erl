-module(security_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("erlzmq.hrl").
-export_type([erlzmq_socket/0, erlzmq_context/0]).

%% Test generators with extended timeouts for security tests
curve_test_() ->
    {"curve security test", {timeout, 30, fun curve_impl/0}}.

plain_test_() ->
    {"plain security test", {timeout, 30, fun plain_impl/0}}.

null_test_() ->
    {"null security test", {timeout, 30, fun null_impl/0}}.

curve_zap(S, AllowedKey) ->
    case erlzmq:recv(S) of
        {ok, <<"1.0">>} ->
            {ok, Sequence} = erlzmq:recv(S),
            {ok, _Domain} = erlzmq:recv(S),
            {ok, _Address} = erlzmq:recv(S),
            {ok, <<"">>} = erlzmq:recv(S),
            {ok, <<"CURVE">>} = erlzmq:recv(S),
            {ok, ClientKey} = erlzmq:recv(S),

            ok = erlzmq:send(S, <<"1.0">>, [sndmore]),
            ok = erlzmq:send(S, Sequence, [sndmore]),

            {ok, Enc} = erlzmq:z85_encode(ClientKey),

            case Enc of
                AllowedKey ->
                    ok = erlzmq:send(S, <<"200">>, [sndmore]),
                    ok = erlzmq:send(S, <<"OK">>, [sndmore]),
                    ok = erlzmq:send(S, <<"anonymous">>, [sndmore]),
                    ok = erlzmq:send(S, <<"">>);
                _ ->
                    ok = erlzmq:send(S, <<"400">>, [sndmore]),
                    ok = erlzmq:send(S, <<"Key not allowed">>, [sndmore]),
                    ok = erlzmq:send(S, <<"">>, [sndmore]),
                    ok = erlzmq:send(S, <<"">>)
            end,
            curve_zap(S, AllowedKey);
        {error, eterm} ->
            ok
    end.

% Modeled on zeromq's test_security_curve.cpp
curve_impl() ->
    {ok, CliPub, CliSec} = erlzmq:curve_keypair(),
    ?assert(is_binary(CliPub)),
    ?assert(is_binary(CliSec)),
    {ok, SerPub, SerSec} = erlzmq:curve_keypair(),

    % Set up server
    {ok, C} = erlzmq:context(),

    {ok, Zap} = erlzmq:socket(C, rep),
    ok = erlzmq:bind(Zap, "inproc://zeromq.zap.01"),

    spawn_link(fun () -> curve_zap(Zap, CliPub) end),

    {ok, Server} = erlzmq:socket(C, dealer),
    ok = erlzmq:setsockopt(Server, curve_server, 1),
    ok = erlzmq:setsockopt(Server, curve_secretkey, SerSec),
    ok = erlzmq:bind(Server, "tcp://127.0.0.1:9998"),

    % Client can talk
    {ok, Client1} = erlzmq:socket(C, dealer),
    ok = erlzmq:setsockopt(Client1, curve_serverkey, SerPub),
    ok = erlzmq:setsockopt(Client1, curve_publickey, CliPub),
    ok = erlzmq:setsockopt(Client1, curve_secretkey, CliSec),
    ok = erlzmq:connect(Client1, "tcp://localhost:9998"),
    bounce(Server, Client1),
    ok = erlzmq:close(Client1),

    % Client with bad server key can't talk
    BadSerKey = <<"1234567890123456789012345678901234567890">>,
    {ok, Client2} = erlzmq:socket(C, dealer),
    ok = erlzmq:setsockopt(Client2, curve_serverkey, BadSerKey),
    ok = erlzmq:setsockopt(Client2, curve_publickey, CliPub),
    ok = erlzmq:setsockopt(Client2, curve_secretkey, CliSec),
    ok = erlzmq:connect(Client2, "tcp://localhost:9998"),
    bounce_fail(Server, Client2),
    close_zero_linger(Client2),

    % Client with bad client secret key can't talk
    BadCliSecKey = <<"1234567890123456789012345678901234567890">>,
    {ok, Client3} = erlzmq:socket(C, dealer),
    ok = erlzmq:setsockopt(Client3, curve_serverkey, SerPub),
    ok = erlzmq:setsockopt(Client3, curve_publickey, CliPub),
    ok = erlzmq:setsockopt(Client3, curve_secretkey, BadCliSecKey),
    ok = erlzmq:connect(Client3, "tcp://localhost:9998"),
    bounce_fail(Server, Client3),
    close_zero_linger(Client3),

    % Client with not allowed key
    {ok, NotAllowedPub, NotAllowedSec} = erlzmq:curve_keypair(),
    {ok, Client4} = erlzmq:socket(C, dealer),
    ok = erlzmq:setsockopt(Client4, curve_serverkey, SerPub),
    ok = erlzmq:setsockopt(Client4, curve_publickey, NotAllowedPub),
    ok = erlzmq:setsockopt(Client4, curve_secretkey, NotAllowedSec),
    ok = erlzmq:connect(Client4, "tcp://localhost:9998"),
    bounce_fail(Server, Client4),
    close_zero_linger(Client4),

    % Non-curve client can't talk
    {ok, Client5} = erlzmq:socket(C, dealer),
    ok = erlzmq:connect(Client5, "tcp://localhost:9998"),
    bounce_fail(Server, Client5),
    close_zero_linger(Client5),

    ok = erlzmq:close(Server),
    close_zap_and_term(C, Zap).

bounce(S, C) ->
    timer:sleep(100), % apparently we need to wait a bit

    Content = <<"12345678ABCDEFGH12345678abcdefgh">>,
    ?assertEqual(ok, erlzmq:send(C, Content, [sndmore])),
    ?assertEqual(ok, erlzmq:send(C, Content)),

    ?assertMatch({ok, Content}, erlzmq:recv(S)),
    ?assertMatch({ok, 1}, erlzmq:getsockopt(S, rcvmore)),
    ?assertMatch({ok, Content}, erlzmq:recv(S)),
    ?assertMatch({ok, 0}, erlzmq:getsockopt(S, rcvmore)),

    ?assertEqual(ok, erlzmq:send(S, Content, [sndmore])),
    ?assertEqual(ok, erlzmq:send(S, Content)),

    ?assertMatch({ok, Content}, erlzmq:recv(C)),
    ?assertMatch({ok, 1}, erlzmq:getsockopt(C, rcvmore)),
    ?assertMatch({ok, Content}, erlzmq:recv(C)),
    ?assertMatch({ok, 0}, erlzmq:getsockopt(C, rcvmore)).

bounce_fail(S, C) ->
    timer:sleep(100), % apparently we need to wait a bit
    Content = <<"12345678ABCDEFGH12345678abcdefgh">>,

    % Set send timeout on client to avoid blocking indefinitely
    ok = erlzmq:setsockopt(C, sndtimeo, 500),
    case erlzmq:send(C, Content, [sndmore]) of
        ok ->
            _ = erlzmq:send(C, Content);
        {error, eagain} ->
            ok
    end,

    ok = erlzmq:setsockopt(S, rcvtimeo, 150),
    ?assertMatch({error, eagain}, erlzmq:recv(S)),

    ok = erlzmq:setsockopt(S, sndtimeo, 150),
    case erlzmq:send(S, Content, [sndmore]) of
        ok ->
            ?assertEqual(ok, erlzmq:send(S, Content));
        {error, eagain} ->
            ok
    end,

    ok = erlzmq:setsockopt(C, rcvtimeo, 150),
    ?assertMatch({error, eagain}, erlzmq:recv(C)).

close_zero_linger(Sock) ->
    ok = erlzmq:setsockopt(Sock, linger, 0),
    erlzmq:close(Sock).

plain_zap(S) ->
    case erlzmq:recv(S) of
        {ok, <<"1.0">>} ->
            {ok, Sequence} = erlzmq:recv(S),
            {ok, _Domain} = erlzmq:recv(S),
            {ok, _Address} = erlzmq:recv(S),
            {ok, <<"IDENT">>} = erlzmq:recv(S),
            {ok, <<"PLAIN">>} = erlzmq:recv(S),
            {ok, Username} = erlzmq:recv(S),
            {ok, Password} = erlzmq:recv(S),

            ok = erlzmq:send(S, <<"1.0">>, [sndmore]),
            ok = erlzmq:send(S, Sequence, [sndmore]),
            case {Username, Password} of
                {<<"admin">>, <<"password">>} ->
                    ok = erlzmq:send(S, <<"200">>, [sndmore]),
                    ok = erlzmq:send(S, <<"OK">>, [sndmore]),
                    ok = erlzmq:send(S, <<"anonymous">>, [sndmore]),
                    ok = erlzmq:send(S, <<"">>);
                {_, _} ->
                    ok = erlzmq:send(S, <<"400">>, [sndmore]),
                    ok = erlzmq:send(S, <<"Invalid username or password">>, [sndmore]),
                    ok = erlzmq:send(S, <<"">>, [sndmore]),
                    ok = erlzmq:send(S, <<"">>)
            end,
            plain_zap(S);
        {error, eterm} ->
            ok
    end.

plain_impl() ->
    % Set up server
    {ok, C} = erlzmq:context(),

    {ok, Zap} = erlzmq:socket(C, rep),
    ok = erlzmq:bind(Zap, "inproc://zeromq.zap.01"),

    spawn_link(fun () -> plain_zap(Zap) end),

    {ok, Server} = erlzmq:socket(C, dealer),
    ok = erlzmq:setsockopt(Server, routing_id, <<"IDENT">>),
    ok = erlzmq:setsockopt(Server, zap_domain, <<"test">>),
    ok = erlzmq:setsockopt(Server, plain_server, 1),
    ok = erlzmq:bind(Server, "tcp://127.0.0.1:9996"),

    % Client can talk
    {ok, Client1} = erlzmq:socket(C, dealer),
    ok = erlzmq:setsockopt(Client1, plain_username, <<"admin">>),
    ok = erlzmq:setsockopt(Client1, plain_password, <<"password">>),
    ok = erlzmq:connect(Client1, "tcp://localhost:9996"),
    bounce(Server, Client1),
    ok = erlzmq:close(Client1),

    % Client with bad password
    {ok, Client2} = erlzmq:socket(C, dealer),
    ok = erlzmq:setsockopt(Client2, plain_username, <<"admin">>),
    ok = erlzmq:setsockopt(Client2, plain_password, <<"bad">>),
    ok = erlzmq:connect(Client2, "tcp://localhost:9996"),
    bounce_fail(Server, Client2),
    close_zero_linger(Client2),
    
    % Non-plain client can't talk
    {ok, Client4} = erlzmq:socket(C, dealer),
    ok = erlzmq:connect(Client4, "tcp://localhost:9996"),
    bounce_fail(Server, Client4),
    close_zero_linger(Client4),
    
    ok = erlzmq:close(Server),
    close_zap_and_term(C, Zap).

null_zap(S) ->
    case erlzmq:recv(S) of
        {ok, <<"1.0">>} ->
            {ok, Sequence} = erlzmq:recv(S),
            {ok, Domain} = erlzmq:recv(S),
            {ok, _Address} = erlzmq:recv(S),
            {ok, <<"">>} = erlzmq:recv(S),
            {ok, <<"NULL">>} = erlzmq:recv(S),

            ok = erlzmq:send(S, <<"1.0">>, [sndmore]),
            ok = erlzmq:send(S, Sequence, [sndmore]),
            case Domain of
                <<"test">> ->
                    ok = erlzmq:send(S, <<"200">>, [sndmore]),
                    ok = erlzmq:send(S, <<"OK">>, [sndmore]),
                    ok = erlzmq:send(S, <<"anonymous">>, [sndmore]),
                    ok = erlzmq:send(S, <<"">>);
                _ ->
                    ok = erlzmq:send(S, <<"400">>, [sndmore]),
                    ok = erlzmq:send(S, <<"Bad domain">>, [sndmore]),
                    ok = erlzmq:send(S, <<"">>, [sndmore]),
                    ok = erlzmq:send(S, <<"">>)
            end,
            null_zap(S);
        {error, eterm} ->
            ok
    end.

null_impl() ->
    % Set up server
    {ok, C} = erlzmq:context(),

    {ok, Zap} = erlzmq:socket(C, rep),
    ok = erlzmq:bind(Zap, "inproc://zeromq.zap.01"),

    spawn_link(fun () -> null_zap(Zap) end),

    % Good domain
    {ok, Server1} = erlzmq:socket(C, dealer),
    ok = erlzmq:setsockopt(Server1, zap_domain, <<"test">>),
    ok = erlzmq:bind(Server1, "tcp://127.0.0.1:9993"),
    {ok, Client1} = erlzmq:socket(C, dealer),
    ok = erlzmq:connect(Client1, "tcp://localhost:9993"),
    bounce(Server1, Client1),
    ok = erlzmq:close(Client1),
    ok = erlzmq:close(Server1),

    % Bad domain
    {ok, Server2} = erlzmq:socket(C, dealer),
    ok = erlzmq:setsockopt(Server2, zap_domain, <<"bad">>),
    ok = erlzmq:bind(Server2, "tcp://127.0.0.1:9994"),
    {ok, Client2} = erlzmq:socket(C, dealer),
    ok = erlzmq:connect(Client2, "tcp://localhost:9994"),
    bounce_fail(Server2, Client2),
    ok = erlzmq:close(Client2),
    ok = erlzmq:close(Server2),

    % No domain
    {ok, Server3} = erlzmq:socket(C, dealer),
    ok = erlzmq:bind(Server3, "tcp://127.0.0.1:9995"),
    {ok, Client3} = erlzmq:socket(C, dealer),
    ok = erlzmq:connect(Client3, "tcp://localhost:9995"),
    bounce(Server3, Client3),
    ok = erlzmq:close(Client3),
    ok = erlzmq:close(Server3),
    close_zap_and_term(C, Zap).

close_zap_and_term(C, Zap) ->
    Self = self(),
    spawn_link(fun () ->
        ok = erlzmq:close(Zap),
        Self ! ok
    end),
    ok = erlzmq:term(C),
    receive
        ok -> ok
    end.
