-module(timeo_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("erlzmq.hrl").
-export_type([erlzmq_socket/0, erlzmq_context/0]).                          

timeo() ->
    {ok, Ctx} = erlzmq:context(),
    %%  Create a disconnected socket.
    {ok, Sb} = erlzmq:socket(Ctx, dealer),
    ok = erlzmq:bind(Sb, "inproc://timeout_test"),
    %%  Check whether non-blocking recv returns immediately.
    {error, eagain} = erlzmq:recv(Sb, [dontwait]),
    %%  Check whether recv timeout is honoured.
    Timeout0 = 500,
    ok = erlzmq:setsockopt(Sb, rcvtimeo, Timeout0),
    {Elapsed0, _} =
        timer:tc(fun() ->
                         ?assertMatch({error, eagain}, erlzmq:recv(Sb))
                 end),
    ?assert(Elapsed0 > 440000 andalso Elapsed0 < 550000),

    %%  Check whether connection during the wait doesn't distort the timeout.
    Timeout1 = 2000,
    ok = erlzmq:setsockopt(Sb, rcvtimeo, Timeout1),
    proc_lib:spawn(fun() ->
                           timer:sleep(1000),
                           {ok, Sc} = erlzmq:socket(Ctx, dealer),
                           ok = erlzmq:connect(Sc, "inproc://timeout_test"),
                           timer:sleep(1000),
                           % can't match here as close may return eterm on terminated context
                           erlzmq:close(Sc)
                   end),
    {Elapsed1, _} = timer:tc(fun() ->
                                     ?assertMatch({error, eagain}, erlzmq:recv(Sb))
                             end),
    ?assert(Elapsed1 > 1900000 andalso Elapsed1 < 2100000),

    %%  Check that timeouts don't break normal message transfer.
    {ok, Sc} = erlzmq:socket(Ctx, dealer),
    ok = erlzmq:setsockopt(Sb, rcvtimeo, Timeout1),
    ok = erlzmq:setsockopt(Sb, sndtimeo, Timeout1),
    ok = erlzmq:connect(Sc, "inproc://timeout_test"),

    Buff = <<"12345678ABCDEFGH12345678abcdefgh">>,
    ok = erlzmq:send(Sc, Buff),
    case erlzmq:recv(Sb) of
        {ok, Buff} ->
            ok;
        {error, eagain} ->
            timeout
    end,
    %%  Clean-up.
    ok = erlzmq:close(Sc),
    ok = erlzmq:close(Sb),
    ok = erlzmq:term (Ctx),
    ok.

timeo_multipart() ->
    {ok, Ctx} = erlzmq:context(),
    %%  Create a disconnected socket.
    {ok, Sb} = erlzmq:socket(Ctx, dealer),
    ok = erlzmq:bind(Sb, "inproc://timeout_test"),
    %%  Check whether non-blocking recv returns immediately.
    {error, eagain} = erlzmq:recv_multipart(Sb, [dontwait]),
    %%  Check whether recv timeout is honoured.
    Timeout0 = 500,
    ok = erlzmq:setsockopt(Sb, rcvtimeo, Timeout0),
    {Elapsed0, _} =
        timer:tc(fun() ->
                         ?assertMatch({error, eagain}, erlzmq:recv_multipart(Sb))
                 end),
    ?assert(Elapsed0 > 440000 andalso Elapsed0 < 550000),

    %%  Check whether connection during the wait doesn't distort the timeout.
    Timeout1 = 2000,
    ok = erlzmq:setsockopt(Sb, rcvtimeo, Timeout1),
    proc_lib:spawn(fun() ->
                           timer:sleep(1000),
                           {ok, Sc} = erlzmq:socket(Ctx, dealer),
                           ok = erlzmq:connect(Sc, "inproc://timeout_test"),
                           timer:sleep(1000),
                           % can't match here as close may return eterm on terminated context
                           erlzmq:close(Sc)
                   end),
    {Elapsed1, _} = timer:tc(fun() ->
                                     ?assertMatch({error, eagain}, erlzmq:recv_multipart(Sb))
                             end),
    ?assert(Elapsed1 > 1900000 andalso Elapsed1 < 2100000),

    %%  Check that timeouts don't break normal message transfer.
    {ok, Sc} = erlzmq:socket(Ctx, dealer),
    ok = erlzmq:setsockopt(Sb, rcvtimeo, Timeout1),
    ok = erlzmq:setsockopt(Sb, sndtimeo, Timeout1),
    ok = erlzmq:connect(Sc, "inproc://timeout_test"),

    Buff = <<"12345678ABCDEFGH12345678abcdefgh">>,
    ok = erlzmq:send_multipart(Sc, [Buff, Buff]),
    case erlzmq:recv_multipart(Sb) of
        {ok, [Buff, Buff]} ->
            ok;
        {error, eagain} ->
            timeout
    end,
    %%  Clean-up.
    ok = erlzmq:close(Sc),
    ok = erlzmq:close(Sb),
    ok = erlzmq:term (Ctx),
    ok.

timeo_test_() ->
    % sometimes this test can timeout with the default timeout
    {timeout, 10, [
        ?_assert(timeo() =:= ok)
    ]}.

timeo_multipart_test_() ->
    % sometimes this test can timeout with the default timeout
    {timeout, 10, [
        ?_assert(timeo_multipart() =:= ok)
    ]}.
