-module(simple_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("erlzmq.hrl").
-export_type([erlzmq_socket/0, erlzmq_context/0]).                          

bad_init_test() ->
    ?assertEqual({error, einval}, erlzmq:context(-1)).

context_init_term_test() ->
    {ok, C} = erlzmq:context(),
    ok = erlzmq:term(C).

socket_init_close_test() ->
    {ok, C} = erlzmq:context(),
    {ok, S1} = erlzmq:socket(C, req),
    ok = erlzmq:close(S1),
    ok = erlzmq:term(C).

context_term_before_test() ->
    {ok, C} = erlzmq:context(),
    {ok, S} = erlzmq:socket(C, pub),
    spawn_link(fun () ->
        timer:sleep(300),
        ok = erlzmq:close(S)
    end),
    ok = erlzmq:term(C).

bind_connect_passive_test() ->
    {ok, C} = erlzmq:context(),
    {ok, S1} = erlzmq:socket(C, req),
    {ok, S2} = erlzmq:socket(C, rep),
    ok = erlzmq:bind(S2, <<"tcp://127.0.0.1:5558">>),
    ok = erlzmq:connect(S1, <<"tcp://127.0.0.1:5558">>),
    ok = erlzmq:close(S1),
    ok = erlzmq:close(S2),
    ok = erlzmq:term(C).

send_recv_test() ->
    {ok, C} = erlzmq:context(),
    {ok, S1} = erlzmq:socket(C, req),
    {ok, S2} = erlzmq:socket(C, rep),
    ok = erlzmq:bind(S2, <<"tcp://127.0.0.1:5558">>),
    ok = erlzmq:connect(S1, <<"tcp://127.0.0.1:5558">>),
    ok = erlzmq:send(S1, <<"abc">>),
    {ok, <<"abc">>} = erlzmq:recv(S2),
    ok = erlzmq:close(S1),
    ok = erlzmq:close(S2),
    ok = erlzmq:term(C).

send_recv_multi_part_test() ->
    {ok, C} = erlzmq:context(),
    {ok, S1} = erlzmq:socket(C, req),
    {ok, S2} = erlzmq:socket(C, rep),
    ok = erlzmq:bind(S2, <<"tcp://127.0.0.1:5559">>),
    ok = erlzmq:connect(S1, <<"tcp://127.0.0.1:5559">>),
    ok = erlzmq:send_multipart(S1, [<<"abc">>, <<"def">>]),
    {ok, [<<"abc">>, <<"def">>]} = erlzmq:recv_multipart(S2),
    ok = erlzmq:close(S1),
    ok = erlzmq:close(S2),
    ok = erlzmq:term(C).

max_sockets_test() ->
    {ok, C} = erlzmq:context(1),
    ok = erlzmq:ctx_set(C, max_sockets, 30),
    Sockets = create_sockets(C, []),
    ?assertEqual(length(Sockets), 30),
    lists:foreach(fun (S) ->
        ok = erlzmq:close(S)
    end, Sockets),
    ok = erlzmq:term(C).

max_sockets_no_limit_test() ->
    {ok, C} = erlzmq:context(1),
    Sockets = create_sockets(C, []),
    ?assert(length(Sockets) > 0),
    lists:foreach(fun (S) ->
        ok = erlzmq:close(S)
    end, Sockets),
    ok = erlzmq:term(C).

create_sockets(Context, List) ->
    case erlzmq:socket(Context, req) of
        {ok, S} -> create_sockets(Context, [S | List]);
        {error, emfile} -> List
    end.

term_while_sending_test() ->
    {ok, C} = erlzmq:context(),
    {ok, S1} = erlzmq:socket(C, req),
    spawn_link(fun () ->
        {error, eterm} = erlzmq:send(S1, <<>>)
    end),
    timer:sleep(1000),
    spawn_link(fun () ->
        timer:sleep(500),
        ok = erlzmq:close(S1)
    end),
    ok = erlzmq:term(C).

term_while_receiving_test() ->
    {ok, C} = erlzmq:context(),
    {ok, S1} = erlzmq:socket(C, rep),
    spawn_link(fun () ->
        {error, eterm} = erlzmq:recv(S1)
    end),
    timer:sleep(1000),
    spawn_link(fun () ->
        timer:sleep(500),
        ok = erlzmq:close(S1)
    end),
    ok = erlzmq:term(C).
