![Build status](https://github.com/lukaszsamson/erlzmq/actions/workflows/ci.yml/badge.svg)

erlzmq_dnif
=======
Dirty NIF based Erlang bindings for the ZeroMQ messaging library.

Forked from erlang solutions erlzmq project.

Forked from the erlzmq2 project.

Copyright (c) 2020 Łukasz Samson

Copyright (c) 2019 erlang solutions ltd

Copyright (c) 2011 Yurii Rashkovskii, Evax Software and Michael Truog

Overview
--------

The erlzmq application provides high-performance NIF based Erlang
bindings for the ZeroMQ messaging library.

Installation
------------

Add reference to the packege from [Hex.pm](https://hex.pm/packages/erlzmq_dnif)

erlang: add to rebar.config

    {erlzmq, "~> 4.1.3", {pkg, erlzmq_dnif}}

elixir: add to mix.exs

    {:erlzmq, "~> 4.1", hex: :erlzmq_dnif}

Downloading
-----------

The erlzmq_dnif source code can be found on
[GitHub](https://github.com/lukaszsamson/erlzmq)

    $ git clone http://github.com/lukaszsamson/erlzmq.git

Building
--------

Please note that to behave properly on your system ZeroMQ might
require [some tuning](http://www.zeromq.org/docs:tuning-zeromq).

Install zeromq-dev package for your distro.

Build the code

    $ rebar3 compile

Build the docs

    $ rebar3 edoc

Run the test suite

    $ rebar3 eunit

Architecture
------------

The bindings use Erlang's Dirty
[NIF (native implemented functions)](http://www.erlang.org/doc/man/erl_nif.html)
interface to achieve the best performance.

License
-------

The project is released under the MIT license.
