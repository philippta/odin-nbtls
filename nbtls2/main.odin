package main

import s2n "../s2n"
import "base:runtime"
import "core:c"
import "core:fmt"
import "core:nbio"

Op :: nbio.Operation

main :: proc() {
	nbio.acquire_thread_event_loop()
	socket := nbio.listen_tcp({nbio.IP4_Any, 8443}) or_else panic("listen_tcp")

	init()

	nbio.accept(socket, accept_cb)
	nbio.run()
}

accept_cb :: proc(op: ^Op) {
	tls_accept(op.accept.client, tls_accept_cb)
}

tls_accept_cb :: proc(op: ^Op) {
	fmt.println("accepted")
}

// IMPL

base: ^s2n.Config
config: ^s2n.Config
conns: [4096]^s2n.Connection
certc :: #load("foo.local.pem", cstring)
keyc :: #load("foo.local-key.pem", cstring)

init :: proc() {
	s2n.s2n_init()

	ctx := new_clone(context)

	base = s2n.s2n_config_new()
	assert(s2n.s2n_config_set_client_hello_cb(base, client_hello_cb, ctx) == 0)
	assert(s2n.s2n_config_set_client_hello_cb_mode(base, .Nonblocking) == 0)

	config = s2n.s2n_config_new()
	assert(s2n.s2n_config_set_cipher_preferences(config, "default") == 0)
	assert(s2n.s2n_config_add_cert_chain_and_key(config, certc, keyc) == 0)

	client_hello_cb :: proc "c" (conn: ^s2n.Connection, ctx: rawptr) -> c.int {
		context = (cast(^runtime.Context)ctx)^

		server_name := s2n.s2n_get_server_name(conn)
		assert(s2n.s2n_connection_server_name_extension_used(conn) == 0)

		nbio.next_tick_poly2(conn, config, set_cfg)

		set_cfg :: proc(_: ^nbio.Operation, conn: ^s2n.Connection, config: ^s2n.Config) {
			assert(s2n.s2n_client_hello_cb_done(conn) == 0)

			fd: c.int
			assert(s2n.s2n_connection_get_write_fd(conn, &fd) == 0)
			assert(s2n.s2n_connection_set_config(conn, config) == 0)

			cb := s2n.s2n_connection_get_ctx(conn)

			op: nbio.Operation
			op.poll.socket = nbio.TCP_Socket(fd)
			_tls_accept_cb(&op, conn, nbio.Callback(cb))
		}

		return s2n.Success
	}
}

tls_accept :: proc(socket: nbio.TCP_Socket, cb: nbio.Callback) {
	conn := s2n.s2n_connection_new(.Server)
	assert(conn != nil)
	assert(s2n.s2n_connection_set_fd(conn, c.int(socket)) == 0)
	assert(s2n.s2n_connection_set_config(conn, base) == 0)
	assert(s2n.s2n_connection_set_ctx(conn, rawptr(cb)) == 0)
	conns[int(socket)] = conn

	nbio.poll_poly2(socket, .Receive, conn, cb, _tls_accept_cb)
}

_tls_accept_cb :: proc(op: ^Op, conn: ^s2n.Connection, cb: nbio.Callback) {
	blocked: s2n.Blocked_Status
	if s2n.s2n_negotiate(conn, &blocked) == s2n.Success {
		cb(op)
		return
	}

	switch blocked {
	case .Not_Blocked:
		panic("handle error")
	case .Blocked_On_Read:
		nbio.poll_poly2(op.poll.socket, .Receive, conn, cb, _tls_accept_cb)
	case .Blocked_On_Write:
		nbio.poll_poly2(op.poll.socket, .Send, conn, cb, _tls_accept_cb)
	case .Blocked_On_Application_Input:
		return // handled by client_hello_cb
	case .Blocked_On_Early_Data:
		panic("not implemented")
	}
}
