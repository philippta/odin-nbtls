package nbtls

import "base:runtime"
import "core:c"
import "core:nbio"
import "core:os"
import "core:strings"
import "s2n"

Connection :: s2n.Connection
Config :: s2n.Config

Callback :: #type proc(op: ^Operation)
Client_Hello_Callback :: #type proc(
	conn: ^Connection,
	server_name: string,
	cb: Set_Certificate_Callback,
)
Set_Certificate_Callback :: #type proc(conn: ^Connection, config: ^Config)

Operation :: struct {
	cb:             Callback,
	conn:           ^Connection,
	type:           Operation_Type,
	using specifcs: Specifics,
}

Operation_Type :: enum {
	Accept,
	Handshake,
	Recv,
	Send,
	Close,
}

Specifics :: struct #raw_union {
	accept: Accept,
	recv:   Recv,
	send:   Send,
	close:  Close,
}

Accept :: struct {
	socket:      nbio.TCP_Socket,
	server_name: string,
}

Recv :: struct {
	socket:   nbio.TCP_Socket,
	buf:      []byte,
	received: int,
}

Send :: struct {
	socket: nbio.TCP_Socket,
	buf:    []byte,
	sent:   int,
}

Close :: struct {
	socket: nbio.TCP_Socket,
}

Error :: union {
	nbio.Accept_Error,
	nbio.Network_Error,
	nbio.Recv_Error,
	nbio.Send_Error,
}

_base_config: ^Config

init :: proc() {
	s2n.s2n_init()
	_base_config = config_init()

	saved_ctx := new_clone(context)
	assert(s2n.s2n_config_set_ctx(_base_config, saved_ctx) == s2n.Success)
	assert(
		s2n.s2n_config_set_client_hello_cb(_base_config, client_hello_cb, saved_ctx) ==
		s2n.Success,
	)
	assert(s2n.s2n_config_set_client_hello_cb_mode(_base_config, .Nonblocking) == s2n.Success)
}

destroy :: proc() {
	config_destroy(_base_config)
}

config_init :: proc() -> ^Config {
	return s2n.s2n_config_new()
}

config_init_with_cert_and_key_file :: proc(
	cert_file: string,
	key_file: string,
	allocator := context.allocator,
) -> ^Config {
	cert_pem, _ := os.read_entire_file(cert_file, allocator)
	key_pem, _ := os.read_entire_file(key_file, allocator)
	defer delete(cert_pem)
	defer delete(key_pem)
	return config_init_with_cert_and_key(string(cert_pem), string(key_pem), allocator)
}

config_init_with_cert_and_key :: proc(
	cert_pem: string,
	key_pem: string,
	allocator := context.allocator,
) -> ^Config {
	certc := strings.clone_to_cstring(string(cert_pem), allocator)
	keyc := strings.clone_to_cstring(string(key_pem), allocator)
	defer delete(certc)
	defer delete(keyc)

	config := config_init()
	assert(s2n.s2n_config_set_cipher_preferences(config, "default") == s2n.Success)
	assert(s2n.s2n_config_add_cert_chain_and_key(config, certc, keyc) == s2n.Success)

	return config
}

config_destroy :: proc(config: ^Config) {
	ctx: rawptr
	s2n.s2n_config_get_ctx(config, &ctx)
	if ctx != nil {
		free(ctx)
	}
	s2n.s2n_config_free(config)
}

accept :: proc(socket: nbio.TCP_Socket, cb: Callback) {
	tlsop := new_clone(Operation{cb = cb, type = .Accept, accept = {socket = socket}})
	nbio.accept_poly(socket, tlsop, accept_cb)

	accept_cb :: proc(op: ^nbio.Operation, tlsop: ^Operation) {
		assert(op.accept.err == nil)
		assert(tlsop.type == .Accept)

		tlsop.conn = s2n.s2n_connection_new(.Server)
		assert(tlsop.conn != nil)

		assert(s2n.s2n_connection_set_config(tlsop.conn, _base_config) == s2n.Success)
		assert(s2n.s2n_connection_set_fd(tlsop.conn, c.int(op.accept.client)) == s2n.Success)
		assert(s2n.s2n_connection_set_ctx(tlsop.conn, tlsop) == s2n.Success)

		nbio.poll_poly(op.accept.client, .Receive, tlsop, handshake_cb)
	}

	handshake_cb :: proc(op: ^nbio.Operation, tlsop: ^Operation) {
		assert(tlsop.type == .Accept)

		blocked: s2n.Blocked_Status
		s2n.s2n_negotiate(tlsop.conn, &blocked)

		switch blocked {
		case .Blocked_On_Read:
			nbio.poll_poly(op.poll.socket, .Receive, tlsop, handshake_cb)
		case .Blocked_On_Write:
			nbio.poll_poly(op.poll.socket, .Send, tlsop, handshake_cb)
		case .Blocked_On_Application_Input:
			return
		case .Blocked_On_Early_Data:
			panic("not implemented")
		case .Not_Blocked:
			panic("s2n_negotiate should always block")
		}
	}

}

client_hello_cb :: proc "c" (conn: ^Connection, ctx: rawptr) -> c.int {
	context = (cast(^runtime.Context)ctx)^

	server_name := string(s2n.s2n_get_server_name(conn))
	assert(s2n.s2n_connection_server_name_extension_used(conn) == s2n.Success)

	tlsop := cast(^Operation)s2n.s2n_connection_get_ctx(conn)
	assert(tlsop.type == .Accept)
	tlsop.accept.server_name = server_name

	nbio.next_tick_poly(tlsop, tick)

	tick :: proc(_: ^nbio.Operation, tlsop: ^Operation) {
		tlsop.cb(tlsop)
		free(tlsop)
		return
	}

	return s2n.Success
}

handshake :: proc(conn: ^Connection, config: ^Config, cb: Callback) {
	socket: nbio.TCP_Socket
	assert(s2n.s2n_connection_get_read_fd(conn, transmute(^c.int)&socket) == s2n.Success)
	assert(s2n.s2n_client_hello_cb_done(conn) == s2n.Success)
	assert(s2n.s2n_connection_set_config(conn, config) == s2n.Success)

	tlsop := new_clone(Operation{cb = cb, conn = conn, type = .Handshake})
	nbio.poll_poly(socket, .Send, tlsop, handshake_cb)

	handshake_cb :: proc(op: ^nbio.Operation, tlsop: ^Operation) {
		blocked: s2n.Blocked_Status
		ret := s2n.s2n_negotiate(tlsop.conn, &blocked)

		if ret == s2n.Success {
			tlsop.cb(tlsop)
			free(tlsop)
			return
		}

		switch blocked {
		case .Blocked_On_Read:
			nbio.poll_poly(op.poll.socket, .Receive, tlsop, handshake_cb)
		case .Blocked_On_Write:
			nbio.poll_poly(op.poll.socket, .Send, tlsop, handshake_cb)
		case .Blocked_On_Application_Input:
			panic("s2n_negotiate should not block on application input here")
		case .Blocked_On_Early_Data:
			panic("not implemented")
		case .Not_Blocked:
			panic("not implemented")
		}
	}
}

recv :: proc(conn: ^Connection, buf: []byte, cb: Callback) {
	socket: nbio.TCP_Socket
	assert(s2n.s2n_connection_get_read_fd(conn, transmute(^c.int)&socket) == s2n.Success)

	tlsop := new_clone(
		Operation{cb = cb, conn = conn, type = .Recv, recv = {socket = socket, buf = buf}},
	)
	nbio.poll_poly(socket, .Receive, tlsop, recv_cb)

	recv_cb :: proc(op: ^nbio.Operation, tlsop: ^Operation) {
		blocked: s2n.Blocked_Status
		n := s2n.s2n_recv(tlsop.conn, raw_data(tlsop.recv.buf), len(tlsop.recv.buf), &blocked)

		if n >= 0 {
			tlsop.recv.received = n
			tlsop.cb(tlsop)
			free(tlsop)
			return
		}

		if n == -1 && _s2n_error() != .Blocked {
			tlsop.recv.received = 0
			tlsop.cb(tlsop)
			free(tlsop)
			return
		}

		nbio.poll_poly(tlsop.recv.socket, _map_blocked_to_poll(blocked), tlsop, recv_cb)
	}
}

send :: proc(conn: ^Connection, buf: []byte, cb: Callback) {
	socket: nbio.TCP_Socket
	assert(s2n.s2n_connection_get_read_fd(conn, transmute(^c.int)&socket) == s2n.Success)

	tlsop := new_clone(
		Operation{cb = cb, conn = conn, type = .Send, send = {socket = socket, buf = buf}},
	)

	nbio.poll_poly(socket, .Send, tlsop, send_cb)

	send_cb :: proc(_: ^nbio.Operation, tlsop: ^Operation) {
		blocked: s2n.Blocked_Status
		n := s2n.s2n_send(tlsop.conn, raw_data(tlsop.recv.buf), len(tlsop.recv.buf), &blocked)

		if n >= 0 {
			tlsop.recv.received = n
			tlsop.cb(tlsop)
			free(tlsop)
			return
		}

		if n == -1 && _s2n_error() != .Blocked {
			tlsop.recv.received = 0
			tlsop.cb(tlsop)
			free(tlsop)
			return
		}

		nbio.poll_poly(tlsop.recv.socket, _map_blocked_to_poll(blocked), tlsop, send_cb)
	}
}

close :: proc(conn: ^Connection, cb: Callback) {
	socket: nbio.TCP_Socket
	assert(s2n.s2n_connection_get_read_fd(conn, transmute(^c.int)&socket) == s2n.Success)

	tlsop := new_clone(Operation{cb = cb, conn = conn, type = .Close, close = {socket = socket}})
	nbio.poll_poly(socket, .Send, tlsop, close_cb)

	close_cb :: proc(_: ^nbio.Operation, tlsop: ^Operation) {
		blocked: s2n.Blocked_Status
		ret := s2n.s2n_shutdown(tlsop.conn, &blocked)

		if ret == s2n.Success {
			nbio.close_poly(tlsop.close.socket, tlsop, socket_close_cb)
			return
		}

		if _s2n_error() != .Blocked {
			nbio.close_poly(tlsop.close.socket, tlsop, socket_close_cb)
			return
		}

		nbio.poll_poly(tlsop.close.socket, _map_blocked_to_poll(blocked), tlsop, close_cb)
	}

	socket_close_cb :: proc(_: ^nbio.Operation, tlsop: ^Operation) {
		tlsop.cb(tlsop)
		s2n.s2n_connection_free(tlsop.conn)
		free(tlsop)
	}
}

_map_blocked_to_poll :: proc(blocked: s2n.Blocked_Status) -> (ev: nbio.Poll_Event) {
	#partial switch blocked {
	case .Blocked_On_Read:
		ev = .Receive
	case .Blocked_On_Write:
		ev = .Send
	case:
		assert(false)
	}
	return
}

_get_socket :: proc(op: ^nbio.Operation) -> (socket: nbio.TCP_Socket) {
	#partial switch op.type {
	case .Accept:
		socket = op.accept.client
	case .Send:
		socket = op.send.socket.(nbio.TCP_Socket)
	case .Recv:
		socket = op.recv.socket.(nbio.TCP_Socket)
	case .Poll:
		socket = op.poll.socket.(nbio.TCP_Socket)
	case:
		assert(false)
	}
	return
}

_get_err :: proc(op: ^nbio.Operation) -> (err: Error) {
	#partial switch op.type {
	case .Accept:
		err = op.accept.err
	case .Send:
		err = op.send.err
	case .Recv:
		err = op.recv.err
	case .Poll:
		err = nil
	case:
		assert(false)
	}
	return
}

_s2n_error :: proc() -> s2n.Error_Type {
	errno := s2n.s2n_errno_location()
	return s2n.Error_Type(s2n.s2n_error_get_type(errno^))
}
