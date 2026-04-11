package nbtls

import "core:c"
import "core:log"
import "core:nbio"
import "core:os"
import "core:strings"
import "s2n"

Connection :: s2n.Connection
Config :: s2n.Config

Callback :: #type proc(op: ^Operation)

Operation :: struct {
	cb:              Callback,
	config:          ^Config,
	conn:            ^Connection,
	type:            Operation_Type,
	using specifics: Specifics,
}

Operation_Type :: enum {
	Accept,
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
	socket: nbio.TCP_Socket,
	client: nbio.TCP_Socket,
	err:    Error,
}

Recv :: struct {
	socket:   nbio.TCP_Socket,
	buf:      []byte,
	received: int,
	err:      Error,
}

Send :: struct {
	socket: nbio.TCP_Socket,
	buf:    []byte,
	sent:   int,
	err:    Error,
}

Close :: struct {
	socket: nbio.TCP_Socket,
	err:    Error,
}

Error :: union {
	nbio.Accept_Error,
	nbio.Network_Error,
	nbio.Recv_Error,
	nbio.Send_Error,
}

config_init_with_cert_and_key_file :: proc(
	cert_file: string,
	key_file: string,
	cb: Callback,
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

	config := config_init()
	assert(config != nil)
	assert(s2n.s2n_config_set_cipher_preferences(config, "default") == s2n.Success)
	assert(s2n.s2n_config_add_cert_chain_and_key(config, certc, keyc) == s2n.Success)

	return config
}

config_init :: proc() -> ^Config {
	s2n.s2n_init()
	return s2n.s2n_config_new()
}

config_destroy :: proc(config: ^Config) {
	s2n.s2n_config_free(config)
}

accept :: proc(socket: nbio.TCP_Socket, config: ^Config, cb: Callback) {
	tlsop := new(Operation)
	tlsop.cb = cb
	tlsop.config = config
	tlsop.type = .Accept
	tlsop.accept.socket = socket
	nbio.accept_poly2(socket, tlsop, config, accept_cb)

	accept_cb :: proc(op: ^nbio.Operation, tlsop: ^Operation, config: ^Config) {
		log.debug("accept_cb")

		tlsop.accept.client = op.accept.client

		if op.accept.err != nil {
			tlsop.accept.err = op.accept.err
			tlsop.cb(tlsop)
			free(tlsop)
			return
		}

		tlsop.conn = s2n.s2n_connection_new(.Server)
		assert(tlsop.conn != nil)

		assert(s2n.s2n_connection_set_config(tlsop.conn, config) == s2n.Success)
		assert(s2n.s2n_connection_set_fd(tlsop.conn, c.int(op.accept.client)) == s2n.Success)

		handshake_cb(nil, tlsop)
	}

	handshake_cb :: proc(_: ^nbio.Operation, tlsop: ^Operation) {
		log.debug("handshake_cb")

		blocked: s2n.Blocked_Status
		if s2n.s2n_negotiate(tlsop.conn, &blocked) == s2n.Success {
			tlsop.cb(tlsop)
			free(tlsop)
			return
		}

		nbio.poll_poly(tlsop.accept.client, _map_blocked_to_poll(blocked), tlsop, handshake_cb)
	}
}

recv :: proc(conn: ^Connection, buf: []byte, cb: Callback) {
	socket: c.int
	assert(s2n.s2n_connection_get_read_fd(conn, &socket) == s2n.Success)

	tlsop := new(Operation)
	tlsop.cb = cb
	tlsop.conn = conn
	tlsop.type = .Recv
	tlsop.recv.socket = nbio.TCP_Socket(socket)
	tlsop.recv.buf = buf

	recv_cb(nil, tlsop)

	recv_cb :: proc(_: ^nbio.Operation, tlsop: ^Operation) {
		log.debug("recv_cb")

		blocked: s2n.Blocked_Status
		n := s2n.s2n_recv(tlsop.conn, raw_data(tlsop.recv.buf), len(tlsop.recv.buf), &blocked)
		if n >= 0 {
			tlsop.recv.received = n
			tlsop.cb(tlsop)
			free(tlsop)
			return
		}

		nbio.poll_poly(tlsop.recv.socket, _map_blocked_to_poll(blocked), tlsop, recv_cb)
	}
}

send :: proc(conn: ^Connection, buf: []byte, cb: Callback) {
	socket: c.int
	assert(s2n.s2n_connection_get_read_fd(conn, &socket) == s2n.Success)

	tlsop := new(Operation)
	tlsop.cb = cb
	tlsop.conn = conn
	tlsop.type = .Send
	tlsop.send.socket = nbio.TCP_Socket(socket)
	tlsop.send.buf = buf

	send_cb(nil, tlsop)

	send_cb :: proc(_: ^nbio.Operation, tlsop: ^Operation) {
		log.debug("send_cb")

		blocked: s2n.Blocked_Status
		n := s2n.s2n_send(tlsop.conn, raw_data(tlsop.send.buf), len(tlsop.send.buf), &blocked)
		if n >= 0 {
			tlsop.send.sent = n
			tlsop.cb(tlsop)
			free(tlsop)
			return
		}

		nbio.poll_poly(tlsop.send.socket, _map_blocked_to_poll(blocked), tlsop, send_cb)
	}
}

close :: proc(conn: ^Connection, cb: Callback) {
	socket: c.int
	assert(s2n.s2n_connection_get_read_fd(conn, &socket) == s2n.Success)

	tlsop := new(Operation)
	tlsop.cb = cb
	tlsop.conn = conn
	tlsop.type = .Close
	tlsop.close.socket = nbio.TCP_Socket(socket)

	close_cb(nil, tlsop)

	close_cb :: proc(_: ^nbio.Operation, tlsop: ^Operation) {
		log.debug("close_cb")

		blocked: s2n.Blocked_Status
		if s2n.s2n_shutdown(tlsop.conn, &blocked) == s2n.Success {
			nbio.close_poly(tlsop.close.socket, tlsop, socket_close_cb)
			return
		}

		nbio.poll_poly(tlsop.close.socket, _map_blocked_to_poll(blocked), tlsop, close_cb)
	}

	socket_close_cb :: proc(_: ^nbio.Operation, tlsop: ^Operation) {
		log.debug("socket_close_cb")
		tlsop.conn = nil
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
