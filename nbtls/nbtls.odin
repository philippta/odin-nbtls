package nbtls

import "../s2n"
import "core:c"
import "core:fmt"
import "core:nbio"
import "core:os"
import "core:strings"

Connection :: s2n.Connection
Callback :: #type proc(op: Operation)

Operation :: struct {
	socket: nbio.TCP_Socket,
	conn:   ^Connection,
	buf:    []byte,
	err:    Error,
}

Error :: union {
	nbio.Accept_Error,
	nbio.Network_Error,
	nbio.Recv_Error,
	nbio.Send_Error,
}

config: ^s2n.Config

accept_with_cert_and_key_file :: proc(
	socket: nbio.TCP_Socket,
	cert_file: string,
	key_file: string,
	cb: Callback,
	allocator := context.allocator,
) {
	cert, _ := os.read_entire_file(cert_file, allocator)
	key, _ := os.read_entire_file(key_file, allocator)
	certc := strings.clone_to_cstring(string(cert), allocator)
	keyc := strings.clone_to_cstring(string(key), allocator)
	delete(cert)
	delete(key)

	s2n.s2n_init()
	config = s2n.s2n_config_new()
	assert(config != nil)
	assert(s2n.s2n_config_set_cipher_preferences(config, "default") == s2n.Success)
	assert(s2n.s2n_config_add_cert_chain_and_key(config, certc, keyc) == s2n.Success)

	nbio.accept_poly(socket, cb, accept_cb)

	accept_cb :: proc(op: ^nbio.Operation, cb: Callback) {
		fmt.println("accept_cb")
		if op.accept.err != nil {
			cb({_get_socket(op), nil, nil, _get_err(op)})
			return
		}

		conn := s2n.s2n_connection_new(.Server)
		assert(conn != nil)
		assert(s2n.s2n_connection_set_config(conn, config) == s2n.Success)
		assert(s2n.s2n_connection_set_fd(conn, c.int(op.accept.client)) == s2n.Success)

		handshake_cb(op, conn, cb)
	}

	handshake_cb :: proc(op: ^nbio.Operation, conn: ^s2n.Connection, cb: Callback) {
		fmt.println("handshake_cb")

		blocked: s2n.Blocked_Status
		if s2n.s2n_negotiate(conn, &blocked) == s2n.Success {
			cb({_get_socket(op), conn, nil, _get_err(op)})
			return
		}

		nbio.poll_poly2(_get_socket(op), _map_blocked_to_poll(blocked), conn, cb, handshake_cb)
	}
}

recv :: proc(socket: nbio.TCP_Socket, conn: ^Connection, buf: []byte, cb: Callback) {
	nbio.poll_poly3(socket, .Receive, conn, buf, cb, recv_cb)

	recv_cb :: proc(op: ^nbio.Operation, conn: ^s2n.Connection, buf: []byte, cb: Callback) {
		blocked: s2n.Blocked_Status
		ret := s2n.s2n_recv(conn, raw_data(buf), len(buf), &blocked)
		if ret >= 0 {
			cb({_get_socket(op), conn, buf, _get_err(op)})
			return
		}

		nbio.poll_poly3(_get_socket(op), _map_blocked_to_poll(blocked), conn, buf, cb, recv_cb)
	}
}

send :: proc(socket: nbio.TCP_Socket, conn: ^Connection, buf: []byte, cb: Callback) {
	nbio.poll_poly3(socket, .Send, conn, buf, cb, send_cb)

	send_cb :: proc(op: ^nbio.Operation, conn: ^s2n.Connection, buf: []byte, cb: Callback) {
		blocked: s2n.Blocked_Status
		ret := s2n.s2n_send(conn, raw_data(buf), len(buf), &blocked)
		if ret >= 0 {
			cb({_get_socket(op), conn, buf, _get_err(op)})
			return
		}

		nbio.poll_poly3(_get_socket(op), _map_blocked_to_poll(blocked), conn, buf, cb, send_cb)
	}
}


close :: proc(socket: nbio.TCP_Socket, conn: ^Connection, cb: Callback) {
	nbio.poll_poly2(socket, .Send, conn, cb, shutdown_cb)

	shutdown_cb :: proc(op: ^nbio.Operation, conn: ^s2n.Connection, cb: Callback) {
		blocked: s2n.Blocked_Status
		if s2n.s2n_shutdown(conn, &blocked) == s2n.Success {
			s2n.s2n_connection_free(conn)
			nbio.close_poly(op.poll.socket.(nbio.TCP_Socket), cb, close_cb)
			return
		}

		nbio.poll_poly2(_get_socket(op), _map_blocked_to_poll(blocked), conn, cb, shutdown_cb)
	}

	close_cb :: proc(op: ^nbio.Operation, cb: Callback) {
		cb({})
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
