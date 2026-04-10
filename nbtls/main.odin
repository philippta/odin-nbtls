package main

import "../s2n"
import "core:c"
import "core:fmt"
import "core:nbio"
import "core:os"
import "core:strings"

config: ^s2n.Config

main :: proc() {
	cert_pem, _ := os.read_entire_file("example.local.pem", context.allocator)
	key_pem, _ := os.read_entire_file("example.local-key.pem", context.allocator)
	cert_pem_c := strings.clone_to_cstring(string(cert_pem))
	key_pem_c := strings.clone_to_cstring(string(key_pem))

	s2n.s2n_init()
	config = s2n.s2n_config_new()
	assert(config != nil)

	assert(s2n.s2n_config_set_cipher_preferences(config, "default") == s2n.Success)
	assert(s2n.s2n_config_add_cert_chain_and_key(config, cert_pem_c, key_pem_c) == s2n.Success)

	nbio.acquire_thread_event_loop()
	defer nbio.release_thread_event_loop()

	socket, err := nbio.listen_tcp({nbio.IP4_Any, 8443})
	assert(err == nil)

	nbio.accept(socket, accept_cb)
	nbio.run()
}

accept_cb :: proc(op: ^nbio.Operation) {
	assert(op.accept.err == nil)

	conn := s2n.s2n_connection_new(.Server)
	assert(conn != nil)
	assert(s2n.s2n_connection_set_config(conn, config) == s2n.Success)
	assert(s2n.s2n_connection_set_fd(conn, c.int(op.accept.client)) == s2n.Success)

	nbio.poll_poly(op.accept.client, .Receive, conn, negotiate_cb)
}

negotiate_cb :: proc(op: ^nbio.Operation, conn: ^s2n.Connection) {
	fmt.println("negotiate_cb")
	blocked: s2n.Blocked_Status
	ret := s2n.s2n_negotiate(conn, &blocked)
	if ret == s2n.Success {
		send_cb(op, conn)
		return
	}

	#partial switch blocked {
	case .Not_Blocked:
		return
	case .Blocked_On_Read:
		nbio.poll_poly(op.poll.socket, .Receive, conn, negotiate_cb)
	case .Blocked_On_Write:
		nbio.poll_poly(op.poll.socket, .Send, conn, negotiate_cb)
	case:
		panic("wtf?")
	}

}

send_cb :: proc(op: ^nbio.Operation, conn: ^s2n.Connection) {
	fmt.println("send_cb")

	msg := "Hello\n"
	blocked: s2n.Blocked_Status
	ret := s2n.s2n_send(conn, raw_data(msg), len(msg), &blocked)
	if ret >= 0 {
		shutdown_cb(op, conn)
		return
	}

	#partial switch blocked {
	case .Not_Blocked:
		return
	case .Blocked_On_Read:
		nbio.poll_poly(op.poll.socket, .Receive, conn, send_cb)
	case .Blocked_On_Write:
		nbio.poll_poly(op.poll.socket, .Send, conn, send_cb)
	case:
		panic("wtf?")
	}
}

shutdown_cb :: proc(op: ^nbio.Operation, conn: ^s2n.Connection) {
	fmt.println("shutdown_cb")
	blocked: s2n.Blocked_Status
	if s2n.s2n_shutdown(conn, &blocked) == s2n.Success {
		return
	}

	#partial switch blocked {
	case .Not_Blocked:
		return
	case .Blocked_On_Read:
		nbio.poll_poly(op.poll.socket, .Receive, conn, shutdown_cb)
	case .Blocked_On_Write:
		nbio.poll_poly(op.poll.socket, .Send, conn, shutdown_cb)
	case:
		panic("wtf?")
	}
}
