package main

import "core:log"
import "core:nbio"
import "core:os"


main :: proc() {
	f, err_create := os.create("nbio.log")
	assert(err_create == nil)

	context.logger = log.create_file_logger(f)

	nbio.acquire_thread_event_loop()
	defer nbio.release_thread_event_loop()

	socket, err := nbio.listen_tcp({nbio.IP4_Any, 8080})
	assert(err == nil)

	nbio.accept(socket, accept_cb)
	nbio.run()
}

accept_cb :: proc(op: ^nbio.Operation) {
	log.warn("ACCEPTED")

	nbio.poll(op.accept.client, .Receive, poll_cb)
}
poll_cb :: proc(_: ^nbio.Operation) {
	log.warn("POLLED")

	// never fires when peer closes connection.
	// how else do I nbio.close the socket?
}
