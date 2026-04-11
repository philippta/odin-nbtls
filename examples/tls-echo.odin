package main

import nbtls ".."
import "core:log"
import "core:nbio"

main :: proc() {
	// context.logger = log.create_console_logger()

	nbio.acquire_thread_event_loop()
	defer nbio.release_thread_event_loop()

	socket, err := nbio.listen_tcp({nbio.IP4_Any, 8443})
	assert(err == nil)


	config := nbtls.config_init_with_cert_and_key(cert_pem, key_pem)
	defer nbtls.config_destroy(config)

	nbtls.accept(socket, config, accept_cb)
	nbio.run()
}

accept_cb :: proc(op: ^nbtls.Operation) {
	log.debug("accepted client", op.accept.client)

	buf := make([]byte, 1024)
	nbtls.recv(op.conn, buf, recv_cb)

	nbtls.accept(op.accept.socket, op.config, accept_cb)
}

recv_cb :: proc(op: ^nbtls.Operation) {
	if op.recv.received == 0 do return

	log.debug("received", op.recv.received)
	log.debug(string(op.recv.buf[:op.recv.received]))
	delete(op.recv.buf)

	msg := "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\nok\n"
	nbtls.send(op.conn, transmute([]byte)msg[:], send_cb)
}

send_cb :: proc(op: ^nbtls.Operation) {
	if op.send.sent == 0 do return

	log.debug("sent")

	nbtls.close(op.conn, close_cb)
}

close_cb :: proc(op: ^nbtls.Operation) {
	log.debug("closed")
}

cert_pem :: `-----BEGIN CERTIFICATE-----
MIIDmjCCAgKgAwIBAgIQcVOYYbCIiDQGoWbiKxOLvDANBgkqhkiG9w0BAQsFADCB
lzEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMTYwNAYDVQQLDC1waGls
aXBwQE1hY0Jvb2tQcm8uZnJpdHouYm94IChQaGlsaXBwIFRhbmxhaykxPTA7BgNV
BAMMNG1rY2VydCBwaGlsaXBwQE1hY0Jvb2tQcm8uZnJpdHouYm94IChQaGlsaXBw
IFRhbmxhaykwHhcNMjYwNDExMDgwMjE4WhcNMjgwNzExMDgwMjE4WjBhMScwJQYD
VQQKEx5ta2NlcnQgZGV2ZWxvcG1lbnQgY2VydGlmaWNhdGUxNjA0BgNVBAsMLXBo
aWxpcHBATWFjQm9va1Byby5mcml0ei5ib3ggKFBoaWxpcHAgVGFubGFrKTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABM9ms/4y1HERjg24J95VLOqakkLEaZfmRiAp
yubP9RVJC8RGhTFBloQAYN8uyOWXU8X8q8Y6PGZlVXyBtDw3f92jYjBgMA4GA1Ud
DwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAfBgNVHSMEGDAWgBTd+gN/
5jcimn+rgUFBefS/DT8BvDAYBgNVHREEETAPgg1leGFtcGxlLmxvY2FsMA0GCSqG
SIb3DQEBCwUAA4IBgQAbOfTwOTL7d4UQNMXi3EwAfWaRx7PDTfHexWBEYN7/z9Sf
19Ac6zqaXoEpPHGNELnLlmHWPZm+3tgCP3F6JoxletRKVLu503r3HJghBCcF6DjT
rk3NnW2BHZc9QKHuaQE53myHEIjPy8/91YX87dFj3TJZJ7Q8405ARGvU2zPiXk+J
qKvs2HcTsxnH1mXMRzJ5qnjc/3uph96Rp2k00ArRUOSvN0JFGCy53/VOE+eOEiaA
AVIr5UleZ8wrSYfZfAgdO5FjrAQKAoR6VfV1AvsJJZjMnvP2FIiIjvfagam7pmEX
59FTcRyloWyuMTxzSjzZnCnutG2BvM0S0NeL137NsD9h+MYXk0SSy0qYuzCqkg1M
19ozJa3PkDNApaLkEtMQDwNL5vZb1satRbkbCuC6xD4tnx0Cq7cSL2YNhnikwQra
qPQjP70S8zwp0V/eHugj47H1YoNzXu4Htwxx7ndHO3rRJ1ejYz8ECCh4dTYdm0f8
/l9GvT2Wz6bFT0KA7MU=
-----END CERTIFICATE-----`


key_pem :: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjsrrDcZ543kRG5+H
cKvxzy4YFabgQCpzrDImdkhDQXOhRANCAATPZrP+MtRxEY4NuCfeVSzqmpJCxGmX
5kYgKcrmz/UVSQvERoUxQZaEAGDfLsjll1PF/KvGOjxmZVV8gbQ8N3/d
-----END PRIVATE KEY-----`
