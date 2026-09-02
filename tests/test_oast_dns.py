"""DNS-based OAST catcher tests — parse query, extract token, answer A record."""
import socket
import struct

from pentestiq.oast import DnsServer, OastStore, parse_qname


def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _dns_query(name: str, txn: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", txn, 0x0100, 1, 0, 0, 0)   # RD=1, QD=1
    question = _encode_qname(name) + struct.pack(">HH", 1, 1)  # type A, class IN
    return header + question


def test_parse_qname():
    q = _dns_query("abc123def456.oast.test")
    name, _ = parse_qname(q)
    assert name == "abc123def456.oast.test"


def test_dns_catcher_records_token_and_answers():
    store = OastStore()
    srv = DnsServer(host="127.0.0.1", port=0, answer_ip="10.1.2.3", store=store).start()
    try:
        token = "deadbeefcafe1234"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(_dns_query(f"{token}.oast.test"), (srv.host, srv.port))
        resp, _ = sock.recvfrom(2048)
        sock.close()

        # recorded as a DNS interaction correlated to the token
        hits = store.poll(token)
        assert hits and hits[0].kind == "dns"
        assert hits[0].host == f"{token}.oast.test"

        # response echoes txn id and carries one answer with our A record
        assert resp[:2] == struct.pack(">H", 0x1234)
        ancount = struct.unpack(">H", resp[6:8])[0]
        assert ancount == 1
        assert socket.inet_ntoa(resp[-4:]) == "10.1.2.3"
    finally:
        srv.stop()


def test_dns_catcher_ignores_non_token_labels():
    store = OastStore()
    srv = DnsServer(host="127.0.0.1", port=0, store=store).start()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(_dns_query("www.example.com"), (srv.host, srv.port))
        sock.recvfrom(2048)
        sock.close()
        assert store.all() == []          # "www" is not a token -> not recorded
    finally:
        srv.stop()
