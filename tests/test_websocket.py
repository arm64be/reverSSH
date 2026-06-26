import socket
import threading
import unittest

from reverssh.websocket import accept_websocket, connect_websocket


class WebSocketTests(unittest.TestCase):
    def test_websocket_stream_roundtrip(self):
        ready = threading.Event()
        result: list[bytes] = []

        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def run_server():
            ready.set()
            conn, _addr = server.accept()
            ws = accept_websocket(conn, "/relay/")
            result.append(ws.recv(3))
            ws.sendall(b"def")
            ws.close()
            server.close()

        thread = threading.Thread(target=run_server)
        thread.start()
        ready.wait(2)
        ws = connect_websocket(f"ws://127.0.0.1:{port}/relay/")
        ws.sendall(b"abc")
        self.assertEqual(ws.recv(3), b"def")
        ws.close()
        thread.join(2)
        self.assertEqual(result, [b"abc"])


if __name__ == "__main__":
    unittest.main()
