from socketserver import StreamRequestHandler,ThreadingTCPServer as TCPServer
import threading

import obspython as obs

ASCIITable = bytes(((c if c >= 32 and c < 127 else 0 for c in range(256))))
def stripascii(string):
    return string.translate(ASCIITable).partition(b'\0')[0].decode('ASCII')

class NexgenPacket(object):
    def __init__(self,stream):
        self.stream = stream
    def __iter__(self):
        return self
    def __next__(self):
        header = self.stream.read(0x70)
        if not header or len(header) < 0x70:
            raise StopIteration
        event = header[0xC]
        packetsize = int.from_bytes(header[0:4], byteorder='little')
        message = self.stream.read(packetsize - len(header))
        if not message:
            raise StopIteration
        return stripascii(message)

class ExecuteHandler(StreamRequestHandler):
    def handle(self):
        try:
            for message in NexgenPacket(self.rfile):
                self.server.handle(message)
        except ConnectionResetError:
            pass

class TCPExecuteServer(TCPServer):
    def __init__(self, server_address):
        super().__init__(server_address, ExecuteHandler, True)
        self.daemon_threads = True
        self.exec_lock = threading.Lock()
    def handle(self, name):
        with self.exec_lock:
            if name == "START RECORDING":
                obs.obs_frontend_recording_start()
            elif name == "STOP RECORDING":
                obs.obs_frontend_recording_stop()
            elif name == "START STREAMING":
                obs.obs_frontend_streaming_start()
                obs.obs_frontend_recording_start()
            elif name == "STOP STREAMING":
                obs.obs_frontend_streaming_stop()
                obs.obs_frontend_recording_stop()

def start_server():
    def run_server(server):
        server.serve_forever()
    server = TCPExecuteServer(('0.0.0.0', 50050))
    daemon = threading.Thread(target=run_server, args=(server,))
    daemon.start()
    return server

def script_load(settings):
    global my_server
    my_server = start_server()

def script_unload():
    my_server.shutdown()
