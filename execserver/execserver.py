from socketserver import StreamRequestHandler,BaseRequestHandler,ThreadingTCPServer as TCPServer
from subprocess import DEVNULL, Popen
import threading
import socket
import sys
from ui import status

def spawn(args):
    Popen(args, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL, start_new_session=True, creationflags=0x10)

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
        for message in NexgenPacket(self.rfile):
            self.server.handle(message)

class TerminalHandler(BaseRequestHandler):
    def handle(self):
        count = 0
        self.request.settimeout(0.3)
        try:
            block = self.request.recv(16)
            while block:
                countstring = "%06X: " % count
                bytestring = " ".join((f"{'%02X'%c}" for c in block[:8])).ljust(23) + " - " + \
                            " ".join((f"{'%02X'%c}" for c in block[8:])).ljust(23)
                charstring = block.translate(ASCIITable).replace(b'\0',b'.').decode("ascii").ljust(16)
                #sys.stdout.write("%06X: "%count + bytestring + "    " + charstring + "\n")
                self.server.output.write("%06X: "%count + bytestring + "    " + charstring + "\n")
                count += len(block)
                block = self.request.recv(16)
        except BlockingIOError:
            pass
        except socket.timeout:
            pass
        self.server.output.flush()
        #sys.stdout.write("\n")

class DumpHandler(BaseRequestHandler):
    def handle(self):
        self.request.settimeout(0.3)
        while True:
            try:
                block = self.request.recv(16)
                self.server.output.write(block)
            except BlockingIOError:
                pass
            except socket.timeout:
                pass
            self.server.output.flush()

class TCPDumpServer(TCPServer):
    def __init__(self, server_address, output):
        handler = TerminalHandler if output.isatty() else DumpHandler
        super().__init__(server_address, handler, True)
        self.daemon_threads = True
        self.output = output


class TCPExecuteServer(TCPServer):
    def __init__(self, server_address, applist):
        super().__init__(server_address, ExecuteHandler, True)
        self.daemon_threads = True
        self.exec_lock = threading.Lock()
        self.apps = applist
    def handle(self, name):
        with self.exec_lock:
            execute = self.apps.get(name)
            if execute:
                if name:
                    status().write(name)
                spawn(execute)

if __name__=='__main__':
    server = TCPDumpServer(('0.0.0.0',50051), open("dump.txt","ab"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n")
