from socketserver import StreamRequestHandler,BaseRequestHandler,TCPServer
from subprocess import DEVNULL, Popen
import socket
import sys
from time import strftime

def timestamp():
    return strftime("%a, %d %b %Y %H:%M:%S")

def spawn(args):
    Popen(args, stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL, start_new_session=True, creationflags=0x10)

ASCIITable = bytes(((c if c >= 32 and c < 127 else 0 for c in range(256))))
def stripascii(string):
    return string.translate(ASCIITable).partition(b'\0')[0].decode('ASCII')

class ExecuteHandler(StreamRequestHandler):
    def handle(self):
        while True:
            header = self.rfile.read(0x70)
            if not header or len(header) < 0x70:
                break
            event = header[0xC]
            packetsize = int.from_bytes(header[0:4], byteorder='little')
            message = self.rfile.read(packetsize - len(header))
            if not message:
                break
            message = stripascii(message)
            execute = self.server.apps.get(message)
            if execute:
                if message:
                    sys.stdout.write(f"{timestamp()}: {message}\n")
                spawn(execute)

class DumpHandler(BaseRequestHandler):
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
                sys.stdout.write("%06X: "%count + bytestring + "    " + charstring + "\n")
                count += len(block)
                block = self.request.recv(16)
        except BlockingIOError:
            pass
        except socket.timeout:
            pass
        sys.stdout.write("\n")

class TCPExecuteServer(TCPServer):
    def __init__(self, server_address, RequestHandlerClass=ExecuteHandler, bind_and_activate=True):
        super(TCPExecuteServer, self).__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.apps = {}

if __name__=='__main__':
    server = TCPExecuteServer(('0.0.0.0',50050))
    server.apps["START RECORDING"] = r'"C:\Program Files\AutoHotkey\AutoHotkeyU64.exe" "C:\Users\cass\Desktop\StartRecording.ahk"'
    server.apps["STOP RECORDING"] = r'"C:\Program Files\AutoHotkey\AutoHotkeyU64.exe" "C:\Users\cass\Desktop\StopRecording.ahk"'
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n")
