import ui
from execserver import TCPExecuteServer
import threading
import sys

def start_app(name):
    app = ui.Application(name)
    #ui.setstatus(ui.AsyncStatus(app))
    ui.setstatus(ui.QueueStatus(app))
    return app

def start_server(app):
    def run_server(server):
        ui.status().write("Starting server")
        server.serve_forever()
    server = TCPExecuteServer(('0.0.0.0',50050), ui.ListProxy(app))
    daemon = threading.Thread(target=run_server, args=(server,))
    daemon.start()
    return server

app = start_app("Exec Server")
try:
    config = open("execserver.cfg")
    for line in config:
        item = line.strip("\n").split(sep="\t", maxsplit=1)
        item[0] = item[0].strip()
        if item[0]:
            app.addlist(item)
except FileNotFoundError:
    pass
server = start_server(app)
ui.status().write("Starting app")
app.mainloop()
server.shutdown()
applist = app.getallitems()
if applist:
    open("execserver.cfg", "w").write("\n".join([n+"\t"+v for n,v in applist]))
