import tkinter as tk
from tkinter import messagebox, simpledialog
import sys
import threading
from queue import Queue, Empty as EmptyQueue
from time import strftime
import re

def timestamp():
    return strftime("%a, %d %b %Y %H:%M:%S")

class Status:
    def __init__(self, fh):
        self.output = fh
    def write(self, message):
        self.output.write(f"{timestamp()}: {message}\n")

class ThreadStatus:
    def __init__(self, ui):
        self.ui = ui
        self.lock = threading.Lock()
    def write(self, message):
        with self.lock:
            ui.write(message)

class AsyncStatus:
    def __init__(self, ui):
        self.ui = ui
    def write(self, message):
        self.ui.asyncwrite(message);

class QueueStatus:
    def __init__(self, ui):
        self.queue = Queue()
        ui.monitorqueue(self.queue)
    def write(self, message):
        self.queue.put(message)

_Status = Status(sys.stdout)

def status():
    return _Status

def setstatus(ui):
    global _Status
    _Status = ui

class ListProxy:
    def __init__(self, ui):
        self.ui = ui
    def get(self, name):
        return self.ui.getitem(name)

def parsegeometry(geometry):
    m = re.match(r'(\d+)x(\d+)([-+]\d+)([-+]\d+)', geometry)
    if not m:
        raise ValueError(f"failed to parse geometry string: {repr(geometry)}")
    return map(int, m.groups())

class ItemEntryDialog(simpledialog.Dialog):
    def body(self, master):
        tk.Label(master, text="Event name").grid(row=0)
        tk.Label(master, text="Command").grid(row=1)
        self.namefield = tk.Entry(master, width=45)
        self.valuefield = tk.Entry(master, width=45)
        self.namefield.grid(row=0, column=1)
        self.valuefield.grid(row=1, column=1)
        return self.namefield
    def apply(self):
        name,value = self.namefield.get().strip(), self.valuefield.get()
        if name:
            self.result = (name,value)

class Application(tk.Tk):
    MESSAGE_EVENT = '<<WriteStatus>>'

    def __init__(self, title, master=None):
        super().__init__(master)
        self.title(title)
        self.tk.call('tk', 'scaling', 1.5)
        #self.pack()
        #self.create_menu()
        self.create_list()
        self.create_text()
        self.bind('<Configure>', self.initsize)

    def initsize(self, event):
        if event.widget == self:
            self.unbind('<Configure>')
            self.minsize(event.width, event.height)

    def destroy(self):
        if messagebox.askyesno("Question", "Really quit?"):
            super().destroy()

    def create_menu(self):
        mb = tk.Menu(self)
        mb.add_command(label="Exit", command=self.destroy)
        self.config(menu=mb)

    def create_list(self):
        pane = tk.Frame(self)
        listbox = tk.Listbox(pane, exportselection=False)
        listbox.pack(fill=tk.BOTH, expand=True)
        self.listbox = listbox
        bbox = tk.Frame(pane)
        badd = tk.Button(bbox, text="Add", command=self.addlist)
        badd.pack(side=tk.LEFT)
        bdel = tk.Button(bbox, text="Remove", command=self.dellist)
        bdel.pack(side=tk.LEFT)
        bbox.pack(side=tk.BOTTOM, fill=tk.X)
        pane.pack(side=tk.RIGHT, fill=tk.Y)
        self.listitems = dict()
        self.list_lock = threading.Lock()

    def create_text(self):
        text = tk.Text(self, wrap=tk.NONE, width=50, height=20)
        text['state'] = tk.DISABLED
        text.bind("<1>", lambda e: text.focus_set())
        text.pack(fill=tk.BOTH, expand=True)
        self.text = text
        self.message_lock = threading.Lock()
        self.event_add(Application.MESSAGE_EVENT, tk.NONE)
        self.bind(Application.MESSAGE_EVENT, self._write)

    def asyncwrite(self, message):
        with self.message_lock:
            tk.Event.VirtualEventData = message
            self.event_generate(Application.MESSAGE_EVENT)

    def _write(self, event):
        self.write(event.VirtualEventData)

    def monitorqueue(self, queue):
        self.queue = queue
        self._monitor()

    def _monitor(self):
        try:
            while True:
                message = self.queue.get_nowait()
                self.write(message)
                self.update_idletasks()
        except EmptyQueue:
            pass
        self.after(100, self._monitor)

    def write(self, message):
        self.text['state'] = tk.NORMAL
        self.text.insert(tk.END, f"\n{timestamp()}: {message}")
        self.text.see(tk.END)
        #self.text.delete('100.0', tk.END)
        self.text.delete('1.0', tk.END+'-100l')
        self.text['state'] = tk.DISABLED

    def _setlist(self, name, value):
        with self.list_lock:
            if name not in self.listitems:
                self.listbox.insert(tk.END, name)
            self.listitems[name] = value
    def addlist(self, item=None):
        if item is None:
            dialog = ItemEntryDialog(self, title="Enter new command")
            if dialog.result:
                self._setlist(*dialog.result)
        else:
            self._setlist(*item)
            
    def dellist(self, name=None):
        if name is None:
            with self.list_lock:
                for item in self.listbox.curselection():
                    name = self.listbox.get(item)
                    del self.listitems[name]
                    self.listbox.delete(item)
        else:
            with self.list_lock:
                if name in self.listitems:
                    try:
                        del self.listitems[name]
                        item = self.listbox.get(0, tk.END).index(name)
                        self.listbox.delete(item)
                    except ValueError:
                        pass

    def getitem(self, name):
        with self.list_lock:
            return self.listitems.get(name)
    def getallitems(self):
        with self.list_lock:
            return self.listitems.items()

if __name__=='__main__':
    app = Application("UI")
    app.mainloop()
