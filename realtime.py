import time 
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import messagebox
from VtScanner import VirusScannerVT

class liveTimeProtection(object):
    
    def __init__(self,key,path):
        self.vt=VirusScannerVT(key)
        self.key=key
        self.path=path
        
    
    def scan(self):
        return self.vt.scanFile(self.path)
        
    def creatMsg(self,jsonData):
        if jsonData:
            vendors=list(jsonData.keys())
            return self.popupmsg('Virus was detected!!',self.path)
        
    
    def popupmsg(self,titel, msg):
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(titel, msg)
        root.lift()
        
    class LiveHandler(FileSystemEventHandler):

        def __init__(self,key):
            self.key=key

        def on_created(self, event):
            print(self.key)
            lt=liveTimeProtection(key,event.src_path)
            lt.creatMsg(lt.scan())


    def start(self):
        observer = Observer()
        event_handler = self.LiveHandler(self.key) # create event handler
        # set observer to use created handler in directory
        observer.schedule(event_handler, path=r'C:\Users\aronc\Desktop\Advanced-spyware-managed-through-ngrok-any-file-sharing-server-main\Client')
        observer.start()

        # sleep until keyboard interrupt, then stop + rejoin the observer
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
        
        
        
if __name__=='__main__':
    key='VT api key'
    path='Path to monitor'
    liveTimeProtection(key,path)
    
    
