import requests
import hashlib
import os

class VirusScannerVT(object):
    
    def __init__(self,apiKey):
        self.apiKey=apiKey
        assert(self.isKeyValid(self.apiKey))
        
    def __spldate__(self,update):
        return update[:4]+':'+update[4:6]+':'+update[6:]
    
    def isKeyValid(self,key):
        params = {'apikey': self.apiKey}
        r=requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        if r.status_code==200:
            return True
        return False
        
    def __sortDetected__(self,jsonRes):
        detected={}
        for i in jsonRes.keys():
            if jsonRes[i]['detected'] == True:
                isMalware=True
                detected[i]={'version':jsonRes[i]['version'],'result':jsonRes[i]['result'],'update':self.__spldate__(jsonRes[i]['update'])}
        return detected

    def scanHash(self,h):
        params = {'apikey': self.apiKey, 'resource': h}
        url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        res=url.json()
        if res['positives'] > 0:
            return self.__sortDetected__(res['scans'])
        return False
            
    
    def scanFile(self,path):
        h = hashlib.sha256(open(path,'rb').read()).hexdigest()
        return self.scanHash(h)
    
    
    def scanDir(self,path):
        res={}
        for i in self.__all_files_recursive__(path):
            try:
                detect = self.scanFile(i)
                if detect:
                    res[i]=detect
            except Exception as e:
                #print(e)
                pass
        return self.__reprot__(res)
    
    
    def __all_files_recursive__(self,path):
        f = self.__get_dir__(path)
        d=[]
        if len(f)>0:
            for i in f:
                if os.path.isfile(i):
                    d.append(i)
                try:
                    if os.path.isdir(i):
                        for n in self.__all_files_recursive__(i):
                            if os.path.isfile(n):
                                d.append(n)
                except:
                    pass
        return d
    

    def __get_dir__(self,path):
        return list(path+os.sep+i for i in os.listdir(path))
    
    
    def temp(self):
        try:
            os.mkdir(os.environ['AppData']+os.sep+'VT Report')
        except FileExistsError:
            pass
        return os.environ['AppData']+os.sep+'VT Report'
    
    
    def __reprot__(self,jsonData):
        date = dt.now().strftime("%d/%m/%Y %H:%M:%S")
        path= self.temp()+'Report.xlsx'
        wb = Workbook()
        ws = wb.active
        ws.append(['File','Vendor','Result','Update','Detected'])
        keys=list(jsonData.keys())
        for i in range(len(keys)):
            vendors=list(jsonData[keys[i]].keys())
            res,vend='',''
            for n in vendors:
                res+=jsonData[keys[i]][n]['result']+', '
                vend+=n+', '
            ws.append([keys[i],vend,res,date,str(len(vendors))+' vendors'])
        wb.save(path)
        return os.startfile(path)

    

    
def main():
    def __action__(hash_):
        try:
            print('\n\nAnalysing...')
            detect=vt.scanHash(hash_)
            try:
                vendors=len(detect)
            except:
                vendors=0
            print('\nThe hash was detected as malicious by '+str(vendors)+' Security Vendors')
            if detect:
                keys=list(detect.keys())
                print(f"\n{'Vendor':<20}{'Result':^40}{'Update':^20}{'Detected':>10}")
                print('-'*90)
                for i in keys:
                    print(f"{i:<20}{detect[i]['result']:^40}{detect[i]['update']:^20}{'True':>10}")
        except KeyError:
            print('invalid hash')
            
    key=input('Please Enter your api key: ')
    vt=VirusScannerVT(key)
    ask = input('======Virus Scanner======\n  (1) To scan hash\n  (2) To scan file\n  (3) To scan directory\n')
    if ask == '1':
        hash_=input('Please Enter hash to scan: ')
        __action__(hash_)
            
    elif ask =='2':
        path=input('Please Enter path to your file: ')
        hash_=hashlib.sha256(open(path,'rb').read()).hexdigest()
        __action__(hash_)
    
    else:
        path=input('Please Enter path to your Directory: ')
        
    
    
    
if __name__=='__main__':
    #main()
    pass
