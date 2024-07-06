'''
♥; created 2024 copyright JST GPLv3
take a breath and hunt evil
'''
import argparse
import psutil
import os
import re
import hashlib
import subprocess
import pycurl
import inspect
from io import BytesIO
import certifi
import shutil
import datetime
from shadowcopy import shadow_copy as scopy


videoType = re.compile('.*[.](?:MP4|H264|MOV|AVI|WMV|FLV|F4V|MKV|WebM|AVCHD|MPEG2|3GP|3G2|OGV|M4V|ProRes)$', re.IGNORECASE)
otherType = re.compile('.*[.](?:M4A)$', re.IGNORECASE)#TODO: currently configured for debug/testing, set to img types
cliType = None
hashfeed=["b9ab94fd6a2e6b3f0d841529851f8db8","ba51c40c5eb8fdc2f9a98a28470b09fb"]#TODO: replace sample innocuous MD5 with target hash collection of value (sample is an AMD, ATI dll file and of a sample file found hash on test machine)
#Design implementation guide:
#Load hashfeed through external feed file such that compilation of hashes is negotiated by secure server share and encryption key
#Any implementation of sourcetracking to never include feed file via implementation of .ignore files
#All storage of feed file to implement data-at-rest guidelines

#Final packaging of tool deployable by forensic responder as .py across interfaces such as crowdstrike or remote cli as well as packaging to standalone .exe companioned to encypted hash database deployed as network architected

args = None
reportFlagAlert=False
reportTrace=""
reportIP=""
reportHostname=""
reportCSVPath=["filepath,md5"]
reportLogTime=["datetime,message,detail"]
acquireList=[]

def debug(statement=""):
    f = inspect.currentframe().f_back
    thisName = f.f_code.co_filename
    thisLine = f.f_lineno
    print('| %s %d: %s' % (thisName, thisLine, statement))
    None

def acquire(outpath=os.getcwd()+'\\jeResults\\acq'):#define: Acquisition of high valued forensic targets @outpath output directory
    if not os.path.exists(outpath):
        os.makedirs(outpath)
    getfile("C:\Windows\INF\setupapi.dev.log",outpath) #Acquire high value log containing usb device connection artifacts
    getfile("C:\Windows\System32\winevt\Logs\Security.evtx",outpath+"\\winevt")
    getfile("C:\Windows\System32\winevt\Logs\System.evtx",outpath+"\\winevt")
    
    #Process Registry Acquisitions
    for cur in os.listdir("C:\\Users"):
        tPath= "C:\\Users\\"+cur
        src= tPath+"\\NTUSER.DAT"
        dstDir = outpath+"\\"+cur

        if(os.path.isdir(tPath) and os.path.exists(src)):
           getfile(src,dstDir) #Acquire existing user ntuser.dat hive

    reghives=["C:\Windows\System32\config\SAM","C:\Windows\System32\config\SECURITY","C:\Windows\System32\config\SOFTWARE","C:\Windows\System32\config\SYSTEM"]
    for x in reghives:
        getfile(x,outpath) #Acquire critical windows registry hives

    for x in acquireList:
        try:
            getfile(x,outpath)
        except Exception as e:
            handleExcept(e)
    None

def getfile(src, dstDir):#define: Perform a attempt to metadata preserving copy of file @src to @dstDir, Failing by permissions, attempt via volume shadow copy technique against locked files. 
    try:
        dst= dstDir+'\\'+src[src.rfind('\\')+1:]
        
        if os.path.exists(src):
            if (not os.path.exists(dstDir)):
                    os.makedirs(dstDir)
            shutil.copy2(src,dstDir) #Acquire high value log containing usb device connection artifacts
            if os.path.exists(dst):
                    appendLogTime(message="Acquisition: %s"%(src),detail=md5(dst))
        else:
            appendLogTime(message="ACQ Skipped(File DNE): %s"%src)
    except PermissionError:
        try:
            scopy(src,dstDir) #Acquire high value log containing usb device connection artifacts
            if os.path.exists(dst):
                appendLogTime(message="Acquisition- UTILIZING SHADOW COPY: %s"%(src),detail=md5(dst))
        except Exception as e:
                handleExcept(e, "SKIPPING ACQ %s"%(src))
    except Exception as e:
            handleExcept(e)
    None

def appendLogTime(message="",detail=""):#define: Reports an auditable message to the report set
    global reportLogTime
    reportLogTime.append(str(datetime.datetime.now())+','+message+','+detail)
    None
    
def alert(hash):#define: Triggered match from hashfeed, initiate artifact collection
    global reportFlagAlert
    global reportTrace
    global reportIP
    global reportHostname
    debug("HI from ^litte one")
    appendLogTime("Alert Raised on value",hash)
    if (not reportFlagAlert):
        if(not args.cliFlagTracerMakeADifference):
            reportTrace=gettrace()#build ancillory report on visibility to known common target
        reportIP=getip()#get public facing ip of device
        reportHostname=subprocess.check_output(["hostname"])#get the device hostname

        acquire()
        reportFlagAlert=True
    None

def writeReport(outpath=os.getcwd()+'\\jeResults'):
    if not os.path.exists(outpath):
        os.makedirs(outpath)
    
    with open(outpath+'\\jeArtifacts.txt', 'w', newline='') as outfile:
        outfile.writelines('============================\r')
        outfile.writelines('HOSTNAME: <hostname>\r%s\r'%(reportHostname))
        outfile.writelines('============================\r')
        outfile.writelines('PUBLIC IP: <curl ifcfg.me>\r%s\r'%(reportIP))
        outfile.writelines('============================\r')
        outfile.writelines('TRACE: <tracert 8.8.8.8>\r%s\r'%(reportTrace))
        #reg QUERY "HKCU\Software\Microsoft\Internet Explorer\TypedURLs"


    with open(outpath+'\\jeResults.csv', 'w', newline='') as csvfile:
        for x in reportCSVPath:
            csvfile.writelines(x+'\r\n')
         
    with open(outpath+'\\jeLogTime.csv', 'w', newline='') as csvfile:
        for x in reportLogTime:
            csvfile.writelines(x+'\r\n')
    None

def main():
    global args
    global cliType
    parser = argparse.ArgumentParser(description='Forensics response script to triage [VILE] hash match')
    parser.add_argument("--path", help="Start path to begin recursive descent from. Unspecified means walk each of device's Mounts",type=str)
    parser.add_argument("--loadHashFileP", help="Designates path of unencrypted list of [VILE] hashes. Format 1 md5 / line",type=str)
    parser.add_argument("--re", help="Custom regex to match filename to, EX: '.*[.](?:MP4|H264|MOV|AVI|WMV|FLV|F4V|MKV|WebM|AVCHD|MPEG2|3GP|3G2|OGV|M4V|ProRes|M4A)$'",type=str)
    parser.add_argument("-d",help="Disable tracert, greatly affects speed on tests/regex development", action='store_true', dest='cliFlagTracerMakeADifference')
    parser.add_argument("--acquireFiles", help="Path to .txt containing listing of files to acquire if TRIGGERED. Format 1 file path / line",type=str)
    args = parser.parse_args()
    appendLogTime("Application began execution")
    #debug
    args.path="E:\\Code\\"
    #args.loadHashFileP="E:\\Code\\jericho\\test.hash"
    #args.re=".*"
    args.acquireFiles="E:\\Code\\jericho\\jericho\\testAcqPath.txt"
    #
    try:
        if args.loadHashFileP:
            loadHashFeedUNENC(args.loadHashFileP)
        if args.re:
            cliType=re.compile(args.re, re.IGNORECASE)
        if args.acquireFiles:
            loadAcquireList(args.acquireFiles)


        if (not args.path):#No path specified, step through all mounted partitions
            partition = psutil.disk_partitions()
            for p in partition:
                examine(p.mountpoint)
        else:
            examine(args.path.rstrip('\\')+'\\')

        if(reportFlagAlert):
            writeReport()
            
    except Exception as e:
        handleExcept(e)
    yippee("Execution Complete")
    None
        
def loadHashFeedUNENC(path):#define: This function loads an unencrypted hash feed of file format md5, one hash per line ('\r\n' delimited)
    hashfeed.clear()
    with open(path) as inf:
        for line in inf:
            hashfeed.append(line.strip('\r').strip('\n'))
    None

def loadAcquireList(path):#define: This function loads an filelist of additionally requested files to be acquired given an alert match. FORMAT str, one per line ('\r\n' delimited), MAY SPECIFY DYNAMIC USER FOLDERS USING "?USER" ex: "C:\Users\?USER\NTUSER"
    acquireList.clear()
    with open(path) as inf:
        for line in inf:
            acquireList.append(line.strip('\r').strip('\n'))
    None

def handleExcept(e,postmessage=""):
    appendLogTime("INFO-WARN: %s %s"%(str(e),postmessage))
    print('\x1b[6;30;42m' + str(e)+"\n^^^^^^^^^^^^^^^^^^"+ '\x1b[0m')
    None

def yippee(response=""):
    print('!!!!!YIPPEE!!!!! '+response)
    None


def examine(path):#define: given a filepath, recursively explore all directories within it checking videofile types against hashfeed to determine for alert
    cap=step(path)
    while(x := next(cap, None)) is not None:
        try:
            if(os.path.isdir(x)):
                examine(x+r'\\')

            if(videoType.match(x) or otherType.match(x) or (cliType and cliType.match(x))):
                print('==========================================HASH REQUEST=============================================================')
                hash=md5(x)
                reportCSVPath.append(x+','+hash)#passively collect report of videohashes along way in case of triggering alert csvfmt<FILEPATH,MD5>
                print(hash)
                if hash in hashfeed:
                    print("<<<<<<<<<<<<<<<<<Trigger>>>>>>>>>>>>>>>>>")
                    alert(hash)#INITIATE REPORTING ALERT
                    

            print(x)
        except Exception as e:
            handleExcept(e)
    None


def getip(iface=None): #define: issue command {curl ifcfg.me} to identify public ip
    buffer = BytesIO()
    c = pycurl.Curl()
    c.setopt(c.URL, 'ifcfg.me')
    c.setopt(c.WRITEDATA, buffer)
    c.setopt(c.CAINFO, certifi.where())
    if iface:
        c.setopt(pycurl.INTERFACE, iface)
    c.perform()
    c.close()

    body = buffer.getvalue()
    # Body is a byte string.
    # We have to know the encoding in order to print it to a text file
    # such as standard output.
    return(body.decode('iso-8859-1'))
    None
    
def gettrace(target="8.8.8.8"): #define: issue command {tracert 8.8.8.8} to identify network characteristics to known destination @target=specify ip connection string
    print("Enacting TRACERT- caution: patience please, get you a cup of coffee, you deserve it <3")
    return subprocess.check_output(["tracert",target])
    None

def md5(fname): #define: collects md5 hash via chunking in prep handling of potentially large files
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()
    None

def step(oneOfPath): #define: generator on provided path yield- filenames @oneOfPath
     for cur in os.listdir(oneOfPath):
          path=oneOfPath+cur
          yield(path)

if __name__== '__main__':
    main()
