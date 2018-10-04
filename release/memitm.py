import sys,mmap,struct,time,os,random,httplib
from ctypes import *
psutil_ok = False
try:
    import psutil
    psutil_ok = True
except Exception as e:
    print "PSUTIL not found (run pip install psutil). Can't inject by name!"
    pass


############## UPDATE HERE ##############


def logger(data, msgID=None,pid=0):
    sprnt( "#%x : 0x%x bytes" % (msgID,len(data)))
    return
    # examples:
    # open("log_"+str(msgID)+".bin","ab").write(data)
    # open("log_printable.txt","ab").write(str(msgID)+"\t"+printable(data)+"\n")
    # open("log_hexmessages.csv","ab").write(str(msgID)+","+data.encode("hex")+"\r\n")
    #return data

def fuzzer(data, msgID=None, pid = 0):
    data = bufferBitFlip(data, filter=20)
    if httpNetSend(str(pid)+","+str(msgID)+","+data.encode("hex"), "PLACE YOUR IP ADDRESS HERE", 80) == 0:
        sprnt("Network failure.")
    return data

############## !UPDATE HERE ##############


# windows-cmd-proof-print
def sprnt(x):
    try:
        print x
    except:
        pass
    return

httpConn = None
def httpNetSend(m, rHost, rPort):
    global httpConn
    if httpConn is None:
        try:
            httpConn = httplib.HTTPConnection(rHost, rPort,timeout=1)
            httpConn.connect()
        except:
            httpConn = -1
            return 0
            pass
    if httpConn != -1:
        try:
            httpConn.request("GET", "/?"+m)
            httpConn.getresponse()
        except:
            try:
                httpConn.close()
                httpConn = httplib.HTTPConnection(rHost, rPort,timeout=1)
                httpConn.connect()
            except:
                httpConn = -1
                return 0
                pass
            pass
    return 1

def printable(data):
    x = ""
    chs = "1234567890AZERTYUIOPQSDFGHJKLMWXCVBNazertyuiopqsdfghjklmwxcvbn&\"#'{([-|_\\^@)]=+}$*%!:/;.,?"
    for i in data:
        if i in chs:
            x += i
        else:
            x += '.'
    return x

def bitflip(c):
    n = ord(c)
    bitf = 1 << random.randint(0,7)
    n = n ^ bitf
    c = chr(n)
    return c
def bufferBitFlip(data, rate=0.01, filter=20):
    if len(data) <= 2:
        return data
    cnt = int(len(data)*rate)
    if random.randint(0,filter) != 0:
        return data
    if cnt == 0:
        cnt = 1
    for i in range(cnt):
        z = random.randint(0,len(data)-2)
        data = data[:z] + bitflip(data[z]) + data[z+1:]
    return data

############################################

def injectDll(pid):
    PROCESS_ALL_ACCESS = ( 0x00F0000 | 0x00100000 | 0xFFF )
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = windll.kernel32

    h_process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid) )
    if not h_process:
        sprnt( "\t\tOpenProcess failed on %d" %(pid))
        return 1

    x = c_int(0)
    kernel32.IsWow64Process(h_process, byref(x))
    kernel32.CloseHandle(h_process)
    
    if x == 0:
        sprnt( "\t\tx86 process!")
        os.system("injecter.exe "+str(pid))
    else:
        sprnt( "\t\tx64 process!")
        os.system("injecter64.exe "+str(pid))

    return

sharedMemoryArea = 0
sEvent = 0
rEvent = 0
def getSharedMem(pid):
    global sEvent,rEvent,sharedMemoryArea
    SHAREDMEMSIZE = 0x20000
    SYNCHRONIZE = 0x00100000
    EVENT_MODIFY_STATE = 2
    SHAREDMEMNAME = "Local\\SuperMem_%x" % (pid)
    SHAREDMEMEVENTNAME_R = c_char_p("Local\\SuperMemEvent_REPLY_%x" % (pid))
    SHAREDMEMEVENTNAME_S = c_char_p("Local\\SuperMemEvent_SEND_%x" % (pid))
    maxtries = 10
    c = 0
    sharedMemoryArea = mmap.mmap(0, SHAREDMEMSIZE, SHAREDMEMNAME)

    kernel32 = windll.kernel32
    while c < maxtries:
        rEvent = kernel32.OpenEventA(SYNCHRONIZE | EVENT_MODIFY_STATE, False, SHAREDMEMEVENTNAME_R)
        sEvent = kernel32.OpenEventA(SYNCHRONIZE | EVENT_MODIFY_STATE, False, SHAREDMEMEVENTNAME_S)
        if sEvent == 0 or rEvent == 0:
            time.sleep(0.5)
            c+=1
        else:
            break
    if sEvent == 0 or rEvent == 0:
        return 1
    return 0

def cleanup():
    global sEvent,rEvent,sharedMemoryArea
    kernel32 = windll.kernel32
    if sEvent != 0:
        kernel32.CloseHandle(sEvent)
        sEvent = 0
    if rEvent != 0:
        kernel32.CloseHandle(rEvent)
        rEvent = 0
    if sharedMemoryArea != None:
        sharedMemoryArea.close()
        sharedMemoryArea =  None
    return

def getConfigEntries(conf):
    cpt = 0
    entries = []
    while len(conf) > 4:
        configData = conf
        sz = struct.unpack("<L", configData[:4])[0]
        configData = configData[4:]
        x = struct.unpack("<H", configData[:2])[0]
        configData = configData[2:]
        modName = configData[:x-1]
        configData = configData[x:]
        modOffset = struct.unpack("<L", configData[:4])[0]
        entries.append((modName, modOffset))
        conf = conf[sz:]
        cpt += 1
    return entries

def printConfig(conf):
    sprnt( "\t\tHooks:")
    cdata = getConfigEntries(conf)
    for x,y in cdata:
        sprnt( "\t\t\t"+x+ ": "+ hex(y))
    return

def printFullConfig(configData):

    sprnt( "Config:")
    sprnt( "\ts.dwSize: %x" % (struct.unpack("<L", configData[:4])[0]))
    configData = configData[4:]

    x = struct.unpack("<H", configData[:2])[0]
    sprnt( "\ts.modNameSize: %x" % (x))
    configData = configData[2:]

    sprnt( "\ts.modName: %s" % (configData[:x]))
    configData = configData[x:]

    sprnt( "\ts.moduleOffset: %x" % (struct.unpack("<L", configData[:4])[0]))
    configData = configData[4:]

    sprnt( "\ts.nopsSize: %x" % (struct.unpack("<H", configData[:2])[0]))
    configData = configData[2:]

    x = struct.unpack("<H", configData[:2])[0]
    sprnt( "\ts.t1OpcodesSize: %x" % (x))
    configData = configData[2:]

    sprnt( "\ts.t1Opcodes: %s" % (configData[:x].encode("hex")))
    configData = configData[x:]

    x = struct.unpack("<H", configData[:2])[0]
    sprnt( "\ts.t2OpcodesSize: %x" % (x))
    configData = configData[2:]
    sprnt( "\ts.t2Opcodes: %s" % (configData[:x].encode("hex")))
    configData = configData[x:]

    x = struct.unpack("<H", configData[:2])[0]
    sprnt( "\ts.relocsCount: %x" % (x))
    configData = configData[2:]
    sprnt( "\trelocs: %s" % (configData.encode("hex")))
    return

def send_config(cData):
    global rEvent,sharedMemoryArea
    printConfig(cData)
    START_MONITORING = 0x2
    sharedMemoryArea.write(struct.pack("<L",START_MONITORING))
    sharedMemoryArea.write(struct.pack("<L",len(cData)))
    sharedMemoryArea.write(cData)
    kernel32 = windll.kernel32
    kernel32.SetEvent(rEvent)
    return

def do_something(data, hID, pid):
    logger(data, hID, pid)
    x = fuzzer(data, hID, pid)
    if len(x) == len(data) and x != data:
        return x
    return None

def monitorSMEM(pid):
    global rEvent,sEvent,sharedMemoryArea
    kernel32 = windll.kernel32

    MUTATE_BUFFER_MSGID            = 0x01
    MUTATE_BUFFER_MSGID_RESPONSE   = 0x03
    MUTATE_BUFFER_MSGID_RESP_MOD   = 0x04
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    WAIT_TIMEOUT = 0x102
    WAIT_OBJECT_0 = 0x0
    while True:
        # waits for a message
        stat = kernel32.WaitForSingleObject(sEvent, 5000)
        if stat == WAIT_OBJECT_0:
            # reads the message ID and the size
            sharedMemoryArea.seek(0)
            opCode = struct.unpack("<L",sharedMemoryArea.read(4))[0]
            hID = 0
            opCodeL = opCode & 0xFFFF
            if opCodeL == MUTATE_BUFFER_MSGID:
                hID = opCode >> 16

            dataSize = struct.unpack("<L",sharedMemoryArea.read(4))[0]

            # message buffer
            data = sharedMemoryArea.read(dataSize)

            # do something!
            x = do_something(data,hID, pid)
            sharedMemoryArea.seek(0)
            if x != None and len(x) == len(data) and x != data:
                # update? let's patch the ID too
                sharedMemoryArea.write(struct.pack("<L",MUTATE_BUFFER_MSGID_RESP_MOD))
                sharedMemoryArea.write(struct.pack("<L",len(data)))
                sharedMemoryArea.write(x)
            else:
                sharedMemoryArea.write(struct.pack("<L",MUTATE_BUFFER_MSGID_RESPONSE))

            # set event
            kernel32.SetEvent(rEvent)
        else:
            # process disapeared?
            h_process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if h_process == 0:
                sprnt( "\t\tProcess seems down (OpenProcess)!")
                kernel32.CloseHandle(h_process)
                return
            code = c_ulong(0)
            if kernel32.GetExitCodeProcess(h_process, byref(code)) == True:
                if code.value != STILL_ACTIVE:
                    sprnt( "\t\tProcess seems down (GetExitCodeProcess %x)!" % (code.value))
                    kernel32.CloseHandle(h_process)
                    return
            kernel32.CloseHandle(h_process)
    return


def monitor_process_by_pid(pid):
    sprnt( "Process found: "+str(pid))
    sprnt( "\tInjection...")
    injectDll(pid)
    sprnt( "\tCommunication...")
    if getSharedMem(pid) == 0:
        sprnt( "\tCommunication etablished.")
        sprnt( "\tSending config...")
        send_config(config_data)
        sprnt( "\tMonitoring...")
        monitorSMEM(pid)
        sprnt( "\tMonitoring ended, cleanup")
        cleanup()
    else:
        sprnt("\tCommunication failed!")
    return

def monitor_process(name, c_respawn = None):
    global psutil_ok
    if psutil_ok is False:
        return
    MAX_TRIES = 60
    TIMEOUT_T = 30
    tmout = 0
    while tmout < MAX_TRIES:
        found = False
        sprnt("-----------------------------")
        sprnt( "Searching for %s..." % (name))
        for p in psutil.process_iter():
            if p.name() == name:
                monitor_process_by_pid(p.pid)
                tmout = 0
                found = True
        if found is False and c_respawn is not None:
            sprnt("\tNot found, let's try to restart it")
            os.system("start "+c_respawn)
        elif found is False:
            time.sleep(TIMEOUT_T)
        tmout += 1
    return

if __name__ == "__main__":
    if (len(sys.argv) < 3):
        sprnt( "Usage : %s <PID>/<PROCESSNAME> <configfile> (<restart commandline>)" %(sys.argv[0]))
        sprnt( " - PROCESSNAME: the first one will be picked. If it dies, the next one will be picked, and so on.")
        sprnt( " - PROCESSNAME only: you may give a commandline which may be used to respawn the process :).")
        sprnt( "Ex:")
        sprnt( "\t%s 1111 config.bin => process with PID 1111" %(sys.argv[0]))
        sprnt( "\t%s explorer.exe config.bin => all 'explorer.exe' processes will be targeted, one by one." %(sys.argv[0]))
        sprnt( "\t%s test.exe config.bin C:\\toto\\test.exe => all 'test.exe' processes. If none are found, a 'cmd /c start C:\\toto\\test.exe' will be issued." %(sys.argv[0]))
        sprnt( "\t%s service.exe config.bin \"sc start service\" => auto respawn a service (run as High IL!)" %(sys.argv[0]))
        sys.exit(0)

    pid = sys.argv[1]
    conf_path = sys.argv[2]
        
    # read la config
    config_data = open(conf_path,"rb").read()
    try:
        if int(pid) != 0:
            monitor_process_by_pid(pid)
    except:
        sprnt("Auto mode started")
        restartcmd = None
        if len(sys.argv) > 3:
            restartcmd = sys.argv[3]
        sprnt("\tProcessname: %s" % (pid))
        if restartcmd is not None:
            sprnt("\tProcess restart: %s" % (restartcmd))
        monitor_process(pid,restartcmd)
        pass


