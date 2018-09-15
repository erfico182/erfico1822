#!/usr/bin/env python

#### TODO LIST ####
# on dissconnect put message "hes dead jim!"
# put child procs pid number into a global variable
# while no socket check and empty the queue
###################

import sys, os, random, time, socket, errno, thread, binascii, struct, unicodedata
try:
    import hexdump
except:
    print '[+] Please install python hexdump module'
    print '[+] sudo pip install hexdump'
    print '[+] sudo easy_install hexdump'
    sys.exit(0)
try:
    import multiprocessing
    from multiprocessing import Process, Queue
except:
    print '[+] Failed to import from multiprocessing'
try:
    from subprocess import Popen
except:
    print '[+] Failed to import from subprocess'

if __name__ != '__main__':
    print 'BEGIN SCRIPT Hi My Name Is: {}'.format(__name__)

args = list(sys.argv)

if len(args) == 1:
    sys.stderr.write('Usage: botnetclient.py <host> <port>')
    sys.stderr.write('\r\n')
    sys.exit(1)
if len(args) == 2:
    hostport = args[1]
    hostport = hostport.split(':')
    if len(hostport) != 2:
        sys.exit(0)
    else:
        host = hostport[0]
        port = int(hostport[1])
        portstr = hostport[1]
if len(args) == 3:
    host = args[1]
    port = int(args[2])
    portstr = args[2]
if len(args) > 3:
    sys.exit(0)

loglevel = 9
newline = '\r'
logfile = '/tmp/{}_{}.log' .format(host, port)
f = open(logfile,'a')

NEW = (
'\x0a'
)

def stdin():
    while True:
        try:
            line = None
#            log(4, 'STDIN READY')
            line = raw_input()
            if line == '' and connected == True:
                heartbeat('CLIENT', 'PING')
            elif line != '' and connected == True:
                line = line + NEW
                data_send(line)
            time.sleep(0.2)
        except KeyboardInterrupt:
            signals(2, 'STDIN', 'SIGINT')
            raise
        except:
            raise

def stdout(type, msg):
    try:
        if type == int(1):
            print msg + newline
        if type >= int(2):
            print '\033[93m'+'='*76+'\033[0m'
            hexdump.hexdump(msg)
            print '\033[93m'+'='*76+'\033[0m'
    except KeyboardInterrupt:
        signals(2, 'STDOUT', 'SIGINT')
        raise
    except:
        raise

def debug(level, name, msg):
    ## 1 = VITAL INFO
    ## 2 = IMPORTANT INFO (VERBOSE)
    ## 3 = ARGS INFO (VERY VERBOSE)
    ## 4 = EXTRA AND OPTIONAL (EXTEME VERBOSE)
    debuglevel = 3
#    print '\033[91m'+'='*35+'\033[0m' + ' INFO ' + '\033[91m'+'='*35+'\033[0m'
    if level <= int(debuglevel):
        if msg == 'CALLED':
            log(1, '{} {}'.format(name, msg))
        if msg != 'CALLED':
            log(1, '{}: {}'.format(name, msg))
#    print '\033[91m'+'='*35+'\033[0m' + ' INFO ' + '\033[91m'+'='*35+'\033[0m'

def log(level, msg):
    now = time.time()
    h = host + ":" + portstr + " - - "
    t = time.strftime("[%d/%b/%Y:%H:%M:%S %z]") + " "
    if level == int(1):
        n = str('DEBUG')
    elif level == int(2):
        n = str('ERROR')
    elif level == int(3):
        n = str('WARN')
    elif level == int(4):
        n = str('INFO')
    elif level == int(5):
        n = str('FATAL')
    elif level == int(6):
        n = str('SIGINT')
    elif level == int(7):
        n = str('SIGKILL')
    else:
        n = str('+')
    if level >= int(loglevel):
        #debug = '{}'.format(int(debuglevel))
        try:
            stdout(1, h + t + '[' + n + '] ' + msg)
        except KeyboardInterrupt:
            sys.exit(0)
            raise
        except:
            sys.exit(0)
            raise

def dumphex(asciidata):
    debug(2, 'DUMPHEX', 'CALLED')
    debug(3, 'DUMPHEX', 'CALLED WITH {}'.format(asciidata))
    stdout(2, asciidata)

def genrandip(ip):
    ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
    return ip

def genrandlogin(login):
    debug(2, 'GENRANDLOGIN', 'CALLED')
    debug(3, 'GENRANDLOGIN', 'CALLED WITH {}'.format(login))
    usernames = ['root', '', 'admin', 'user', 'login', 'guest', 'support', 'toor']
    passwords = ['root', '', 'toor', 'admin', 'user', 'guest', 'login', 'changeme', '1234', '12345', '123456', 'default', 'pass', 'password']
    randomuser = random.choice(usernames)
    randompass = random.choice(passwords)
    if randomuser == '' and randompass == '':
        login = None
        debug(4, 'GENRANDLOGIN', 'REROLLING')
        genrandlogin(login)
    else:
        login = randomuser + ':' + randompass
        return login

def data_split(hexdata):
    debug(2, 'DATA SPLIT', 'CALLED')
    debug(3, 'DATA SPLIT', 'CALLED WITH {}'.format(hexdata))
    asciidata = None
    presplit = hexdata
    splithexdata = hexdata.split('0a')
    postsplit = splithexdata
    splitcounter = len(postsplit)
    splitcounter = int(splitcounter)
    while splitcounter >= int(1):
        for splitdata in splithexdata:
            debug(4, 'DATA SPLIT LOOP', 'COUNT {}'.format(splitcounter))
            splitdata = data_truncate(splitdata)
            if len(splitdata) != int(0):
                debug(4, 'DATA SPLIT LOOP', 'LENGTH {}'.format(len(splitdata)))
                asciidata = (binascii.unhexlify(splitdata))
                dumphex(asciidata)
                debug(4, 'DATA SPLIT LOOP', 'REMOVE 1 FROM COUNTER')
                splitcounter -= 1
                localqueue('DATA_SPLIT', 'PUT', asciidata)
                return None
            else:
                log(3, 'SPLIT DATA EMPTY')
        time.sleep(1)
    log(3, 'NOTHING MORE TO SPLIT')

def data_truncate(hexdata):
    debug(2, 'DATA TRUNC', 'CALLED')
    debug(3, 'DATA TRUNC', 'CALLED WITH {}'.format(hexdata))
    debug(4, 'DATA TRUNC', 'PRE LENGTH {}'.format(len(hexdata)))
    asciidata = (binascii.unhexlify(hexdata))
    #dumphex(asciidata)
    while hexdata[-4:] == ('0d0a'):
        hexdata = hexdata[:-4]
    while hexdata[-2:] == ('0a'):
        hexdata = hexdata[:-2]
    while hexdata[-2:] == ('0d'):
        hexdata = hexdata[:-2]
    while hexdata[-2:] == ('00'):
        hexdata = hexdata[:-2]
    debug(4, 'DATA TRUNC', 'MID LENGTH {}'.format(len(hexdata)))
    asciidata = (binascii.unhexlify(hexdata))
    #dumphex(asciidata)
    while hexdata[:-4] == ('0d0a'):
        hexdata = hexdata[-4:]
    while hexdata[:-2] == ('0a'):
        hexdata = hexdata[-2:]
    while hexdata[:-2] == ('0d'):
        hexdata = hexdata[-2:]
    while hexdata[:-2] == ('00'):
        hexdata = hexdata[-2:]
    debug(4, 'DATA TRUNC', 'POST LENGTH {}'.format(len(hexdata)))
    asciidata = (binascii.unhexlify(hexdata))
    #dumphex(asciidata)
    if len(hexdata) != int(0):
        debug(1, 'DATA TRUNC', 'RETURNING')
        return hexdata
    else:
        debug(1, 'DATA TRUNC', 'EMPTY')
        return None

def data_recv():
#    if hasattr(os, 'getppid'):  # only available on Unix
#        print 'data_recv parent process:', os.getppid()
#    print 'data_recv process id:', os.getpid()
    ## NOTE 0d we replace 0a we split
    global packet_recv
    global init_packet_recv
    global connected
    global sock
    global q
    global s
    debug(1, 'DATA_RECV', 'CALLED')
    try:
        data = None
        data = s.recv(4096)
        packet_recv += 1
#        log(4, 'RECV PACKET #{}'.format(packet_recv))
        hexdata = (binascii.hexlify(data))
        if len(data) == int(1):
            time.sleep(1)
        elif len(data) >= int(1):
            debug(4, 'DATA_RECV', '{} BYTE(S)'.format(len(data)))
            while hexdata[:2] == '00' or hexdata[-2:] == '00':
                hexdata = (data_truncate(hexdata))
                time.sleep(0.3)
            while '0d' in hexdata:
                hexdata = hexdata.replace('0d', '')
                time.sleep(0.3)
            while hexdata[:2] == '0a' or hexdata[-2:] == '0a':
                hexdata = (data_truncate(hexdata))
            if '0a' in hexdata:
                data_split(hexdata)
#                data_recv()
            else:
                asciidata = (binascii.unhexlify(hexdata))
#                dumphex(asciidata)
                localqueue('DATA_RECV', 'PUT', asciidata)
                time.sleep(0.3)
#                print 'CHECKING THE QUEUE FOR DATA'
#                localqueue('DATA_RECV', 'CHECK', None)
#                print 'FOUND SOME GRABBING THE DATA!'
                if connected == True and sock == True:
                    localqueue('DATA_RECV', 'GET', None)
#                    data_recv()
#        else:
#            stdout(1, '9')
#            log(3, 'DATA RECV: 0 BYTES!')
#            sock = False
#            connected = False
#            connect(4, 'data_recv else')
    except KeyboardInterrupt:
        signals(2, 'DATA_RECV', 'SIGINT')
    except:
        sys.exit(255)
    try:
        if connected == True and sock == True:
            log(4, 'DATA RECV CALLED AGAIN UNDER TRY CONNECTED')
            data_recv()
    except KeyboardInterrupt:
        signals(2, 'DATA_RECV', 'SIGINT')
    except:
        print 'OH SHIT WE FUCKED UP! (Line 284)'
        sys.exit(255)

def data_send(asciidata):
    global packet_send
    global init_packet_send
    global s

    packet_send += 1
#    log(4, 'SEND PACKET #{}'.format(packet_send))
    debug(2, 'DATA_SEND', 'CALLED')
    debug(3, 'DATA_SEND', 'CALLED WITH {}'.format(asciidata))
    hexdata = (binascii.hexlify(asciidata))
    try:
        debug(4, 'DATA_SEND', '{} BYTE(S)'.format(len(asciidata)))
        debug(4, 'DATA_SEND', hexdata)
        s.send(asciidata)
    except KeyboardInterrupt:
        signals(2, 'DATA_SEND', 'SIGINT')
        raise
    except:
        signals(4, 'DATA_SEND', 'FAILED')
        raise

def localqueue(gotfrom, action, que):
#    if hasattr(os, 'getppid'):  # only available on Unix
#        print 'queue parent process:', os.getppid()
#    print 'queue process id:', os.getpid()
    ## queuenum = sequence number
    global q
    global queuenum
    debug(1, 'LOCALQUEUE', 'CALLED')
    debug(1, 'LOCALQUEUE', 'CALLED WITH {}, {}, {}'.format(gotfrom, action, que))
    queuenum += int(1)
    if action == 'PUT':
        q.put([queuenum, gotfrom, que])
    elif action == 'CHECK':
        print 'queue check placeholder'
    elif action == 'GET':
        que = None
        que = q.get()
        num, who, msg = que
        #print 'QUEUE GOT SEQ {} WHO {} MSG {}'.format(num, who, msg)
        comms(2, msg)
    else:
        p = None
        q = Queue()
        print 'Q INIT: {}'.format(q)

def comms(sig, msg):
    debug(1, 'COMMS', 'CALLED')
    debug(1, 'COMMS', 'CALLED WITH {}'.format(sig))
    sig = int(sig)
    if sig == int(1):
        try:
            builds = ['ARM', 'MIPS', 'MIPSEL', 'X86', 'GAYFGT']
            BUILD = 'BUILD ' + (random.choice(builds)) + NEW
            dumphex(BUILD)
            data_send(BUILD)
            #log(4, '{}'.format(BUILD)
        except KeyboardInterrupt:
            signals(2, 'COMMS 1', 'SIGINT')
        except:
            signals(4, 'COMMS 1', 'FAILED')
            raise
    if sig == int(2) and msg != None:
        try:
            if msg == 'PING':
                heartbeat('SERVER', 'PING')
            elif msg == 'PONG':
                heartbeat('SERVER', 'PONG')
            elif msg[:1] == '!':
                servercommand(msg)
            else:
                dumphex(msg)
                hexdata = (binascii.hexlify(msg))
                debug(4, 'COMMS', 'LENGTH {}'.format(len(hexdata)))
                debug(4, 'COMMS', hexdata)
                log(4, '<server>: ' + msg)
#                f.write(response.encode('hex'))
        except KeyboardInterrupt:
            signals(2, 'COMMS 2', 'SIGINT')
            raise
        except:
            signals(4, 'COMMS 2', 'FAILED')
            raise

def genfakereport():
#    if hasattr(os, 'getppid'):  # only available on Unix
#        print 'report parent process:', os.getppid() ## I AM A CHILD OF PROCS
#    print 'report process id:', os.getpid() ## HERE IS MY PID
    global connected
    global sock
    debug(2, 'GENFAKEREPORT', 'CALLED')
    debug(2, 'GENFAKEREPORT', 'CONNECTED {} SOCKET {}'.format(connected, sock))
    if connected == True and sock == True:
        try:
            ip = None
            login = None
            ip = genrandip(ip)
            login = genrandlogin(login)
            report = 'REPORT {}:{}'.format(ip, login) + NEW
            data_send(report)
            ransleep = ['5', '8', '13', '17']
            randomsleep = random.choice(ransleep)
            randomsleep = int(randomsleep)
            time.sleep(randomsleep)
        except KeyboardInterrupt:
            signals(2, 'GENFAKEREPORT', 'SIGINT')
            raise
        except:
            signals(4, 'GENFAKEREPORT', 'FAILED')
            raise
        genfakereport()
    debug(1, 'GENFAKEREPORT', 'FATAL')

def servercommand(command):
    debug(2, 'SERVERCOMMAND', 'CALLED')
    debug(3, 'SERVERCOMMAND', 'CALLED WITH {}'.format(command))
    if command[:2] == '! ':
        command = command[2:]
    elif command[:2] == '!*':
        command = command[3:]
    if command[:9] == 'LOLNOGTFO':
        log(4, '[LOLNOGTFO]')
        connect(4, 'LOLNOGTFO')
    elif command[:3] == 'DUP':
        log(4, '[DUP]')
        connect(4, 'DUP')
    elif command[:7] == 'SCANNER':
        command = command[8:]
        log(4, '[SCANNER] {}'.format(command))
    elif command[:10] == 'GETLOCALIP':
        log(4, '[GETLOCALIP]')
    elif command[:4] == 'HOLD':
        command = command[5:]
        log(4, '[HOLD] {}'.format(command))
    elif command[:4] == 'JUNK':
        command = command[5:]
        log(4, '[JUNK] {}'.format(command))
    elif command[:3] == 'TCP':
        command = command[4:]
        log(4, '[TCP] {}'.format(command))
    elif command[:3] == 'UDP':
        command = command[4:]
        log(4, '[UDP] {}'.format(command))
    elif command[:8] == 'KILLATTK':
        command = command[9:]
        log(4, '[KILLATTK] {}'.format(command))
    else:
        dumphex(command)

def heartbeat(who, type):
    log(4, '[{}] {}'.format(who, type))
    debug(2, 'HEARTBEAT', 'CONNECTED {} SOCKET {}'.format(connected, sock))
    PING = ('\x50\x49\x4e\x47')
    PONG = ('\x50\x4f\x4e\x47')
    NEW = ('\x0a')
    if who == 'SERVER' and connected == True and sock == True:
        if type == 'PING':
            checkin(who, 'HEARTBEAT', type, connected, sock)
        elif type == 'PONG':
            checkin(who, 'HEARTBEAT', type, connected, sock)
    elif who == 'CLIENT' and connected == True and sock == True:
        if type == 'PING':
            PING = PING + NEW
            data_send(PING)
        elif type == 'PONG':
            data_send(PONG)
            time.sleep(1)
            data_send(NEW)

def procs(sig):
#    print 'procs process id:', os.getpid() ## CHILD OF __MAIN__
    ## 1 = INIT DAEMONS
    ## 2 = CONNECTED DAEMONS
    ## 5 = CHECK PROCS
    ## 9 = DISTROY
    ## a parent pid can only test its children
    global sock
    global connected
    global pData
    global pReport
    global pCheckin
    debug(2, 'PROCS', 'CALLED FROM {}'.format(__name__))
    debug(3, 'PROCS', 'CALLED WITH SIGNAL {}'.format(sig))
    sig = int(sig)
    if sig == int(1):
        try:
            if connected == True and sock == True:
                try:
                    pData = Process(target=data_recv,)
                    pData.name = 'pData'
                    pData.start()
                    try:
                        pid3 = pData.pid()
                        log(4, 'pData Started With PID {}'.format(pid3))
                    except:
                        log(4, 'pData Started')
                        pass
                except:
                    log(4, 'pData Refused To Start')
                    raise
            else:
                log(4, 'pData Not Connected')
        except KeyboardInterrupt:
            signals(2, 'PROCS 1', 'SIGINT')
            raise
        except:
            signals(4, 'PROCS 1', 'PDATA REFUSED TO START')
            raise
    elif sig == int(2):
        try:
            if connected == True and sock == True:
                try:
                    pCheckin = Process(target=checkin, args=('CLIENT', 'PROCS', 'PING', connected, sock))
                    pCheckin.name = 'pCheckin'
                    pCheckin.start()
                    try:
                        pid4 = pCheckin.pid()
                        log(4, 'pCheckin Started With PID {}'.format(pid4))
                    except:
                        log(4, 'pCheckin Started')
                        pass
                except:
                    log(4, 'pCheckin Refused To Start')
                    raise
            else:
                log(4, 'pCheckin Not Connected')
        except KeyboardInterrupt:
            signals(2, 'PROCS 2', 'SIGINT')
            raise
        except:
            signals(4, 'PROCS 2', 'CHECKIN FAILED TO START')
            raise
        try:
            if connected == True and sock == True:
                try:
                    pReport = Process(target=genfakereport, args=())
                    pReport.name = 'pReport'
                    pReport.start()
                    try:
                        pid5 = pReport.pid()
                        log(4, 'pReport Started With PID {}'.format(pid5))
                    except:
                        log(4, 'pReport Started')
                        pass
                except:
                    log(4, 'pReport Refused To Start')
                    raise
            else:
                log(4, 'pReport Not Connected')
        except KeyboardInterrupt:
            signals(2, 'PROCS 2', 'SIGINT')
        except:
            signals(4, 'PROCS 2', 'PREPRT FAILED TO START')
            raise
    elif sig == int(5):
        connstatus = 'CONNECTED {} SOCKET {}'.format(connected, sock)
        log(4, 'PROCS CALLED FROM {} WITH SIGNAL {} AND {}'.format(__name__, sig, connstatus))
#        print (pData, pData.is_alive())
#        print (pReport, pReport.is_alive())
    elif sig == int(9):
        try:
            connstatus = 'CONNECTED {} SOCKET {}'.format(connected, sock)
            log(4, 'PROCS CALLED FROM {} WITH SIGNAL {} AND {}'.format(__name__, sig, connstatus))
            log(4, 'START KILLING PIDS')
            pData.terminate()
            pReport.terminate()
            pReport.terminate()
            log(4, 'WHICH PIDS ARE STILL ALIVE?????')
            procs(5)
        except KeyboardInterrupt:
            time.sleep(0.5)
            signals(2, 'PROCS 9', 'SIGINT')
            raise
        except:
            time.sleep(0.5)
            raise

def connsock(sig, who):
    ## 1 = CREATE
    ## 2 = CONNECT
    ## 3 = ERROR
    ## 9 = DISTROY
    global sock
    global connected
    global s
    debug(1, 'CONNSOCK', 'CALLED')
    debug(1, 'CONNSOCK', 'SIGNAL {}'.format(sig))
    debug(1, 'CONNSOCK', 'WHO {}'.format(who))
    debug(1, 'CONNSOCK', 'SOCKET {}'.format(sock))
    debug(1, 'CONNSOCK', 'CONNECTED {}'.format(connected))
    try:
        sig = int(sig)
        if sig == int(1) and connected == False and sock == False:
            debug(1, 'SOCKET', 'CREATE')
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock = True
                #debug(1, 'SOCKET', 'CREATED')
                connect(2, 'CONNSOCK')
            except KeyboardInterrupt:
                signals(2, 'CONNSOCK 1', 'SIGINT')
                raise
            except socket.error as msg:
                s = None
                stdout(1, 'Unable to connect to remote host: {}'.format(msg))
                sys.exit(0)
                print 'HELLO WORLD LINE 595'
                raise
        elif sig == int(2) and connected == False and sock == True:
            debug(1, 'SOCKET', 'CONNECT')
            try:
                stdout(1, 'Trying {}...'.format(host))
                s.connect((host, port))
                #debug(1, 'SOCKET', 'CONNECTED')
                sock = True
                connected = True
                connect(3, 'CONNSOCK')
            except KeyboardInterrupt:
                print 'HELLO WORLD LINE 608'
                signals(2, 'CONNSOCK 2', 'SIGINT')
                time.sleep(3)
                connsock(9, 'CONNSOCK')
                raise
            except socket.error as msg:
#                signals(7, 'CONNSOCK 2', msg)
                raise
#                connect(4, 'CONNSOCK')
            except:
                connsock(9, 'CONNSOCK')
                raise
        elif sig == int(9):
            debug(1, 'SOCKET', 'DESTROY')
            while sock == True:
                try:
                    sock = False
                    connected = False
                    if s != None:
                        s.close()
                        s = None
                    debug(1, 'SOCKET', 'DESTROYED')
                    debug(1, 'SOCKET', 'SLEEP FOR 3')
                    time.sleep(3)
                except KeyboardInterrupt:
                    signals(2, 'CONSOCK 9', 'SIGINT')
                    time.sleep(3)
                    connsock(9, 'CONNSOCK EXCEPTION')
                    raise
                except:
#                    connsock(9, 'CONNSOCK EXCEPTION')
                    raise
    except KeyboardInterrupt:
        signals(2, 'CONNSOCK', 'SIGINT')
    except:
        raise

def connect(sig, who):
    ## 1 = CONNECT
    ## 2 = WITH SOCKET
    ## 3 = CONNECTED
    ## 4 = RECONNECT
    global q
    global s
    global pMain
    global packet_send
    global packet_recv
    global init_packet_send
    global init_packet_recv
    global sock
    global connected
    debug(2, 'CONNECT', 'CALLED')
    debug(3, 'CONNECT', 'SIGNAL {}'.format(sig))
    debug(3, 'CONNECT', 'WHO {}'.format(who))
    debug(3, 'CONNECT', 'SOCKET {}'.format(sock))
    debug(3, 'CONNECT', 'CONNECTED {}'.format(connected))
    sig = int(sig)
    if sig == int(1) and sock == False:
        try:
            connsock(1, 'CONNECT')
        except KeyboardInterrupt:
            signals(2, 'CONNECT 1', 'SIGINT')
            raise
        except:
            raise
    elif sig == int(2) and sock == True:
        try:
            connsock(2, 'CONNECT')
        except KeyboardInterrupt:
            signals(2, 'CONNECT 2', 'SIGINT')
            raise
        except:
            raise
    elif sig == int(3) and sock == True and connected == True:
        stdout(1, 'Connected to {}.'.format(host))
        packet_recv = int(0)
        packet_send = int(0)
        init_packet_recv = int(0)
        init_packet_send = int(0)
        try:
            log(4, 'Init Starting')
            comms(1, None)
            log(4, 'Start Some Workers For Queue')
            try:
                pool = multiprocessing.Pool(processes=1)
                m = multiprocessing.Manager()
                q = m.Queue()
                workers = pool.apply_async(localqueue, ('GET', None))
            except KeyboardInterrupt:
                signals(2, 'CONNECT 3', 'SIGINT')
                raise
            except:
                print 'unable to start workers'
                p = Process(target=localqueue, args=('GET', None))
                p.name = 'comms2'
                p.start()
                raise
            log(4, 'BUILD CREATED')
            procs(1)
            log(4, 'Init Done')
        except KeyboardInterrupt:
            signals(2, 'Init', 'SIGINT')
            raise
        except:
            raise
        try:
            log(4, 'Main Starting')
            pMain = Process(target=procs, args=('2'))
            pMain.name = 'pMain'
            pMain.start()
            time.sleep(2)
            try:
                pid2 = pMain.pid()
                log(4, 'pMain Started With PID {}'.format(pid2))
            except:
                log(4, 'pMain Started')
            log(4, 'Main Done')
        except KeyboardInterrupt:
            signals(2, 'CONNECT pMain', 'SIGINT')
            raise
        except:
            signals(4, 'CONNECT pMain', None)
            raise
        time.sleep(3)
        try:
            stdin()
        except KeyboardInterrupt:
            signals(2, 'CONNECT STDIN', 'SIGINT')
            raise
        except:
            signals(4, 'CONNECT STDIN', None)
            raise
    elif sig == int(4):
        print 'HELLO WORLD LINE 743'
        #connsock(9, 'CONNECT')
        #log(4, 'CONNECTION LOST!')
        sock = False
        connected = False
        #log(4, 'RETRYING IN 1 SECONDS!')
        #try:
        #    time.sleep(1)
        #except KeyboardInterrupt:
        #    raise
        #connect(1, 'CONNECT')

def checkin(who, fro, type, connected, sock):
#    if hasattr(os, 'getppid'):  # only available on Unix
#        print 'checkin parent process:', os.getppid() ## I AM A CHILD OF PROCS
#    print 'checkin process id:', os.getpid() ## HERE IS MY PID
#    log(4, '[CHECKIN] WHO {} FROM {} TYPE {}'.format(who, fro, type))
#    log(4, 'CONNECTED {} SOCK {}'.format(connected, sock))
    try:
        if connected == True and sock == True:
            try:
                if type == 'PING' or type == int(1):
                    global heartbeatstart
                    heartbeatstart = time.time()
                    if who == 'CLIENT':
                        try:
                            heartbeat(who, type)
                            time.sleep(30)
                            checkin('CLIENT', 'CHECKIN', 'PING', connected, sock)
                        except KeyboardInterrupt:
                            raise
                        except:
                            raise
                    elif who == 'SERVER':
                        heartbeat('CLIENT', 'PONG')
                elif type == 'PONG' or type == int(2):
                    global heartbeatstop
                    if who == 'SERVER':
                        heartbeatstop = time.time()
                        #heartbeat(who, type)
                    elif who == 'CLIENT':
                        heartbeat(who, type)
            except KeyboardInterrupt:
                raise
            except:
                raise
        else:
            signals(9, 'CHECKIN', None)
    except KeyboardInterrupt:
        raise
    except:
        raise

def signals(sig, sigfrom, msg):
    ## 2 = SIGINT
    ## 4 = CRITICAL EXCEPTION
    ## 7 = EXCEPTION
    ## 9 = SIGKILL
    global sock
    global connected
    global procstatus
    #log(4, 'GOT SIGNAL {} FROM {} MSG {}'.format(sig, sigfrom, msg))
    sig = int(sig)
    if sig == int(2):
        log(6, 'FROM {}'.format(sigfrom))
        try:
            raise
        except KeyboardInterrupt:
            raise
        except:
            raise
    elif sig == int(4):
        log(4, '[EXCEPTION] FROM {}'.format(sigfrom))
        if sock == True:
            connsock(9, 'SIGNALS')
        sock = False
        connected = False
        procs(5) ## GET PROC PIDS
        procs(9) ## DISTROY CHILD PROCS
        procstatus = False
        log(4, '[SEND SIGKILL TO MAIN]')
        signals(9, sigfrom, 'CRITICAL EXCEPTION')
    elif sig == int(7):
        log(3, '[{}] {}'.format(sigfrom, msg))
    elif sig == int(9):
        log(7, 'FROM {}'.format(sigfrom))
        if sock == True:
            connsock(9, 'SIGNALS') ## Destroy Socket
        if procstatus == True:
            procs(5)
            procs(9)
        f.close()
        time.sleep(0.5)
        try:
            sys.exit(0) ## Exit Cleanly
        except KeyboardInterrupt:
            raise
        except:
            raise

if __name__ == '__main__':
    p = None
    pData = None
    pReport = None
    pCheckin = None
    pMain = None
    sock = False
    connected = False
    procstatus = False
    packet_recv = int(0)
    packet_send = int(0)
    queuenum = int(0)
    print 'MY PID #', os.getpid()
    try:
        connect(1, __name__)
    except KeyboardInterrupt:
        print 'CAUGHT SIG INT ON __MAIN__'
        raise
    except:
        raise

if __name__ != '__main__':
    print 'END SCRIPT Hi My Name Is: {}'.format(__name__)