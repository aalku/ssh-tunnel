import pexpect
import argparse

s_imports="""
import os
import signal
import datetime
import SocketServer
import socket
import threading
import Queue
import sys
import time
import subprocess
import re
"""
exec s_imports

# -tp targetPort -sh sshHost -lp listenPort [-su sshUser] [-sp sshPort] [-sw sshPassword] [--force] [--kill]

argParser = argparse.ArgumentParser()
argParser.add_argument('-tp', action='store', required=True, type = int)
argParser.add_argument('-sh', action='store', required=True)
argParser.add_argument('-lp', action='store', required=True, type = int)
argParser.add_argument('-su', action='store', required=True, default=None)
argParser.add_argument('-sp', action='store', required=False, type = int, default=22)
argParser.add_argument('-sw', action='store', required=False, default=None)
argParser.add_argument('-di', action='store', required=False, default="in")
argParser.add_argument('--force', action='store_true', required=False, default=False)
argParser.add_argument('--kill', action='store_true', required=False, default=False)
argParser.add_argument('--killall', action='store_true', required=False, default=False)
args = argParser.parse_args()

ssh_cmd = "ssh %s@%s -p %d -t -R %d:localhost:%d python"

ssh_user = args.su
ssh_host = args.sh
ssh_port = args.sp
ssh_password = args.sw

# A donde se hace la ultima conexion, el objetivo real externo a esta app
final_port = args.tp
final_host = 'localhost'

# Donde se escucha la primera conexion, donde comienza la cadena de conexiones
final_listen_port = args.lp

force = args.force
kill = args.kill
killall = args.killall

pyprompt = ">>>"
pwprompt = "password:"

serverEventQueue = Queue.Queue()

def listProcess():
  hz = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
  btime = None
  for line in open('/proc/stat').readlines():
    x = line.split( )
    if (x[0] == 'btime'):
      btime = x[1]
      break
  if (btime == None):
    raise Exception('Can\'t get boot time')
  procs = []
  pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
  for pid in pids:
    try:
      cmd = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read().split("\x00")[:-1]
      exe = os.readlink(os.path.join('/proc', pid, 'exe'))
      cwd = os.readlink(os.path.join('/proc', pid, 'cwd'))
    except IOError: # proc has already terminated
      continue
    except OSError: # proc has already terminated
      continue
    cmd2 = []
    for x in cmd:
      cmd2.append("\"" + x.replace("\"", "\\\"") + "\"")
    qcmd = " ".join(cmd2)

    with open("/proc/%d/stat" % (int(pid),)) as fp:
      x = fp.read().split(' ')[21]
      starttime = float(btime) + (float(x) / hz )
    procs.append({ 'pid':int(pid), 'cmd':cmd, 'qcmd':qcmd, 'cwd':cwd, 'starttimes':starttime, 'starttimestr':str(datetime.datetime.fromtimestamp(starttime)), 'exe':exe })
  return procs

def killProc(pid):
  try:
    os.kill(pid, signal.SIGTERM)
  except Exception as e:
    s = str(e)
    log("  Error: " + s)
    if ('No such process' in s):
      pass
    else:
      raise e

  
def ensureUnique(force = False, kill = False, killall = False):
  def relArgs(cmd, cwd=os.getcwd()):
    _di = "in";
    _sh = None;
    _lp = None;
    _script = None;
    if ("python" in cmd[0]):
      _script = cmd[1]
    if (_script != None and not _script.startswith("/")):
      _script = os.path.normpath(os.path.join(cwd, _script))
    for i in range(1,len(cmd)):
      if cmd[i-1] == '-sh':
        _sh = cmd[i]
      elif cmd[i-1] == '-di':
        _di = cmd[i]
      elif cmd[i-1] == '-lp':
        _lp = cmd[i]
    if (_di == "in"):
      return {"script":_script, "di":_di, "sh":_sh, "lp":_lp}
    else:
      return {"script":_script, "di":_di, "sh":"localhost", "lp":_lp}

  procs = listProcess()
  self = None
  for p in procs:
    if (p['pid'] == os.getpid()):
      self = p
      #debug("me       " + repr(self))
  _args = relArgs(self['cmd'])
  debug("margs = %s" % _args)
  for p in procs:
    #debug("p        " + repr(p))
    if (p['exe'] != self['exe']):
      continue
    if (p['pid'] == os.getpid()):
      continue
    _pargs = relArgs(p['cmd'], p['cwd'])
    debug("pargs = %s" % _pargs)
    if (_pargs['script'] != _args['script']):
      continue
    if (killall):
      log("killing sibiling process: %d" % p['pid'])
      killProc(p['pid'])
      continue
    if (_pargs==_args):
      debug("sibiling " + repr(p))
      if (force or kill):
        log("killing sibiling process: %d" % p['pid'])
        killProc(p['pid'])
        continue
      x = self['starttimes'] - p['starttimes']
      if (x == 0):
        x = self['pid'] - p['pid']
      if (x > 0):
        log("This is redundant process %d, exit" % os.getpid())
        exit(1)
          
def log(s):
  print "%s %d LOG: %s" %(str(datetime.datetime.now()), os.getpid(), s)
  sys.stdout.flush()

def debug(s):
  print "%s %d DEBUG: %s" %(str(datetime.datetime.now()), os.getpid(), s)
  sys.stdout.flush()
  
def debugServer(s):
  print "%s %d DEBUG SERVER: %s" %(str(datetime.datetime.now()), os.getpid(), s)
  sys.stdout.flush()

def debugServerXFer(s):
  #print "%s %d DEBUG SERVER: %s" %(str(datetime.datetime.now()), os.getpid(), s)
  sys.stdout.flush()

  
s_debugServer="""
def debugServer(s):
#  with open('log', 'a') as f:
#   f.write( str(s) + '''
#''')
  pass
def debugServerXFer(s):
#  with open('log', 'a') as f:
#   f.write( str(s) + '''
#''')
  pass
"""
s_startServer="""
class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
  daemon_threads = True
  allow_reuse_address = True

def startServer(target, serverPort):
  class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
      def socketCopy(src, dst, dir):
        dir = threading.current_thread().name
        try:
          while True:
            data = src.recv(1024*32)
            debugServerXFer("%s: %s" % (dir, repr(data)))
            if not data:
              debugServerXFer("%s: %s" % (dir, "EOF, closing"))
              break
            dst.sendall(data)
        except Exception as e:
          debugServer("%s: %s" % (dir, "Error: " + repr(e)))
        finally:
          dst.shutdown(socket.SHUT_WR)
          dst.close()
      c1 = self.request
      c1.settimeout(240)
      try:
        c2 = socket.socket()
        debugServer("Connecting to " + repr(target))
        c2.connect(target)
        c2.settimeout(240)
        try:
          debugServer("  Connected OK")
          t21 = threading.Thread(group=None, target=socketCopy, name="cp-"+repr(c2.getpeername())+">>"+repr(c1.getpeername()), args=(c2, c1, '>>'))
          t12 = threading.Thread(group=None, target=socketCopy, name="cp-"+repr(c2.getpeername())+"<<"+repr(c1.getpeername()), args=(c1, c2, '<<'))
          t12.daemon = True
          t12.start()
          t21.daemon = True
          t21.start()
          t12.join()
          debugServer("Thread " + t12.name + " finnished")
          t21.join()
          debugServer("Thread " + t21.name + " finnished")
        finally:
          c2.close()
      finally:
        c1.close()
  server = ThreadedTCPServer(("0.0.0.0", serverPort), ThreadedTCPRequestHandler)
  ip, port = server.server_address

  server_thread = threading.Thread(target=server.serve_forever)
  server_thread.daemon = True
  server_thread.start()
  return server
"""
exec s_startServer

def connectSshPy(host, ssh_port, user, ssh_password, tunnelPortL, tunnelPortR):
  cmd = ssh_cmd % (user, host, ssh_port, tunnelPortL, tunnelPortR)
  debug( " -- running cmd " + cmd)
  ssh = pexpect.spawn (cmd)
  ssh.logfile=sys.stderr
  i=ssh.expect([pyprompt, pwprompt, "Name or service not known", pexpect.TIMEOUT])
  ssh.logfile=None
  if (i == 1 and ssh_password != None):
    ssh.send(ssh_password + "\n")
    ssh.expect(pyprompt)
  elif (i >= 2):
    raise Exception(ssh.before + ssh.match)
  return ssh

def runRemotePy(ssh, script):
  debug("@@@ " + script.strip()[:40] + "...")
  sep = "'--8<--- "+repr(datetime.datetime.now())+"'"
  ssh.send('script="""\n')
  ssh.send(script.replace('"""', '""" + ' + '\'"""\'' +  ' + """') + "\n")
  ssh.send('""" # ' + sep + '\n')
  ssh.expect_exact(sep)
  ssh.expect_exact(pyprompt)
  ssh.send('exec script\n')
  ssh.expect_exact('exec script')
  ssh.expect_exact(pyprompt)
  debug ("Executed remote script")
  return ssh.before.strip()

s_wdogConfig = """
wdogTimeoutInterval = 120
wdogTimeoutCheckInterval = wdogTimeoutInterval / 2
wdogTimeoutResetInterval = wdogTimeoutInterval / 2
"""
exec s_wdogConfig

s_wdogRemote = """
wdogTimeout = None
def wdogReset():
  wdogTimeout = datetime.datetime.now() + datetime.timedelta(seconds=wdogTimeoutInterval)
def wdogTimeoutCheck():
  if (datetime.datetime.now() > wdogTimeout):
    debugServer("WATCHDOG TIMEOUT")
    exit(1)
wdogTimer = threading.Timer(wdogTimeoutCheckInterval, wdogTimeoutCheck)
wdogTimer.start()
wdogReset()
"""

s_killPortThief="""
def killPortThief(port):
  #Proto Recv-Q Send-Q Local Address               Foreign Address             State       User       Inode      PID/Program name 
  #tcp        0      0 0.0.0.0:3422                0.0.0.0:*                   LISTEN      22622/python  
  uid = os.getuid()
  repeat = True
  while repeat:
    repeat = False
    out = subprocess.Popen(["netstat", "-l", "-n", "-t", "-e", "-p"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0].splitlines()
    while True:
      h = out.pop(0)
      if h.find("Local Address") >= 0:
        break
    #debugServer(h)
    hUser = re.search("User\\s*", h)
    hProc = re.search("PID\/Program name\\s*", h)
    hLAddr = re.search("Local Address\\s*", h)
    for l in out:
      #debugServer(l)
      _uid = int(l[hUser.start():hUser.end()].strip())
      proc = l[hProc.start():hProc.end()].strip()
      laddr = l[hLAddr.start():hLAddr.end()].strip()
      if (laddr.endswith(":%d" % port)):
        debugServer("user %s, process %s, laddr %s " % (uid, proc, laddr))
        if (uid == _uid):
          debugServer("local port %d is in use by process %s, killing it..." % (port, proc))
          os.kill(int(proc.split('/')[0]), signal.SIGTERM)
          time.sleep(1)
          repeat = True
        else:
          debugServer("local port %d is in use by process %s. It is owned by another user, aborting." % (port, proc))
          exit(1)
"""

def sigterm_handler(_signo, _stack_frame):
  exit(2)

try:
      
    signal.signal(signal.SIGTERM, sigterm_handler)

    ensureUnique(force, kill, killall)

    if (kill or killall):
      exit(0)
      
    log("Starting up, pid=%d" % (os.getpid(),))

    while True:
      try:
        server = startServer((final_host, final_port), 0)
        log( "- Server listening on %s:%d" % server.server_address)
        try:

          log( "- Connecting to remote host")
          ssh = connectSshPy(ssh_host, ssh_port, ssh_user, ssh_password, server.server_address[1], server.server_address[1])
          log( "- Connected, ssh PID = %d" % ssh.pid)
          try:

            runRemotePy(ssh, s_wdogConfig)
            runRemotePy(ssh, s_wdogRemote)

            #ssh.logfile=sys.stderr

            # Transmit and run code on remote host
            runRemotePy(ssh, s_imports)
            runRemotePy(ssh, s_debugServer)
            runRemotePy(ssh, s_startServer)

            runRemotePy(ssh, "wdogReset()")

            # check port free on remote host, kill process that uses it
            runRemotePy(ssh, s_killPortThief)
            ssh.logfile=sys.stderr
            runRemotePy(ssh, "killPortThief(%d)" % final_listen_port)
            ssh.logfile=None
            
            runRemotePy(ssh, "wdogReset()")
            
            log( runRemotePy(ssh, "startServer(('localhost', %d), %d)" % (server.server_address[1],final_listen_port) ))

            # Expect later output and terminate
            #ssh.interact()
            ssh.logfile=sys.stderr
            while True:
              runRemotePy(ssh, "wdogReset()")
              time.sleep(wdogTimeoutResetInterval)
            #ssh.expect (pexpect.EOF, timeout=60*60*24)
          finally:
            try:
              ssh.close(force=True)
            except:
              pass
        finally:
          try:
            server.close()
          except:
            pass
      except KeyboardInterrupt:
        log( "aborted process %d" % os.getpid())
        break
      except Exception as e:
        log(repr(e))
      time.sleep(10)
finally:
  pass
