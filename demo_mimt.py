import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback
import time
import paramiko
from paramiko.py3compat import b, u, decodebytes

paramiko.util.log_to_file("demo_server.log")
TARGET = '192.168.1.1'
Host_key = paramiko.RSAKey(filename="rsa")
DoGSSAPIKeyExchange = True



def windows_shell(chanUser,chanServer):
    import threading
    print("start shell")
    def writeall(sockUser, sockServer):
        s = ''
        while True:
            try:
                data = sockServer.recv(256)
                s += data
            except socket.timeout:
                continue
            if not data:
                sys.stdout.write("\r\n*** EOF ***\r\n\r\n")
                sys.stdout.flush()
                sockUser.close() # disallowed recieve and send
                break
            # if '\n' in s:
            #     print('<'+s)
            #     s = ''
            sockUser.sendall(data)

    writer = threading.Thread(target=writeall, args=(chanUser, chanServer))
    writer.start()
    string = ''
    while True:
        try:
            d = chanUser.recv(1)
            string += d
        except socket.timeout:
            continue
        except EOFError:
            break

        if not d:
            break

        # if '\n' in string:
        #     print('>'+string)
        #     string = ''
        try:
            chanServer.send(d)
        except:
            break
    print("shell exit!")

class Client(object):
    def __init__(self):
        global TARGET
        self.hostname = TARGET
        client = paramiko.SSHClient()
        self.client = client
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        self.pty = []

    def agent_auth(self, username, password = '', key = None, port=22):
        if key:
            print("We can't support key authenticate.")
            return False

        else:
            try:
                print(username,password,port)
                self.client.connect(
                    self.hostname, 
                    port, 
                    username, 
                    password
                    )
                return True

            except Exception as e:
                print("auth fail", e)
                return False

    def request_pty(self, term,
        width, height, pixelwidth, pixelheight,
        modes
        ):
        self.pty = [term, width, height,
            pixelwidth, pixelheight, modes]

    def invoke_shell(self):
        if len(self.pty):
            return self.client.invoke_shell(
                self.pty[0],
                self.pty[1],
                self.pty[2],
                self.pty[3],
                self.pty[4]
                )
        return self.client.invoke_shell()

    def exec_command(self, command):
        transport = self.client.get_transport()
        chan = transport.open_session()
        chan.exec_command(command)
        return chan

    def open_sftp(self):
        return self.client.open_sftp()

    def close(self):
        if self.client:
            self.client.close()


class Server(paramiko.ServerInterface):
    def __init__(self, clientSSH):
        self.event = threading.Event()
        self.clientSSH = clientSSH
        self.clientSSH_chan = None
        self.server_chan = None
        self.sftpClient = None

    def set_chan(self, channel):
        self.server_chan = channel

    def run(self):
        self.server_chan.settimeout(2)
        if self.sftpClient:
            self.clientSSH_chan = self.sftpClient.get_channel()

        while not self.clientSSH_chan:
            print("no client chan")
            time.sleep(1)
        self.clientSSH_chan.settimeout(2)
        windows_shell(
            self.server_chan, 
            self.clientSSH_chan
            )

    def close(self):
        if self.sftpClient:
            self.sftpClient.close()

        elif self.clientSSH_chan:
            self.clientSSH_chan.close()

        self.clientSSH.close()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, user, pswd):
        print(user,pswd)
        try:
            ret = self.clientSSH.agent_auth(user,pswd)
            if ret:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED

        except Exception as e:
            print(e)
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return True

    def get_allowed_auths(self, username):
        return "gssapi-keyex,gssapi-with-mic,password,publickey"

    def check_channel_shell_request(self, channel):
        print("invoke_shell")
        clientSSH_chan = self.clientSSH.invoke_shell()
        print("invoke done", clientSSH_chan)
        if clientSSH_chan:
            self.clientSSH_chan = clientSSH_chan
            self.event.set()
            return True
        else:
            return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        print("exec", command)
        self.clientSSH_chan = self.clientSSH.exec_command(command)
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        print("request pty")
        self.clientSSH.request_pty(
            term,
            width,
            height,
            pixelwidth,
            pixelheight,
            modes)
        return True

    def check_channel_subsystem_request(
        self, channel, name
    ):
        print("request subsystem", name)
        if name == 'sftp':
            try:
                self.sftpClient = self.clientSSH.open_sftp()
            except Exception as e:
                print(e)
            self.event.set()
            return True
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

class Connection(threading.Thread):
    def __init__(self,client):
        self.client = client
        super(Connection, self).__init__()

    def run(self):
        global Host_key, DoGSSAPIKeyExchange

        t = paramiko.Transport(self.client, gss_kex=DoGSSAPIKeyExchange)
        t.set_gss_host(socket.getfqdn(""))
        try:
            t.load_server_moduli()
        except:
            print("(Failed to load moduli -- gex will be unsupported.)")
            raise
        t.add_server_key(Host_key)

        clientSSH = Client()
        server = Server(clientSSH)
        
        try:
            t.start_server(server=server)
        except paramiko.SSHException:
            print("*** SSH negotiation failed.")
            sys.exit(1)

        # wait for auth
        chan = t.accept(20)
        if chan is None:
            print("*** No channel.")
            sys.exit(1)
        print("Authenticated!")

        server.event.wait(10)
        if not server.event.is_set():
            print("*** Client never asked for a shell.")
            sys.exit(1)
        server.set_chan(chan)
        server.run()
        # chan.close() this channel closed by windows_shell function.
        server.close()



if __name__ == '__main__':
    print("Read key: " + u(hexlify(Host_key.get_fingerprint())))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 2200))
        sock.listen(100)
        sock.settimeout(2)
    except Exception as e:
        print("*** Bind failed: " + str(e))
        traceback.print_exc()
        sys.exit(1)

    print("Listening for connection ...")
    while 1:
        try:
            try:
                sockclient, addr = sock.accept()
            except socket.timeout:
                continue
            conn = Connection(sockclient)
            conn.start()

        except socket.timeout:
            print("*** Listen/accept failed: " + str(e))
            traceback.print_exc()
            sys.exit(1)

