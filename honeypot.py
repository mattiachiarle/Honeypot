import getopt
import socket
import sys
import threading
import _thread as thread
import paramiko


# generate keys with 'ssh-keygen -t rsa -f server.key'
key = paramiko.RSAKey(filename='server.key')
port = 2222

opts, args = getopt.getopt(sys.argv[1:], "p:")  # We get the CLI arguments
for opt, arg in opts:
    if opt == "-p":
        port = int(arg)  # We store the port

attempts = {}  # Dictionary to store the number of attempts for each username
file_system = {}  # Dictionary that will store the fake file system
logged_user = ""  # Global variable to store the username of the logged user

user_file = open("usernames.txt", "r")  # File containing all the allowed usernames


for user in user_file:
    name = user.strip()
    attempts[name] = 0  # Dictionary initialization

user_file.close()


# Here, we redefine all the functions that we'll use in our paramiko implementation
class SSHServerHandler(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        global logged_user
        print("New login: " + username + ":" + password)  # Debugging print
        if username in attempts.keys():  # The user is among the ones in the file
            attempts[username] += 1
            print(username + " performed {} attempts".format(attempts[username]))  # Debugging print
            if attempts[username] == 5:  # We grant access
                logged_user = username  # We overwrite the global variable
                return paramiko.AUTH_SUCCESSFUL  # We return a successful authentication

        return paramiko.AUTH_FAILED  # Either the user isn't in the file or the user performed less than 5 attempts

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED  # We allow the opening of the channel

    def check_channel_shell_request(self, channel):
        self.event.set()  # We record the user's shell request
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True  # Used to enable the PTY allocation


def handle_connection(client):
    global file_system

    transport = paramiko.Transport(client)  # We create an SSH session, but we don't start it yet

    transport.add_server_key(key)  # We add the key

    server_handler = SSHServerHandler()  # We create a paramiko server

    transport.start_server(server=server_handler)  # We negotiate a new SSH session, and we act as the server

    channel = transport.accept(100)  # We accept the connection

    if channel is None:
        print('Closing connection.')
        return

    server_handler.event.wait(10)  # We wait for the client's shell request

    if not server_handler.event.is_set():
        print('Client never asked for a shell')
        raise Exception("No shell request")

    file_system = {}  # We clear the file system

    dir_msg = logged_user + "@honeypot:/$ "  # We create the string that will always be printed at the beginning

    channel.settimeout(60.0)

    while True:
        try:
            channel.send(dir_msg)  # We send the string

            try:
                cmd = ""
                while not cmd.endswith("\r"):
                    # Receive data from the client
                    data = channel.recv(1024)
                    channel.send(data)
                    cmd += data.decode('utf-8')

                # Check if data is received
                if not data:
                    break  # Break the loop if no data is received

                # Process the received data
                run_cmd(cmd.rstrip(), channel)
                channel.send("\r\n")

            except paramiko.SSHException:
                break  # Break the loop on SSH exception (e.g., client disconnect)

        except TimeoutError:
            break

    reset_attempts(logged_user)
    channel.close()


def reset_attempts(user):
    global attempts
    attempts[user] = 0


def run_cmd(cmd, channel):
    global file_system

    if cmd == "ls":
        if len(file_system.keys()) > 0:
            channel.send("\r\n")
        msg = ""
        for key in file_system.keys():
            msg += key + " "  # We concatenate all the files created up to now
        channel.send(msg)
    elif cmd.startswith("echo"):
        parts = cmd.split(">")
        if not parts[1].strip().endswith(".txt"):  # We check the filename
            msg = "\r\nUnknown file extension"  # Wrong file extension
            channel.send(msg)
            return
        content = parts[0].split("\'\'")[1]  # We get the content
        file_system[parts[1].strip()] = content  # We associate the content to the filename
    elif cmd.startswith("cat"):
        file = cmd.split(" ")[1].strip()  # We retrieve the filename
        if not file.endswith(".txt"):  # Wrong extension
            msg = "\r\nUnknown file extension"
            channel.send(msg)
            return
        if file not in file_system.keys():  # The file doesn't exist
            msg = "\r\nFile " + file + " not found"
            channel.send(msg)
            return
        msg = "\r\n" + file_system[file]  # We get the file content
        channel.send(msg)
    elif cmd.startswith("cp"):
        files = cmd.split(" ")
        src = files[1].strip()  # Filename of source
        dst = files[2].strip()  # Filename of destination
        if (not src.endswith(".txt")) or (not dst.endswith(".txt")):  # Extension check
            msg = "\r\nUnknown file extension"
            channel.send(msg)
            return
        if src not in file_system.keys():  # We check if source exists in the file system
            msg = "\r\nFile " + src + " not found"
            channel.send(msg)
            return
        file_system[dst] = file_system[src]  # We copy the content
    else:
        msg = "\r\nCommand not found"  # Wrong command
        channel.send(msg)


try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', port))  # We create a socket that listens on the provided port
    server_socket.listen(100)
    print('SSH Honeypot Server Started.')

    while True:
        try:
            client_socket, client_addr = server_socket.accept()  # We accept clients' connections
            print('Connection Received From:', client_addr)
            thread.start_new_thread(handle_connection, (client_socket,))  # We handle the connection
        except Exception as e:
            print("ERROR: Client handling")
            print(e)

except Exception as e:
    print("ERROR: Failed to create socket")
    print(e)
    sys.exit(1)
