import struct
import rwlock
import socket
import threading
import time
import frida


LOCAL_IP = "0.0.0.0" # listening ip
LOCAL_PORT = 8081 # listening port
TIMEOUT = 500
STATISTICAL_INTERVAL = 10 # s
JS_PATH = r'.\_agent.js'
TARGET = 21748


def threaded(fn):
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
        thread.start()
        return thread
    return wrapper

stop_forward = False
thread_num = 0
proxy_info_stru = struct.Struct("<HHI")
clientPort_serverAddr_map = {}
grwlock = rwlock.RWLock()
listen_lock = threading.Lock()
thread_num_lock = threading.Lock()

def int2IP(v: int) -> str:
    return socket.inet_ntoa(struct.pack('<L', v))


def Addcp2sMap(ClientPort: int, ServerIP: str, ServerPort: int):
     with grwlock.w_locked():
          clientPort_serverAddr_map[ClientPort] = (ServerIP, ServerPort)


def Delcp2sMap(ClientPort: int):
    with grwlock.w_locked():
        del clientPort_serverAddr_map[ClientPort]


def Findcp2sMap(ClientPort: int) -> tuple[str, int]:
    with grwlock.r_locked():
        return clientPort_serverAddr_map.get(ClientPort)


def GetCurrentTime(): # millisecond
    return int(round(time.time() * 1000))


@threaded
def tcp_forward_thread(conn_receiver, conn_sender):
    try:
        conn_receiver_info = conn_receiver.getpeername()
        conn_sender_info = conn_sender.getpeername()
    except Exception as e:
        conn_receiver.close()
        conn_sender.close()
        print(f"[x] get forward info err: {e}")
        return

    total = 0
    ct = time.time()
    timer = time.time()
    data = bytes()

    try:
        while True:
            if not stop_forward:
                data = conn_receiver.recv(2048)
                conn_sender.sendall(data)

                total += len(data)
                interval = time.time() - timer
                if interval > STATISTICAL_INTERVAL:
                    timer = time.time()
                    print(f"{conn_receiver_info[0]}:{conn_receiver_info[1]} >> {conn_sender_info[0]}:{conn_sender_info[1]} statistical data:\n\t{round(total/1024, 2)} KB, {round(interval, 2)} s, avg: {round((total/1024)/interval, 2)} KB/s")
            else:
                raise Exception("{conn_receiver_info[0]}:{conn_receiver_info[1]} XX>XX {conn_sender_info[0]}:{conn_sender_info[1]}")

    except Exception as e:
        print(f"[x] forward err: {e}")


    with thread_num_lock:
        global thread_num
        thread_num -= 1

    interval = time.time() - ct
    if interval != 0:
        print(f"FINAL {conn_receiver_info[0]}:{conn_receiver_info[1]} >> {conn_sender_info[0]}:{conn_sender_info[1]} statistical data:\n\t{round(total/1024, 2)} KB, {round(interval, 2)} s, avg: {round((total/1024)/interval, 2)} KB/s")

    conn_receiver.close()
    conn_sender.close()
    return


@threaded
def connect_to_target_server_thread(local_conn, local_addr):
    server_IP, server_port = None, None
    ct = GetCurrentTime()
    while True:
        ret = Findcp2sMap(local_addr[1])
        if ret != None:
            server_IP, server_port = ret
            break
        if GetCurrentTime() - ct > TIMEOUT:
            print(f"[x] mapping err: map client {local_addr[0]}:{local_addr[1]} to server addr overtime")
            local_conn.close()
            return

    remote_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        remote_conn.connect((server_IP, server_port))
    except Exception:
        print(f"[x] connection err: client {local_addr[0]}:{local_addr[1]} can not connect to target server {server_IP}:{server_port}")
        local_conn.close()
        return

    print(f"[+] link: {local_addr[0]}:{local_addr[1]} <<-->> {server_IP}:{server_port}")
    with thread_num_lock:
        global thread_num
        thread_num += 2
    tcp_forward_thread(local_conn, remote_conn)
    tcp_forward_thread(remote_conn, local_conn)
    # threading.Thread(target = tcp_mapping_worker, args = (local_conn, remote_conn)).start()
    # threading.Thread(target = tcp_mapping_worker, args = (remote_conn, local_conn)).start()
    return


@threaded
def listen_thread():
    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server.bind((LOCAL_IP, LOCAL_PORT))
    local_server.listen()
    print(f"[*] listen on {LOCAL_IP}:{LOCAL_PORT}")

    listen_lock.release()

    try:
        while True:
            if not stop_forward:
                (local_conn, local_addr) = local_server.accept()
                connect_to_target_server_thread(local_conn, local_addr)
                #threading.Thread(target = connect_to_target_server_thread, args = (local_conn, local_addr)).start()
            else:
                time.sleep(0.2)
    except Exception as e:
        local_server.close()
        print(f"[xxx] accept err: {e}")
        return


def on_message(message, data):
    if message['type'] == 'send':
        clientPort, targetPort, targetIP = proxy_info_stru.unpack_from(data, 0)
        Addcp2sMap(clientPort, int2IP(targetIP), targetPort)
    elif message['type'] == 'error':
        print(message['stack'])


def instrument(target: str | int):
    listen_lock.acquire()
    listen_thread()
    listen_lock.acquire()

    spawn_mod = False
    pid = 0
    session = None

    if isinstance(target, str) and '\\' in target:
        spawn_mod = True
        pid = frida.spawn(target)
        session = frida.attach(pid)
    else:
        session = frida.attach(target)

    js_script = None
    with open(JS_PATH, 'rb') as f:
        js_script = f.read().decode(encoding='utf-8')
    script = session.create_script(js_script)
    script.on('message', on_message)

    script.load()

    if spawn_mod:
        frida.resume(pid)

    global stop_forward
    while True:
        cmd = input() # pause
        match cmd:
            case '':
                break
            case 'q':
                break
            case 'c':
                print(f"connection num: {thread_num//2}")
            case "stop":
                stop_forward = True
            case 'start':
                stop_forward = False
            case _:
                print("unknown instruction")

    script.unload()
    session.detach()

    if spawn_mod:
        frida.kill(pid)


if __name__ == "__main__":
    instrument(TARGET)
