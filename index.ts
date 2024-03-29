export {}

// 其他思路 hook 域名解析函数(GetAddrInfo, gethostbyname及变种) 重定向IP

type BigEndian = number;
type LittleEndian = number;

if (Module.findBaseAddress('ws2_32.dll') == null) {
    throw new Error(`process ${Process.id} without ws2_32.dll`);
}


const MY_PROXY_IP: BigEndian = inet_addr('127.0.0.1');
const MY_PROXY_PORT: BigEndian = swap16_LittleEndian_BigEndian(8081);
const FORCE_PROXY_MODE = true;
const VERBOSE = false;
// const excludeIP = [inet_addr('127.0.0.1'), inet_addr('0.0.0.0')]; // 要排除的内网IP


const wincalling_convention = Process.pointerSize == 4 ? 'stdcall' : 'win64';

function inet_addr(ip_str: string): BigEndian {
    const octets = ip_str.split('.').map((val) => { return parseInt(val, 10) });
    if (octets.length !== 4) {
        return 0; // 非法IP地址
    }

    const binaryIp = octets.reduce((ip, octet, index): number => {
        if (isNaN(octet) || octet < 0 || octet > 255) {
            return 0; // 非法IP地址
        }
        return (octet * (index == 0 ? 1 : 256 ** index)) + ip;
    }, 0);

    return binaryIp;
}

function uint32ToIp(int32: BigEndian): string {
    const u64 = uint64(int32);
    return u64.and(0xff).toNumber() + '.' + u64.shr(8).and(0xff).toNumber() + '.' + u64.shr(16).and(0xff).toNumber() + '.' + u64.shr(24).and(0xff).toNumber();
}

function swap16_LittleEndian_BigEndian(uint16: number): number {
    // 16位小端和大端互转
    return ((uint16 >> 8) & 0xff) | ((uint16 & 0xff) << 8);
}

function swap32_LittleEndian_BigEndian(num: number): number {
    // 32位小端和大端互转
    const u64 = uint64(num);
    let r = uint64(0);
    r = u64.and(0xff).shl(24);
    r = r.or(u64.shr(8).and(0xff).shl(16));
    r = r.or(u64.shr(16).and(0xff).shl(8));
    r = r.or(u64.shr(24).and(0xff));
    return r.toNumber();
}


/*
    判断是否内网IP
    内网IP列表:
    127.0.0.1 到 127.255.255.254
    10.0.0.0 到 10.255.255.255
    172.16.0.0 到 172.31.255.255
    192.168.0.0 到 192.168.255.255
*/
const IntranetIPRange1 = [swap32_LittleEndian_BigEndian(inet_addr('127.0.0.1')), swap32_LittleEndian_BigEndian(inet_addr('127.255.255.254'))];
const IntranetIPRange2 = [swap32_LittleEndian_BigEndian(inet_addr('10.0.0.0')), swap32_LittleEndian_BigEndian(inet_addr('10.255.255.255'))];
const IntranetIPRange3 = [swap32_LittleEndian_BigEndian(inet_addr('172.16.0.0')), swap32_LittleEndian_BigEndian(inet_addr('172.31.255.255'))];
const IntranetIPRange4 = [swap32_LittleEndian_BigEndian(inet_addr('192.168.0.0')), swap32_LittleEndian_BigEndian(inet_addr('192.168.255.255'))];
function IsIntranetIP(ip: BigEndian): boolean {
    const n = swap32_LittleEndian_BigEndian(ip);

    if (n == 0) { // 0.0.0.0
        return true;
    }
    if (IntranetIPRange4[0] <= n && n <= IntranetIPRange4[1]) {
        return true;
    }
    if (IntranetIPRange3[0] <= n && n <= IntranetIPRange3[1]) {
        return true;
    }
    if (IntranetIPRange2[0] <= n && n <= IntranetIPRange2[1]) {
        return true;
    }
    if (IntranetIPRange1[0] <= n && n <= IntranetIPRange1[1]) {
        return true;
    }
    return false;
}

const SOCKET_ERROR = -1;
const INVALID_SOCKET = -1;

function warpPacket(p: NativePointer, clientPort: BigEndian, targetPort: BigEndian, targetIP: BigEndian) {
    p.writeU16(clientPort);
    p.add(2).writeU16(targetPort);
    p.add(4).writeU32(targetIP);
}

// WSAGetLastError 内部实际调用了GetLastError, 需要获取错误代码的API请用 SystemFunction 包装
// /*
//     int WSAGetLastError();
// */
// const ws2_WSAGetLastError = new NativeFunction(Module.findExportByName('ws2_32.dll', 'WSAGetLastError') as NativePointer, 'int', [], wincalling_convention);

// /*
//     int getsockname(
//     [in]      SOCKET   s,
//     [out]     sockaddr *name,
//     [in, out] int      *namelen
//     );
// */
// const ws2_getsockname = new SystemFunction(Module.findExportByName('ws2_32.dll', 'getsockname') as NativePointer, 'int', ['pointer', 'pointer', 'int'], wincalling_convention);
// function getSocketPort(s: NativePointer): number {
//     const sockaddr_in = Memory.alloc(0x10);
//     const r = ws2_getsockname(s, sockaddr_in, 0x10);
//     if (r.value !== 0) {
//         const err = (r as WindowsSystemFunctionResult<number>).lastError
//         if (err != 10022 /* WSAEINVAL */) {
//             /*
//                 The socket has not been bound to an address with bind, or ADDR_ANY is specified in bind but connection has not yet occurred.
//             */
//             console.error(`[X] [process ${Process.id} failed to query the socket port, socket: ${ptr(s.toString())}, errcode:${err}`)
//         }
//         return -1
//     }
//     return swap16_LittleEndian_BigEndian(sockaddr_in.add(2).readU16());
// }
// Interceptor.attach(Module.findExportByName('ws2_32.dll', 'getsockname') as NativePointer, {
//     onEnter(args) {
//         console.log(`getsockname ${args[0]}`)
//     },
// })


interface spmap { [key: string]: LittleEndian | undefined; }
const socket_port_map: spmap = {};

/*
    int WSAAPI closesocket(
    [in] SOCKET s
    );
*/
const ws2_closesocket_addr = Module.findExportByName('ws2_32.dll', 'closesocket') as NativePointer;
const ws2_closesocket = new SystemFunction(ws2_closesocket_addr, 'int', ['pointer'], wincalling_convention);
function replace_closesocket(s: NativePointer): number {
    // 不是所有socket都会bind, 所以会出现socket_port_map大小为0, 但是仍然在delete不存在属性的情况
    if (VERBOSE) {
        console.log(`[i] [del] length of socket_port_map: ${Object.keys(socket_port_map).length} socket: ${ptr(s.toString())}`);
    }
    delete socket_port_map[s.toString()];
    return ws2_closesocket(s).value;
}
Interceptor.replace(ws2_closesocket_addr, new NativeCallback(replace_closesocket, 'int', ['pointer'], wincalling_convention));

/*
    int WSAAPI bind(
    [in] SOCKET         s,
    [in] const sockaddr *name,
    [in] int            namelen
    );
*/
const ws2_bind_addr = Module.findExportByName('ws2_32.dll', 'bind') as NativePointer;
const ws2_bind = new SystemFunction(ws2_bind_addr, 'int', ['pointer', 'pointer', 'int'], wincalling_convention);

function replace_bind(s: NativePointer, name: NativePointer, namelen: number): number {

    const port = swap16_LittleEndian_BigEndian(name.add(2).readU16());
    if (port === 0) {
        // 绑定到0端口等于让系统选择空闲端口来绑定
        /*
            对套接字bind(包括bind到0端口)后再次bind会失败, 错误代码:
            WSAEINVAL 10022
                An invalid argument was supplied. This error is returned of the socket s is already bound to an address.
            这种情况需要特殊处理
        */
        const [r, err] = bindFreePort(s, name);
        if (r !== -1) {
            socket_port_map[s.toString()] = r;
            if (VERBOSE) {
                console.log(`[i] [add, zreo port] length of socket_port_map: ${Object.keys(socket_port_map).length} socket: [${ptr(s.toString())}] = ${r}`);
            }
        } else {
            console.error(`[X] [process ${Process.id} hook: bind] failed to change the port which bind to 0, socket: ${ptr(s.toString())}, errcode: ${err}`);
        }
        return r;
    } else {
        // 绑定到非0端口
        const r = ws2_bind(s, name, namelen);
        if (r.value === 0) {
            socket_port_map[s.toString()] = port;
            if (VERBOSE) {
                console.log(`[i] [add, nozreo port] length of socket_port_map: ${Object.keys(socket_port_map).length} socket: [${ptr(s.toString())}] = ${r}`);
            }
        } else {
            console.error(`[X] [process ${Process.id} hook: bind] failed to bind port (by ws2_bind), socket: ${ptr(s.toString())}, errcode: ${(r as WindowsSystemFunctionResult<number>).lastError}`);
        }
        return r.value;
    }
}
Interceptor.replace(ws2_bind_addr, new NativeCallback(replace_bind, 'int', ['pointer', 'pointer', 'int'], wincalling_convention));

function bindFreePort(s: NativePointer, name: NativePointer|null = null): [number, number] {
    const startPort = 49152, endPort = 65535;
    let sockaddr_in;
    if (name !== null) {
        sockaddr_in = name;
        // sockaddr_in.writeU16(2); // AF_INET
        // sockaddr_in.add(4).writeU32(0); // INADDR_ANY
    } else {
        sockaddr_in = Memory.alloc(0x10);
        sockaddr_in.writeU16(2); // AF_INET
        sockaddr_in.add(4).writeU32(0); // INADDR_ANY
    }

    const port_offset = sockaddr_in.add(2);

    let i, r;
    for (i = startPort; i <= endPort; i++){
        port_offset.writeU16(swap16_LittleEndian_BigEndian(i));
        r = ws2_bind(s, sockaddr_in, 0x10);
        if (r.value === 0) {
            return [i, 0];
        }
    }
    const err = (r as WindowsSystemFunctionResult<number>).lastError;
    return [-1, err];
}

function connectToProxy(args: NativePointer[], connectType: string) {
    if (args[2].toInt32() !== 16 /* ipv4 */) {
        return;
    }

    const sockaddr = args[1];
    // 保存原connect目标的地址
    const OriginalPort = sockaddr.add(2).readU16();
    const OriginalIP = sockaddr.add(4).readU32();
    const LittleEndianPort = swap16_LittleEndian_BigEndian(OriginalPort);

    const OriginaAddr = uint32ToIp(OriginalIP) + ": " + LittleEndianPort;


    // 不转发基础服务
    if ([53,].includes(LittleEndianPort)) {
        console.warn(`[-] [process: ${Process.id} hook: ${connectType}] connect exclude PORT ` + OriginaAddr);
        return;
    }
    // 不转发内网IP
    if ( /* excludeIP.indexOf(OriginalIP) != -1 || */ IsIntranetIP(OriginalIP)) {
        console.warn(`[-] [process: ${Process.id} hook: ${connectType}] connect exclude IP ` + OriginaAddr);
        return;
    }


    // 固定客户端将使用的端口
    const socket = args[0];
    // 使用getSocketPort有局限
    let clientPort = socket_port_map[socket.toString()];
    if (clientPort === undefined) {
        let err;
        [clientPort, err] = bindFreePort(socket);
        if (clientPort === -1) {
            if (FORCE_PROXY_MODE) {
                args[0] = ptr(INVALID_SOCKET);
            }
            console.error(`[X] [process ${Process.id} hook: ${connectType}] failed to bind port (by bindFreePort) ${OriginaAddr}, socket: ${ptr(socket.toString())}, errcode: ${err}`);
            return;
        }
        if (VERBOSE) {
            console.log(`[i] [process: ${Process.id} hook: ${connectType}] target ${OriginaAddr} bind from 127.0.0.1:${clientPort} (bindFreePort socket: ${ptr(socket.toString())})`);
        }
    } else {
        if (VERBOSE) {
            console.log(`[i] [process: ${Process.id} hook: ${connectType}] target ${OriginaAddr} bind from 127.0.0.1:${socket_port_map[socket.toString()]} (socket_port_map socket: ${ptr(socket.toString())})`);
        }
    }


    // 把客户端将在连接时使用的端口通知proxy, 使得proxy将此端口与目标服务器地址绑定
    const bindInfoPacket = Memory.alloc(0x8);
    warpPacket(bindInfoPacket, clientPort, LittleEndianPort, OriginalIP);
    send("", ArrayBuffer.wrap(bindInfoPacket, 0x8));


    // 替换connect连接目标为代理服务器
    sockaddr.add(2).writeU16(MY_PROXY_PORT);
    sockaddr.add(4).writeU32(MY_PROXY_IP);
}

Interceptor.attach(Module.findExportByName('ws2_32.dll', 'connect') as NativePointer, {
    /*
        int WSAAPI connect(
        [in] SOCKET         s,
        [in] const sockaddr *name,
        [in] int            namelen
        );
    */
    onEnter(args) {
        connectToProxy(args, "connect");
    }
});

Interceptor.attach(Module.findExportByName('ws2_32.dll', 'WSAConnect') as NativePointer, {
    /*
        int WSAAPI WSAConnect(
        [in]  SOCKET         s,
        [in]  const sockaddr *name,
        [in]  int            namelen,
        [in]  LPWSABUF       lpCallerData,
        [out] LPWSABUF       lpCalleeData,
        [in]  LPQOS          lpSQOS,
        [in]  LPQOS          lpGQOS
        );
    */
    onEnter(args) {
        connectToProxy(args, "WSAConnect");
    }
});

function GetConnectExPtr(): NativePointer {
    /*
        int WSAStartup(
                WORD      wVersionRequired,
        [out] LPWSADATA lpWSAData
        );
    */
    const WSAStartup = new NativeFunction(Module.findExportByName('ws2_32.dll', 'WSAStartup') as NativePointer, 'int', ['uint16', 'pointer'], wincalling_convention);
    const wsaData = Memory.alloc(0x198); // x64 > x86 0x198为WSADATA占用空间最大字节
    WSAStartup(0x0202 /* MAKEWORD(2, 2) */, wsaData);

    /*
        SOCKET WSAAPI socket(
        [in] int af,
        [in] int type,
        [in] int protocol
        );
    */
    const socket = new NativeFunction(Module.findExportByName('ws2_32.dll', 'socket') as NativePointer, 'pointer', ['int', 'int', 'int'], wincalling_convention);
    //socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    const s = socket(2, 1, 6);

    /*
        int WSAAPI WSAIoctl(
        [in]  SOCKET                             s,
        [in]  DWORD                              dwIoControlCode,
        [in]  LPVOID                             lpvInBuffer,
        [in]  DWORD                              cbInBuffer,
        [out] LPVOID                             lpvOutBuffer,
        [in]  DWORD                              cbOutBuffer,
        [out] LPDWORD                            lpcbBytesReturned,
        [in]  LPWSAOVERLAPPED                    lpOverlapped,
        [in]  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );
    */
    const WSAIoctl = new SystemFunction(Module.findExportByName('ws2_32.dll', 'WSAIoctl') as NativePointer, 'int',
        ['pointer', 'uint32', 'pointer', 'uint32', 'pointer', 'uint32', 'pointer', 'pointer', 'pointer'], wincalling_convention);
    //int success = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (void*)&guid, sizeof(guid), (void*)&ConnectExPtr, sizeof(ConnectExPtr),&numBytes, NULL, NULL);
    const guidarray = [0xb9, 0x07, 0xa2, 0x25, 0xf3, 0xdd, 0x60, 0x46, 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e];
    const guid = Memory.alloc(guidarray.length);
    guid.writeByteArray(guidarray);
    const pConnectExPtr = Memory.alloc(Process.pointerSize);
    const numBytes = Memory.alloc(4);
    let addr: NativePointer;
    const r = WSAIoctl(s, 0xC8000006, guid, 16, pConnectExPtr, Process.pointerSize, numBytes, ptr(0), ptr(0));
    if (r.value === SOCKET_ERROR) {
        console.error(`[X] WSAIoctl fail ${(r as WindowsSystemFunctionResult<number>).lastError}`);
        addr = ptr(0);
    } else {
        addr = pConnectExPtr.readPointer();
    }
    ws2_closesocket(s);
    return addr;
}

const ConnectExPtr = GetConnectExPtr();
console.log(`[i] process ${Process.id} LpfnConnectex: ${ConnectExPtr}`);

Interceptor.attach(ConnectExPtr, {
    /*
        BOOL LpfnConnectex(
        [in]           SOCKET s,
        [in]           const sockaddr *name,
        [in]           int namelen,
        [in, optional] PVOID lpSendBuffer,
        [in]           DWORD dwSendDataLength,
        [out]          LPDWORD lpdwBytesSent,
        [in]           LPOVERLAPPED lpOverlapped
        )
    */
    onEnter(args) {
        connectToProxy(args, "LpfnConnectex");
    }
});
