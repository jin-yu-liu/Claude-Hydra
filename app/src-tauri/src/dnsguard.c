/*
 * Hydra DNS guard: loaded by Sandboxie (InjectDll64) into every process of a Hydra box.
 *
 * Name lookups in a box are handed to the Windows DNS client service outside the box (its
 * RPC endpoint is opened by Sandboxie's default template and cannot be closed by settings),
 * so a boxed process could resolve, and leak, any name on the host's DNS. This DLL refuses
 * connections to that endpoint. Windows then resolves inside the process, which sends its
 * queries with WSASendMsg to (v4-mapped) IPv6 addresses, a path Sandboxie's network rules do
 * not catch. So the DLL also refuses, in Winsock, every connect or send to an address that is
 * not loopback, which matches the box rules (only Hydra's local relay is allowed): external
 * names fail, while localhost, IP literals and the hosts file keep working. Claude itself
 * sends host names to its proxy and is unaffected.
 *
 * Loopback: the box rules let every process reach 127.0.0.1, since many runtimes (curl's
 * resolver, Python, ...) connect a socket pair to themselves over loopback. This DLL narrows
 * it again: a loopback destination is allowed only on the account's relay port (box setting
 * `HydraRelayPort`) or when the listening socket belongs to a process in the same box, so host
 * services such as a local system proxy stay out of reach. ConnectEx (used by Node, Bun and
 * other IOCP runtimes) is wrapped through WSAIoctl so it gets the same checks.
 *
 * Direct boxes: an environment without a node has no relay and no network rules
 * (`HydraDirect=y`, no `HydraRelayPort`). The guard then hooks nothing, so names resolve and
 * connections leave as they would outside the box. Only that explicit setting turns it off: a
 * box whose settings cannot be read keeps every check.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <winternl.h>
#include <iphlpapi.h>

#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)

/* SbieDll is built with stdcall as its default convention (it only matters on x86). */
typedef void *(__stdcall *P_SbieDll_Hook)(const char *name, void *source, void *detour, HMODULE module);
#ifndef _WIN64
/* x86 decorates the stdcall export; Sandboxie looks the entry point up by its plain name. */
#pragma comment(linker, "/EXPORT:InjectDllMain=_InjectDllMain@8")
#endif

typedef NTSTATUS(NTAPI *P_NtAlpcConnectPort)(PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, PVOID, ULONG, PSID,
                                             PVOID, PSIZE_T, PVOID, PVOID, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI *P_NtAlpcConnectPortEx)(PHANDLE, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, PVOID, ULONG,
                                               PSECURITY_DESCRIPTOR, PVOID, PSIZE_T, PVOID, PVOID, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI *P_NtConnectPort)(PHANDLE, PUNICODE_STRING, PSECURITY_QUALITY_OF_SERVICE, PVOID, PVOID,
                                         PULONG, PVOID, PULONG);
typedef int(WSAAPI *P_connect)(SOCKET, const struct sockaddr *, int);
typedef int(WSAAPI *P_WSAConnect)(SOCKET, const struct sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int(WSAAPI *P_sendto)(SOCKET, const char *, int, int, const struct sockaddr *, int);
typedef int(WSAAPI *P_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr *, int,
                                 LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int(WSAAPI *P_WSASendMsg)(SOCKET, LPWSAMSG, DWORD, LPDWORD, LPWSAOVERLAPPED,
                                  LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef void(WSAAPI *P_WSASetLastError)(int);
typedef int(WSAAPI *P_getsockopt)(SOCKET, int, int, char *, int *);
typedef int(WSAAPI *P_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL(PASCAL *P_ConnectEx)(SOCKET, const struct sockaddr *, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef LONG(__stdcall *P_QueryProcess)(HANDLE, WCHAR *, WCHAR *, WCHAR *, ULONG *);
typedef LONG(__stdcall *P_QueryConf)(const WCHAR *, const WCHAR *, ULONG, WCHAR *, ULONG);
typedef DWORD(WINAPI *P_GetExtendedTable)(PVOID, PDWORD, BOOL, ULONG, ULONG, ULONG);

static P_NtAlpcConnectPort sys_NtAlpcConnectPort;
static P_NtAlpcConnectPortEx sys_NtAlpcConnectPortEx;
static P_NtConnectPort sys_NtConnectPort;
static P_connect sys_connect;
static P_WSAConnect sys_WSAConnect;
static P_sendto sys_sendto;
static P_WSASendTo sys_WSASendTo;
static P_WSASendMsg sys_WSASendMsg;
static P_WSASetLastError ws_set_error;
static P_getsockopt ws_getsockopt;
static P_WSAIoctl sys_WSAIoctl;
static P_ConnectEx volatile sys_ConnectEx;
static P_QueryProcess query_process;
static P_GetExtendedTable get_tcp_table, get_udp_table;
static WCHAR own_box[34];
static USHORT relay_port; /* host byte order; 0 = no relay, loopback left unrestricted */
static BOOL direct_box;  /* `HydraDirect=y`: no node, the guard stays out of the way */

/* Whether `name` is the DNS client endpoint (`...\DNSResolver`, any case). */
static BOOL is_dns_port(const UNICODE_STRING *name) {
    static const WCHAR tail[] = L"\\dnsresolver";
    const USHORT n = (USHORT)(sizeof(tail) / sizeof(WCHAR) - 1);
    USHORT len, i;
    if (!name || !name->Buffer) return FALSE;
    len = name->Length / sizeof(WCHAR);
    if (len < n) return FALSE;
    for (i = 0; i < n; i++) {
        WCHAR c = name->Buffer[len - n + i];
        if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
        if (c != tail[i]) return FALSE;
    }
    return TRUE;
}

static NTSTATUS NTAPI my_NtAlpcConnectPort(PHANDLE h, PUNICODE_STRING name, POBJECT_ATTRIBUTES oa, PVOID attrs,
                                           ULONG flags, PSID sid, PVOID msg, PSIZE_T len, PVOID out, PVOID in,
                                           PLARGE_INTEGER timeout) {
    if (is_dns_port(name)) return STATUS_OBJECT_NAME_NOT_FOUND;
    return sys_NtAlpcConnectPort(h, name, oa, attrs, flags, sid, msg, len, out, in, timeout);
}

static NTSTATUS NTAPI my_NtAlpcConnectPortEx(PHANDLE h, POBJECT_ATTRIBUTES port, POBJECT_ATTRIBUTES client,
                                             PVOID attrs, ULONG flags, PSECURITY_DESCRIPTOR sd, PVOID msg,
                                             PSIZE_T len, PVOID out, PVOID in, PLARGE_INTEGER timeout) {
    if (port && is_dns_port(port->ObjectName)) return STATUS_OBJECT_NAME_NOT_FOUND;
    return sys_NtAlpcConnectPortEx(h, port, client, attrs, flags, sd, msg, len, out, in, timeout);
}

static NTSTATUS NTAPI my_NtConnectPort(PHANDLE h, PUNICODE_STRING name, PSECURITY_QUALITY_OF_SERVICE qos,
                                       PVOID client, PVOID server, PULONG max, PVOID info, PULONG info_len) {
    if (is_dns_port(name)) return STATUS_OBJECT_NAME_NOT_FOUND;
    return sys_NtConnectPort(h, name, qos, client, server, max, info, info_len);
}

/* Network-order port to host order (ntohs would need linking ws2_32). */
#define net_port(p) ((USHORT)((((USHORT)(p) & 0xff) << 8) | (((USHORT)(p) >> 8) & 0xff)))

enum dest { DEST_OTHER, DEST_LOOPBACK, DEST_EXTERNAL };

/*
 * Classifies a destination: loopback (127/8, ::1, v4-mapped 127/8) with its port in host byte
 * order, any other IPv4/IPv6 address, or something left to Sandboxie (missing address on a
 * connected socket, Unix sockets, Hyper-V).
 */
static enum dest classify(const struct sockaddr *a, int len, USHORT *port) {
    if (!a || len < (int)sizeof(a->sa_family)) return DEST_OTHER;
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)a;
        if (len < (int)sizeof(struct sockaddr_in)) return DEST_OTHER;
        *port = net_port(v4->sin_port);
        return ((const unsigned char *)&v4->sin_addr)[0] == 127 ? DEST_LOOPBACK : DEST_EXTERNAL;
    }
    if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)a;
        const unsigned char *b;
        int i;
        if (len < (int)sizeof(struct sockaddr_in6)) return DEST_OTHER;
        *port = net_port(v6->sin6_port);
        b = v6->sin6_addr.s6_addr;
        for (i = 0; i < 10 && b[i] == 0; i++) {}
        if (i == 10) {
            if (b[10] == 0xff && b[11] == 0xff) return b[12] == 127 ? DEST_LOOPBACK : DEST_EXTERNAL; /* v4-mapped */
            if (b[10] == 0 && b[11] == 0 && b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] == 1) return DEST_LOOPBACK;
        }
        return DEST_EXTERNAL;
    }
    return DEST_OTHER;
}

static void *table(P_GetExtendedTable get, ULONG family, ULONG klass) {
    DWORD size = 0;
    void *buf = NULL;
    int tries;
    for (tries = 0; tries < 4; tries++) {
        DWORD rc = get(buf, &size, FALSE, family, klass, 0);
        if (rc == NO_ERROR) return buf;
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        buf = NULL;
        if (rc != ERROR_INSUFFICIENT_BUFFER || !size) return NULL;
        buf = HeapAlloc(GetProcessHeap(), 0, size);
        if (!buf) return NULL;
    }
    if (buf) HeapFree(GetProcessHeap(), 0, buf);
    return NULL;
}

/* Whether `pid` runs in this process's box. */
static BOOL same_box(DWORD pid) {
    WCHAR box[34] = {0}, image[96], sid[96];
    ULONG session = 0;
    if (pid == GetCurrentProcessId()) return TRUE;
    if (!pid || !query_process || !own_box[0]) return FALSE;
    if (query_process((HANDLE)(ULONG_PTR)pid, box, image, sid, &session) != 0) return FALSE;
    return lstrcmpiW(box, own_box) == 0;
}

/* Whether a socket bound to loopback (or any address) on `port` belongs to this box. */
static BOOL boxed_listener(BOOL udp, USHORT port) {
    ULONG fam;
    BOOL found = FALSE;
    P_GetExtendedTable get = udp ? get_udp_table : get_tcp_table;
    if (!get) return FALSE;
    for (fam = 0; fam < 2 && !found; fam++) {
        void *t = table(get, fam ? AF_INET6 : AF_INET, udp ? UDP_TABLE_OWNER_PID : TCP_TABLE_OWNER_PID_LISTENER);
        DWORD i, n;
        if (!t) continue;
        n = *(DWORD *)t;
        for (i = 0; i < n && !found; i++) {
            DWORD local_port, pid;
            if (fam == 0 && udp) { MIB_UDPROW_OWNER_PID *r = &((MIB_UDPTABLE_OWNER_PID *)t)->table[i]; local_port = r->dwLocalPort; pid = r->dwOwningPid; }
            else if (fam == 0) { MIB_TCPROW_OWNER_PID *r = &((MIB_TCPTABLE_OWNER_PID *)t)->table[i]; local_port = r->dwLocalPort; pid = r->dwOwningPid; }
            else if (udp) { MIB_UDP6ROW_OWNER_PID *r = &((MIB_UDP6TABLE_OWNER_PID *)t)->table[i]; local_port = r->dwLocalPort; pid = r->dwOwningPid; }
            else { MIB_TCP6ROW_OWNER_PID *r = &((MIB_TCP6TABLE_OWNER_PID *)t)->table[i]; local_port = r->dwLocalPort; pid = r->dwOwningPid; }
            if (net_port((USHORT)local_port) == port && same_box(pid)) found = TRUE;
        }
        HeapFree(GetProcessHeap(), 0, t);
    }
    return found;
}

static BOOL is_udp(SOCKET s) {
    int type = 0, len = sizeof(type);
    return ws_getsockopt && ws_getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &len) == 0 && type == SOCK_DGRAM;
}

/* Whether a connect or send from `s` to `a` is refused (see the file comment). */
static BOOL refused(SOCKET s, const struct sockaddr *a, int len, BOOL datagram) {
    USHORT port = 0;
    switch (classify(a, len, &port)) {
    case DEST_EXTERNAL: return TRUE;
    case DEST_LOOPBACK:
        if (!relay_port || port == relay_port) return FALSE;
        return !boxed_listener(datagram || is_udp(s), port);
    default: return FALSE;
    }
}

static int refuse(int code) {
    if (ws_set_error) ws_set_error(code);
    return SOCKET_ERROR;
}

static int WSAAPI my_connect(SOCKET s, const struct sockaddr *a, int l) {
    if (refused(s, a, l, FALSE)) return refuse(WSAECONNREFUSED);
    return sys_connect(s, a, l);
}

static int WSAAPI my_WSAConnect(SOCKET s, const struct sockaddr *a, int l, LPWSABUF cd, LPWSABUF ce, LPQOS q,
                                LPQOS g) {
    if (refused(s, a, l, FALSE)) return refuse(WSAECONNREFUSED);
    return sys_WSAConnect(s, a, l, cd, ce, q, g);
}

static int WSAAPI my_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tl) {
    if (refused(s, to, tl, TRUE)) return refuse(WSAENETUNREACH);
    return sys_sendto(s, buf, len, flags, to, tl);
}

static int WSAAPI my_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD n, LPDWORD sent, DWORD flags,
                               const struct sockaddr *to, int tl, LPWSAOVERLAPPED ov,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (refused(s, to, tl, TRUE)) return refuse(WSAENETUNREACH);
    return sys_WSASendTo(s, bufs, n, sent, flags, to, tl, ov, cr);
}

static int WSAAPI my_WSASendMsg(SOCKET s, LPWSAMSG msg, DWORD flags, LPDWORD sent, LPWSAOVERLAPPED ov,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (msg && refused(s, msg->name, msg->namelen, TRUE)) return refuse(WSAENETUNREACH);
    return sys_WSASendMsg(s, msg, flags, sent, ov, cr);
}

static BOOL PASCAL my_ConnectEx(SOCKET s, const struct sockaddr *a, int l, PVOID buf, DWORD n, LPDWORD sent,
                                LPOVERLAPPED ov) {
    if (refused(s, a, l, FALSE)) {
        if (ws_set_error) ws_set_error(WSAECONNREFUSED);
        return FALSE;
    }
    return sys_ConnectEx(s, a, l, buf, n, sent, ov);
}

/* Hands out my_ConnectEx in place of the provider's ConnectEx. A second, different provider
 * pointer is passed through unwrapped (Sandboxie's rules still block external addresses). */
static int WSAAPI my_WSAIoctl(SOCKET s, DWORD code, LPVOID in, DWORD in_len, LPVOID out, DWORD out_len,
                              LPDWORD ret, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    static const GUID connect_ex = WSAID_CONNECTEX;
    int rc = sys_WSAIoctl(s, code, in, in_len, out, out_len, ret, ov, cr);
    if (rc == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER && in && in_len >= sizeof(GUID) && out &&
        out_len >= sizeof(P_ConnectEx) && memcmp(in, &connect_ex, sizeof(GUID)) == 0) {
        P_ConnectEx f = *(P_ConnectEx *)out;
        if (f && f != my_ConnectEx) {
            InterlockedCompareExchangePointer((PVOID volatile *)&sys_ConnectEx, (PVOID)f, NULL);
            if (sys_ConnectEx == f) *(P_ConnectEx *)out = my_ConnectEx;
        }
    }
    return rc;
}

/* Reads this box's name and its `HydraDirect` and `HydraRelayPort` settings. */
static void load_box_settings(HMODULE sbie) {
    WCHAR image[96], sid[96], value[16] = {0}, direct[4] = {0};
    ULONG session = 0, port = 0;
    int i;
    P_QueryConf query_conf = (P_QueryConf)GetProcAddress(sbie, "SbieApi_QueryConf");
    query_process = (P_QueryProcess)GetProcAddress(sbie, "SbieApi_QueryProcess");
    if (!query_process || query_process((HANDLE)(ULONG_PTR)GetCurrentProcessId(), own_box, image, sid, &session) != 0) {
        own_box[0] = 0;
        return;
    }
    if (!query_conf) return;
    if (query_conf(own_box, L"HydraRelayPort", 0, value, sizeof(value)) == 0) {
        for (i = 0; value[i] >= L'0' && value[i] <= L'9'; i++) port = port * 10 + (value[i] - L'0');
        if (port > 0 && port < 65536 && value[i] == 0) relay_port = (USHORT)port;
    }
    /* A relay always wins: a leftover `HydraDirect` must never open a box that has one. */
    if (!relay_port && query_conf(own_box, L"HydraDirect", 0, direct, sizeof(direct)) == 0 &&
        (direct[0] == L'y' || direct[0] == L'Y') && direct[1] == 0)
        direct_box = TRUE;
}

static void hook(P_SbieDll_Hook sbie_hook, HMODULE module, HMODULE self, const char *name, void *detour, void **sys) {
    void *source = module ? (void *)GetProcAddress(module, name) : NULL;
    if (source) *sys = sbie_hook(name, source, detour, self);
}

/* Called by Sandboxie after loading this DLL, with SbieDll's module handle. */
__declspec(dllexport) void __stdcall InjectDllMain(HINSTANCE sbie, ULONG_PTR unused) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE ws2 = LoadLibraryW(L"ws2_32.dll");
    HMODULE self = NULL;
    P_SbieDll_Hook sbie_hook = (P_SbieDll_Hook)GetProcAddress((HMODULE)sbie, "SbieDll_Hook");
    (void)unused;
    if (!sbie_hook || !ntdll) return;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)(void *)&InjectDllMain, &self);
    load_box_settings((HMODULE)sbie);
    if (direct_box) return;
    hook(sbie_hook, ntdll, self, "NtAlpcConnectPort", (void *)my_NtAlpcConnectPort, (void **)&sys_NtAlpcConnectPort);
    hook(sbie_hook, ntdll, self, "NtAlpcConnectPortEx", (void *)my_NtAlpcConnectPortEx, (void **)&sys_NtAlpcConnectPortEx);
    hook(sbie_hook, ntdll, self, "NtConnectPort", (void *)my_NtConnectPort, (void **)&sys_NtConnectPort);
    if (!ws2) return;
    if (relay_port) {
        HMODULE iphlp = LoadLibraryW(L"iphlpapi.dll");
        if (iphlp) {
            get_tcp_table = (P_GetExtendedTable)GetProcAddress(iphlp, "GetExtendedTcpTable");
            get_udp_table = (P_GetExtendedTable)GetProcAddress(iphlp, "GetExtendedUdpTable");
        }
    }
    ws_set_error = (P_WSASetLastError)GetProcAddress(ws2, "WSASetLastError");
    ws_getsockopt = (P_getsockopt)GetProcAddress(ws2, "getsockopt");
    hook(sbie_hook, ws2, self, "WSAIoctl", (void *)my_WSAIoctl, (void **)&sys_WSAIoctl);
    hook(sbie_hook, ws2, self, "connect", (void *)my_connect, (void **)&sys_connect);
    hook(sbie_hook, ws2, self, "WSAConnect", (void *)my_WSAConnect, (void **)&sys_WSAConnect);
    hook(sbie_hook, ws2, self, "sendto", (void *)my_sendto, (void **)&sys_sendto);
    hook(sbie_hook, ws2, self, "WSASendTo", (void *)my_WSASendTo, (void **)&sys_WSASendTo);
    hook(sbie_hook, ws2, self, "WSASendMsg", (void *)my_WSASendMsg, (void **)&sys_WSASendMsg);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(inst);
    return TRUE;
}
