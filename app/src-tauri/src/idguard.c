/*
 * Hydra identity guard: loaded by Sandboxie (InjectDll64) into every process of a Hydra box.
 *
 * Sandboxie virtualizes files and the registry, but the system still describes itself the same
 * way to every box: the machine GUID, the hardware profile GUID, volume serials, adapter MAC
 * addresses and the computer name a boxed program reads are this computer's. Accounts kept side
 * by side then look like one device to anything that fingerprints hardware.
 *
 * Hydra derives its own values per account (identity.rs) and stores them as settings on the box
 * (`HydraMachineGuid` and the others below). This DLL answers the matching system calls with
 * those values. Without `HydraMachineGuid` nothing is hooked, so a box that does not use the
 * option behaves exactly as before.
 *
 * Where a value has many Win32 entry points it is rewritten at the native call they all end in,
 * so no route reports the host's copy while another reports the derived one:
 *   - registry values: NtQueryValueKey / NtEnumerateValueKey (RegQueryValueExW/A, RegGetValueW/A,
 *     RegEnumValueW/A, and anything else reading the value);
 *   - volume serials: NtQueryVolumeInformationFile (GetVolumeInformationW/A, ...ByHandleW,
 *     GetFileInformationByHandle, Node's fs.fstat().dev), NtQueryInformationFile and
 *     NtQueryInformationByName (FileIdInformation's 64-bit serial, and FileStatBasicInformation,
 *     which Node's fs.stat() reads by path on Windows 11 24H2+);
 *   - the computer name: GetComputerNameW/A, GetComputerNameExW/A, and the `Hostname` value
 *     `hostname.exe` prints;
 *   - the account: GetUserNameW/A, GetUserNameExW/A, LookupAccountSidW/A, LookupAccountNameW/A
 *     (and the sechost *Local* forms .NET uses, which advapi32 does not forward), and
 *     ConvertSidToStringSidW/A. A local account's domain is the computer name, so both halves are
 *     answered with the box's values, and a SID in either direction maps between the derived name
 *     and the derived SID text. The SID as bytes is answered too: GetTokenInformation(TokenUser
 *     and friends) returns the derived SID, and so do LsaLookupSids / LsaLookupSids2 and
 *     LsaLookupNames2, which .NET's account classes use directly instead of the Win32 lookups.
 *     userenv is answered with the host's own account in every one of these: it builds the profile
 *     directory from the name and the SID, and the profile that exists is the host user's;
 *   - the board, BIOS and disk serials: GetSystemFirmwareTable('RSMB') and the storage descriptor
 *     behind IOCTL_STORAGE_QUERY_PROPERTY. WMI, the other route to them, is closed off in the box.
 *
 * Not covered: the DHCPv6 DUID (`ipconfig` prints the host's copy from outside the box),
 * NtQueryMultipleValueKey, the SCSI pass-through IOCTLs that can report a disk serial, and
 * NtQueryInformationToken when a program calls ntdll directly instead of GetTokenInformation. The
 * token itself still carries the host's SID for access checks - only what it reports is changed.
 */
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <intrin.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif
#define HYDRA_STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#define HYDRA_STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)

typedef void *(__stdcall *P_SbieDll_Hook)(const char *name, void *source, void *detour, HMODULE module);
typedef LONG(__stdcall *P_QueryProcess)(HANDLE, WCHAR *, WCHAR *, WCHAR *, ULONG *);
typedef LONG(__stdcall *P_QueryConf)(const WCHAR *, const WCHAR *, ULONG, WCHAR *, ULONG);
typedef PVOID(NTAPI *P_RtlPcToFileHeader)(PVOID, PVOID *);

/* x86 decorates the stdcall export; Sandboxie looks the entry point up by its plain name. */
#ifndef _WIN64
#pragma comment(linker, "/EXPORT:InjectDllMain=_InjectDllMain@8")
#endif

typedef NTSTATUS(NTAPI *P_NtQueryValueKey)(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *P_NtEnumerateValueKey)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *P_NtQueryKey)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *P_NtQueryVolumeInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS(NTAPI *P_NtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS(NTAPI *P_NtQueryInformationByName)(POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef ULONG(WINAPI *P_GetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
typedef ULONG(WINAPI *P_GetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
typedef DWORD(WINAPI *P_GetIfTable)(PMIB_IFTABLE, PULONG, BOOL);
typedef DWORD(WINAPI *P_GetIfEntry)(PMIB_IFROW);
typedef DWORD(WINAPI *P_GetIfTable2)(PMIB_IF_TABLE2 *);
typedef DWORD(WINAPI *P_GetIfTable2Ex)(MIB_IF_TABLE_LEVEL, PMIB_IF_TABLE2 *);
typedef DWORD(WINAPI *P_GetIfEntry2)(PMIB_IF_ROW2);
typedef DWORD(WINAPI *P_GetIfEntry2Ex)(MIB_IF_ENTRY_LEVEL, PMIB_IF_ROW2);
typedef UINT(WINAPI *P_GetSystemFirmwareTable)(DWORD, DWORD, PVOID, DWORD);
typedef BOOL(WINAPI *P_DeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI *P_GetComputerNameExW)(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);
typedef BOOL(WINAPI *P_GetComputerNameExA)(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
typedef BOOL(WINAPI *P_GetComputerNameW)(LPWSTR, LPDWORD);
typedef BOOL(WINAPI *P_GetComputerNameA)(LPSTR, LPDWORD);
typedef BOOL(WINAPI *P_LookupAccountSidW)(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(WINAPI *P_LookupAccountSidA)(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(WINAPI *P_LookupAccountNameW)(LPCWSTR, LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(WINAPI *P_LookupAccountNameA)(LPCSTR, LPCSTR, PSID, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(WINAPI *P_LookupAccountSidLocalW)(PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(WINAPI *P_LookupAccountSidLocalA)(PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(WINAPI *P_LookupAccountNameLocalW)(LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(WINAPI *P_LookupAccountNameLocalA)(LPCSTR, PSID, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
typedef BOOLEAN(WINAPI *P_GetUserNameExW)(int, LPWSTR, PULONG);
typedef BOOLEAN(WINAPI *P_GetUserNameExA)(int, LPSTR, PULONG);
typedef BOOL(WINAPI *P_GetUserNameW)(LPWSTR, LPDWORD);
typedef BOOL(WINAPI *P_GetUserNameA)(LPSTR, LPDWORD);
typedef BOOL(WINAPI *P_ConvertSidToStringSidW)(PSID, LPWSTR *);
typedef BOOL(WINAPI *P_ConvertSidToStringSidA)(PSID, LPSTR *);
typedef BOOL(WINAPI *P_ConvertStringSidToSidW)(LPCWSTR, PSID *);
typedef BOOL(WINAPI *P_GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, LPDWORD);
/* The native lookup behind .NET's account classes: mscorlib imports these directly and never
   reaches `LookupAccountSid`, so the derived SID has to be answered here too. */
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} HYDRA_UNICODE_STRING;
typedef struct {
    HYDRA_UNICODE_STRING Name;
    PSID Sid;
} HYDRA_TRUST_INFORMATION;
typedef struct {
    ULONG Entries;
    HYDRA_TRUST_INFORMATION *Domains;
} HYDRA_DOMAIN_LIST;
typedef struct {
    SID_NAME_USE Use;
    HYDRA_UNICODE_STRING Name;
    LONG DomainIndex;
} HYDRA_TRANSLATED_NAME;
typedef struct {
    SID_NAME_USE Use;
    PSID Sid;
    LONG DomainIndex;
    ULONG Flags;
} HYDRA_TRANSLATED_SID2;
typedef NTSTATUS(NTAPI *P_LsaLookupSids)(void *, ULONG, PSID *, HYDRA_DOMAIN_LIST **, HYDRA_TRANSLATED_NAME **);
typedef NTSTATUS(NTAPI *P_LsaLookupSids2)(void *, ULONG, ULONG, PSID *, HYDRA_DOMAIN_LIST **, HYDRA_TRANSLATED_NAME **);
typedef NTSTATUS(NTAPI *P_LsaLookupNames2)(void *, ULONG, ULONG, HYDRA_UNICODE_STRING *, HYDRA_DOMAIN_LIST **,
                                           HYDRA_TRANSLATED_SID2 **);

/* A function can be exported by two modules (a forwarder and its target). Both copies are
   hooked so programs bound to either reach the detour; `b` is the target's trampoline and is
   preferred, since calling the forwarder's would re-enter the detour through the target. */
#define REAL(pair) ((pair).b ? (pair).b : (pair).a)
#define PAIR(type) struct { type a; type b; }

static P_NtQueryValueKey sys_NtQueryValueKey;
static P_NtEnumerateValueKey sys_NtEnumerateValueKey;
static P_NtQueryKey sys_NtQueryKey;
/* Not hooked, only called: the caller's module behind a detour, so the system's own profile code
   can be left alone (see `from_userenv`). */
static P_RtlPcToFileHeader sys_RtlPcToFileHeader;
static P_NtQueryVolumeInformationFile sys_NtQueryVolumeInformationFile;
static P_NtQueryInformationFile sys_NtQueryInformationFile;
static P_NtQueryInformationByName sys_NtQueryInformationByName;
static P_GetAdaptersAddresses sys_GetAdaptersAddresses;
static P_GetAdaptersInfo sys_GetAdaptersInfo;
static P_GetIfTable sys_GetIfTable;
static P_GetIfEntry sys_GetIfEntry;
static P_GetIfTable2 sys_GetIfTable2;
static P_GetIfTable2Ex sys_GetIfTable2Ex;
static P_GetIfEntry2 sys_GetIfEntry2;
static P_GetIfEntry2Ex sys_GetIfEntry2Ex;
static PAIR(P_GetSystemFirmwareTable) sys_GetSystemFirmwareTable;
static PAIR(P_DeviceIoControl) sys_DeviceIoControl;
static PAIR(P_GetComputerNameExW) sys_GetComputerNameExW;
static PAIR(P_GetComputerNameExA) sys_GetComputerNameExA;
static PAIR(P_GetComputerNameW) sys_GetComputerNameW;
static PAIR(P_GetComputerNameA) sys_GetComputerNameA;
static PAIR(P_LookupAccountSidW) sys_LookupAccountSidW;
static PAIR(P_LookupAccountSidA) sys_LookupAccountSidA;
static PAIR(P_LookupAccountNameW) sys_LookupAccountNameW;
static PAIR(P_LookupAccountNameA) sys_LookupAccountNameA;
/* Only sechost exports the local-only lookups, which do not take a system name. */
static P_LookupAccountSidLocalW sys_LookupAccountSidLocalW;
static P_LookupAccountSidLocalA sys_LookupAccountSidLocalA;
static P_LookupAccountNameLocalW sys_LookupAccountNameLocalW;
static P_LookupAccountNameLocalA sys_LookupAccountNameLocalA;
static PAIR(P_GetUserNameExW) sys_GetUserNameExW;
static PAIR(P_GetUserNameExA) sys_GetUserNameExA;
static PAIR(P_GetUserNameW) sys_GetUserNameW;
static PAIR(P_GetUserNameA) sys_GetUserNameA;
static PAIR(P_ConvertSidToStringSidW) sys_ConvertSidToStringSidW;
static PAIR(P_ConvertSidToStringSidA) sys_ConvertSidToStringSidA;
/* The token's own SID, which the text entry points above never see: `whoami /user` and .NET's
   account classes format it themselves. */
static PAIR(P_GetTokenInformation) sys_GetTokenInformation;
static PAIR(P_LsaLookupSids) sys_LsaLookupSids;
static PAIR(P_LsaLookupSids2) sys_LsaLookupSids2;
static PAIR(P_LsaLookupNames2) sys_LsaLookupNames2;

/* What this box reports, as configured on it by sandbox.rs. An empty field is left to the host. */
static WCHAR id_machine_guid[64];
static WCHAR id_hw_profile_guid[64];
static WCHAR id_computer_name[64];
static BYTE id_mac[6];
static int have_mac;
static BYTE id_volume_key[4];
static int have_volume_serial;
/* The account the box reports. The name is what the system answers for "who am I"; the SID is
   the text form only — the token keeps the real one, so binary comparisons still see the host. */
static WCHAR id_user_name[64];
static WCHAR id_user_sid[64];
/* This computer's NetBIOS name, read before any hook: account lookups report it as the domain
   of local accounts, and only that exact domain is swapped for the derived name. */
static WCHAR host_name[64];
/* The account this box really runs as, read before the account hooks exist. A lookup still has
   to reach it, and what it answers is rewritten on the way out. */
static WCHAR real_user[64];
static char real_user_a[64];
static BYTE real_sid[68];
static DWORD real_sid_size;
static BYTE derived_sid[68];
static DWORD derived_sid_size;

static int have_account(void) { return id_user_name[0] || id_user_sid[0]; }

/* --- settings -------------------------------------------------------------- */

static int hex_digit(WCHAR c) {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}

/* Parses exactly `count` bytes of hex digits and nothing after them. */
static int parse_hex(const WCHAR *text, BYTE *out, int count) {
    int i;
    for (i = 0; i < count; i++) {
        int hi = hex_digit(text[i * 2]), lo;
        if (hi < 0) return 0;
        lo = hex_digit(text[i * 2 + 1]);
        if (lo < 0) return 0;
        out[i] = (BYTE)(hi * 16 + lo);
    }
    return text[count * 2] == 0;
}

static int conf_text(P_QueryConf query_conf, const WCHAR *box, const WCHAR *name, WCHAR *value, DWORD size) {
    value[0] = 0;
    if (!query_conf || query_conf(box, name, 0, value, size) != 0) return 0;
    return value[0] != 0;
}

/* The account the box really runs as, read before any account hook exists: the name from
   GetUserNameW, its SID from LookupAccountNameW (which needs a full-size SID buffer or it
   falsely reports a short one), and the derived SID text converted to binary so a lookup of
   either form can be answered. Nothing here can be done after the hooks are in place. */
static void load_account(HMODULE advapi32) {
    P_GetUserNameW get_user = (P_GetUserNameW)(void *)GetProcAddress(advapi32, "GetUserNameW");
    P_LookupAccountNameW lookup_name = (P_LookupAccountNameW)(void *)GetProcAddress(advapi32, "LookupAccountNameW");
    P_ConvertStringSidToSidW from_text =
        (P_ConvertStringSidToSidW)(void *)GetProcAddress(advapi32, "ConvertStringSidToSidW");
    WCHAR domain[64];
    DWORD size = (DWORD)(sizeof(real_user) / sizeof(real_user[0])), domain_size = 64, sid_size = sizeof(real_sid);
    SID_NAME_USE use = SidTypeUnknown;
    PSID sid = NULL;
    int i;

    /* Neither half is required on its own: the name is what a caller is answered with, the SID is
       what the text form is answered with, and each is skipped when the box does not claim it. */
    if (id_user_name[0] && get_user && get_user(real_user, &size) && real_user[0]) {
        for (i = 0; real_user[i] && i < (int)(sizeof(real_user_a) - 1); i++) real_user_a[i] = (char)real_user[i];
        real_user_a[i] = 0;
    } else {
        real_user[0] = 0;
        real_user_a[0] = 0;
    }
    /* The call reports the capacity it was handed, not the length it wrote, so the length comes
       from the SID itself; a full-size buffer is what makes the call succeed in the first place. */
    if (lookup_name && real_user[0] &&
        lookup_name(NULL, real_user, real_sid, &sid_size, domain, &domain_size, &use) && ((BYTE *)real_sid)[0] == 1)
        real_sid_size = 8 + 4 * (DWORD)((BYTE *)real_sid)[1];
    if (from_text && id_user_sid[0] && from_text(id_user_sid, &sid) && sid) {
        DWORD length = 8 + 4 * (DWORD)((BYTE *)sid)[1];
        if (length <= sizeof(derived_sid)) {
            memcpy(derived_sid, sid, length);
            derived_sid_size = length;
        }
        LocalFree(sid);
    }
}

/* Reads this box's identifiers; without a machine GUID the option is off and nothing is hooked. */
static int load_identity(HMODULE sbie) {
    WCHAR own_box[34], image[96], sid[96], hex[64];
    ULONG session = 0;
    P_QueryProcess query_process = (P_QueryProcess)(void *)GetProcAddress(sbie, "SbieApi_QueryProcess");
    P_QueryConf query_conf = (P_QueryConf)(void *)GetProcAddress(sbie, "SbieApi_QueryConf");
    if (!query_process || query_process((HANDLE)(ULONG_PTR)GetCurrentProcessId(), own_box, image, sid, &session) != 0)
        return 0;
    if (!conf_text(query_conf, own_box, L"HydraMachineGuid", id_machine_guid, sizeof(id_machine_guid))) return 0;
    if (!conf_text(query_conf, own_box, L"HydraHwProfileGuid", id_hw_profile_guid, sizeof(id_hw_profile_guid)))
        id_hw_profile_guid[0] = 0;
    if (!conf_text(query_conf, own_box, L"HydraComputerName", id_computer_name, sizeof(id_computer_name)))
        id_computer_name[0] = 0;
    have_mac = conf_text(query_conf, own_box, L"HydraMac", hex, sizeof(hex)) && parse_hex(hex, id_mac, 6);
    have_volume_serial =
        conf_text(query_conf, own_box, L"HydraVolumeSerial", hex, sizeof(hex)) && parse_hex(hex, id_volume_key, 4);
    if (!conf_text(query_conf, own_box, L"HydraUserName", id_user_name, sizeof(id_user_name))) id_user_name[0] = 0;
    if (!conf_text(query_conf, own_box, L"HydraUserSid", id_user_sid, sizeof(id_user_sid))) id_user_sid[0] = 0;
    return 1;
}

/* --- helpers --------------------------------------------------------------- */

static void hook(P_SbieDll_Hook sbie_hook, HMODULE module, HMODULE self, const char *name, void *detour, void **sys) {
    void *source = module ? (void *)GetProcAddress(module, name) : NULL;
    if (source) *sys = sbie_hook(name, source, detour, self);
}

/* Hooks `name` in both modules, but the same code only once: when one export forwards to the
   other, GetProcAddress resolves both to one address and a second hook would stack on the first. */
static void hook_pair(P_SbieDll_Hook sbie_hook, HMODULE first, HMODULE second, HMODULE self, const char *name,
                      void *detour, void **sys_a, void **sys_b) {
    void *a = first ? (void *)GetProcAddress(first, name) : NULL;
    void *b = second ? (void *)GetProcAddress(second, name) : NULL;
    if (a) *sys_a = sbie_hook(name, a, detour, self);
    if (b && b != a) *sys_b = sbie_hook(name, b, detour, self);
}

static WCHAR upper_w(WCHAR c) { return (c >= L'a' && c <= L'z') ? (WCHAR)(c - 32) : c; }

/* Case-insensitive (ASCII) equality of a counted string with a terminated one. */
static int same_text(const WCHAR *text, int chars, const WCHAR *other) {
    int i;
    for (i = 0; i < chars; i++) {
        if (!other[i] || upper_w(text[i]) != upper_w(other[i])) return 0;
    }
    return other[chars] == 0;
}

/* Case-insensitive comparison of the last `chars` characters of `text` with `suffix`. */
static int tail_is(const WCHAR *text, int chars, const WCHAR *suffix) {
    int length = (int)lstrlenW(suffix), i;
    if (chars < length) return 0;
    for (i = 0; i < length; i++) {
        if (upper_w(text[chars - length + i]) != upper_w(suffix[i])) return 0;
    }
    return 1;
}

/* The identity value kept under the open `key`, if it is one of the keys Hydra answers for:
   `*value` gets the value's name and the result is the text to report. NtQueryKey names the key
   as the system sees it, so paths through Wow6432Node, ControlSet001 or the box's own copy all
   end the same way. */
static const WCHAR *identity_key(HANDLE key, const WCHAR **value) {
    struct {
        ULONG name_length; /* KEY_NAME_INFORMATION: the length comes first, then the name. */
        WCHAR name[300];
    } info;
    ULONG length = 0;
    int chars;
    if (!sys_NtQueryKey || !key || (ULONG_PTR)key >= 0x80000000) return NULL;
    info.name_length = 0;
    if (sys_NtQueryKey(key, 3 /* KeyNameInformation */, &info, sizeof(info), &length) != 0) return NULL;
    if (info.name_length == 0 || info.name_length >= sizeof(info.name)) return NULL;
    chars = (int)(info.name_length / sizeof(WCHAR));
    if (id_machine_guid[0] && tail_is(info.name, chars, L"\\Microsoft\\Cryptography")) {
        *value = L"MachineGuid";
        return id_machine_guid;
    }
    if (id_hw_profile_guid[0] && tail_is(info.name, chars, L"\\Hardware Profiles\\0001")) {
        *value = L"HwProfileGuid";
        return id_hw_profile_guid;
    }
    /* hostname.exe prints this value instead of calling GetComputerName, so it needs answering too. */
    if (id_computer_name[0] && tail_is(info.name, chars, L"\\Services\\Tcpip\\Parameters")) {
        *value = L"Hostname";
        return id_computer_name;
    }
    return NULL;
}

static int is_identity_name(const WCHAR *name, int chars) {
    return same_text(name, chars, L"MachineGuid") || same_text(name, chars, L"HwProfileGuid") ||
           same_text(name, chars, L"Hostname");
}

/* Writes a REG_SZ value in the layout of `info_class`, with the status and length the kernel
   gives for that buffer size: too small for the fixed part, too small for the whole answer
   (fixed part written), or complete. */
static NTSTATUS answer_value(ULONG info_class, const WCHAR *name, ULONG name_bytes, const WCHAR *text, PVOID info,
                             ULONG length, PULONG result) {
    ULONG data_bytes = ((ULONG)lstrlenW(text) + 1) * sizeof(WCHAR);
    BYTE *out = (BYTE *)info;
    ULONG fixed, data_at, need;
    switch (info_class) {
    case 2: /* KeyValuePartialInformation: TitleIndex, Type, DataLength, Data */
    case 4: /* KeyValuePartialInformationAlign64: Type, DataLength, Data */
        fixed = info_class == 2 ? 12 : 8;
        need = fixed + data_bytes;
        if (result) *result = need;
        if (length < fixed) return HYDRA_STATUS_BUFFER_TOO_SMALL;
        if (info_class == 2) {
            ((ULONG *)out)[0] = 0;
            ((ULONG *)out)[1] = REG_SZ;
            ((ULONG *)out)[2] = data_bytes;
        } else {
            ((ULONG *)out)[0] = REG_SZ;
            ((ULONG *)out)[1] = data_bytes;
        }
        if (length < need) return HYDRA_STATUS_BUFFER_OVERFLOW;
        memcpy(out + fixed, text, data_bytes);
        return 0;
    case 1: /* KeyValueFullInformation: TitleIndex, Type, DataOffset, DataLength, NameLength, Name */
    case 3: /* KeyValueFullInformationAlign64 */
        fixed = 20;
        data_at = (fixed + name_bytes + 7) & ~7u;
        need = data_at + data_bytes;
        if (result) *result = need;
        if (length < fixed) return HYDRA_STATUS_BUFFER_TOO_SMALL;
        ((ULONG *)out)[0] = 0;
        ((ULONG *)out)[1] = REG_SZ;
        ((ULONG *)out)[2] = data_at;
        ((ULONG *)out)[3] = data_bytes;
        ((ULONG *)out)[4] = name_bytes;
        if (length < need) return HYDRA_STATUS_BUFFER_OVERFLOW;
        memmove(out + fixed, name, name_bytes);
        memcpy(out + data_at, text, data_bytes);
        return 0;
    }
    return -1;
}

/* FNV-1a over `key || tag || data`, finished with the murmur3 avalanche. Must match
   `identity.rs::derive` byte for byte; keyed so that relations between two derived values (the
   XOR of two volumes' serials, two adapters' addresses) differ between accounts. */
static DWORD derive(const BYTE *key, int key_len, BYTE tag, const BYTE *data, int len) {
    DWORD hash = 2166136261u;
    int i;
    for (i = 0; i < key_len; i++) hash = (hash ^ key[i]) * 16777619u;
    hash = (hash ^ tag) * 16777619u;
    for (i = 0; i < len; i++) hash = (hash ^ data[i]) * 16777619u;
    hash ^= hash >> 16;
    hash *= 0x85ebca6bu;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35u;
    return hash ^ (hash >> 16);
}

/* The serial this box reports for the volume whose real serial is `host`. Keyed on the real
   serial rather than on a path: at this level only the volume is known, and every route to one
   volume (drive letter, NULL root, mount point, file handle) then agrees. */
static DWORD volume_serial(DWORD host) {
    BYTE data[4];
    data[0] = (BYTE)(host >> 24);
    data[1] = (BYTE)(host >> 16);
    data[2] = (BYTE)(host >> 8);
    data[3] = (BYTE)host;
    return derive(id_volume_key, 4, 'V', data, 4);
}

static ULONGLONG volume_serial64(ULONGLONG host) {
    BYTE data[8];
    int i;
    for (i = 0; i < 8; i++) data[i] = (BYTE)(host >> (56 - i * 8));
    /* The low half is the 32-bit serial `vol` prints, as on NTFS; the high half is keyed apart. */
    return ((ULONGLONG)derive(id_volume_key, 4, 'H', data, 8) << 32) | volume_serial((DWORD)host);
}

/* An adapter's address from its GUID name (`{...}`): the account's three-byte prefix plus three
   bytes keyed on the adapter itself. The same adapter then has the same address through every
   API and across reboots, whatever order adapters are listed in or whether a VPN came and went. */
static void adapter_mac(const char *name, BYTE out[6]) {
    BYTE text[64];
    int length = 0;
    DWORD mix;
    if (name) {
        while (*name && *name != '{') name++;
        for (; name[0] && length < (int)sizeof(text); name++) {
            char c = name[0];
            text[length++] = (BYTE)((c >= 'a' && c <= 'z') ? c - 32 : c);
            if (c == '}') break;
        }
    }
    mix = derive(id_mac, 6, 'M', text, length);
    out[0] = id_mac[0];
    out[1] = id_mac[1];
    out[2] = id_mac[2];
    out[3] = (BYTE)(mix >> 24);
    out[4] = (BYTE)(mix >> 16);
    out[5] = (BYTE)(mix >> 8);
}

/* Values with no host value to key them on (SMBIOS serials, the system UUID, a disk's serial)
   are keyed on the account's machine GUID text, which is already per account and stable. */
static int seed_key(BYTE *out, int capacity) {
    int i;
    for (i = 0; i < capacity && i < 36 && id_machine_guid[i]; i++) out[i] = (BYTE)id_machine_guid[i];
    return i;
}

/* A serial of the host serial's own length, drawn from the characters serials are printed with.
   Both callers rewrite in place, where a different length would move everything after it. */
static void rewrite_serial(char *text, int length, BYTE tag) {
    static const char alphabet[] = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    char host[128];
    BYTE key[36];
    int key_len = seed_key(key, sizeof(key)), i;
    if (!text || length <= 0 || key_len <= 0) return;
    if (length > (int)sizeof(host)) length = (int)sizeof(host);
    memcpy(host, text, (size_t)length);
    for (i = 0; i < length; i++) {
        DWORD mix = derive(key, key_len, (BYTE)(tag + i), (const BYTE *)host, length);
        text[i] = alphabet[mix % (sizeof(alphabet) - 1)];
    }
}

/* The table `GetSystemFirmwareTable('RSMB')` returns: RawSMBIOSData, an 8-byte header and then the
   structures. A structure's size is the first length byte, and its strings follow the fixed part
   up to a double NUL. Serial numbers and the system UUID are rewritten in place, so lengths,
   offsets and checksums stay exactly as the system wrote them. */
static DWORD smbios_end(const BYTE *table, DWORD at, DWORD length) {
    DWORD pos = at + table[at + 1];
    while (pos + 1 < length) {
        if (table[pos] == 0 && table[pos + 1] == 0) return pos + 2;
        pos++;
    }
    return length;
}

static char *smbios_string(const BYTE *table, DWORD at, DWORD end, int index) {
    DWORD pos = at + table[at + 1];
    int i;
    if (index < 1) return NULL;
    for (i = 1; i <= index; i++) {
        if (pos >= end) return NULL;
        if (i == index) return (char *)(table + pos);
        while (pos < end && table[pos]) pos++;
        pos++;
    }
    return NULL;
}

/* The field that names a structure's own serial, by structure type: SMBIOS puts it at a different
   offset in each one, and a serial is the only string there is any reason to change. Type 3
   (chassis) is not listed on purpose: its serial usually repeats the system serial, which the
   second pass below catches by value, and this machine's table does not put the fields where the
   specification says they are. */
static int serial_field(BYTE type) {
    switch (type) {
        case 1: return 0x07;  /* System: serial (what Win32_BIOS reports) */
        case 2: return 0x07;  /* Baseboard: board serial */
        case 17: return 0x18; /* Memory device: module serial */
        default: return 0;
    }
}

/* A string in the structure's string set: how long it is, bounded by the set's end. */
static int smbios_text_length(const char *text, const char *limit) {
    int chars = 0;
    while (text + chars < limit && text[chars]) chars++;
    return chars;
}

/* The table `GetSystemFirmwareTable('RSMB')` returns: RawSMBIOSData, an 8-byte header and then the
   structures. A structure's fixed part starts with its type and length; its strings follow up to a
   double NUL. Everything is rewritten in place at its original length, so offsets and checksums
   stay exactly as the system wrote them. Two passes: the first derives the serials it finds where
   the specification puts them, and the second replaces any string holding one of those values -
   vendors repeat the system serial in the chassis and elsewhere, and one leftover copy is a leak. */
static void rewrite_smbios(BYTE *table, DWORD length) {
#define HYDRA_SMB_SERIALS 6
    char host[HYDRA_SMB_SERIALS][64], derived[HYDRA_SMB_SERIALS][64];
    int host_length[HYDRA_SMB_SERIALS];
    int count = 0, pass, i;
    BYTE key[36];
    int key_len = seed_key(key, sizeof(key));
    DWORD checksum_at = 0, checksum_end = 0;
    if (key_len <= 0) return;
    for (pass = 0; pass < 2; pass++) {
        DWORD at = 8;
        while (at + 2 <= length && (DWORD)at + table[at + 1] <= length) {
            BYTE type = table[at], size = table[at + 1];
            DWORD end = smbios_end(table, at, length);
            char *limit = (char *)table + end;
            int field = serial_field(type);
            if (pass == 0 && field && size > field) {
                char *serial = smbios_string(table, at, end, table[at + field]);
                int chars = serial ? smbios_text_length(serial, limit) : 0;
                if (chars >= 3 && chars < (int)sizeof(host[0]) && count < HYDRA_SMB_SERIALS) {
                    memcpy(host[count], serial, (size_t)chars);
                    host_length[count] = chars;
                    memcpy(derived[count], serial, (size_t)chars);
                    rewrite_serial(derived[count], chars, 'S');
                    memcpy(serial, derived[count], (size_t)chars);
                    count++;
                }
            } else if (pass == 1) {
                DWORD pos = at + size;
                while (pos < end && table[pos]) {
                    char *text = (char *)table + pos;
                    int chars = smbios_text_length(text, limit);
                    for (i = 0; i < count; i++) {
                        if (chars == host_length[i] && memcmp(text, host[i], (size_t)chars) == 0)
                            memcpy(text, derived[i], (size_t)chars);
                    }
                    pos += (DWORD)chars + 1;
                }
                if (type == 1 && size > 0x17) {
                    BYTE uuid[16];
                    memcpy(uuid, table + at + 8, 16);
                    for (i = 0; i < 4; i++) {
                        DWORD mix = derive(key, key_len, (BYTE)('U' + i), uuid, 16);
                        table[at + 8 + i * 4 + 0] = (BYTE)(mix >> 24);
                        table[at + 8 + i * 4 + 1] = (BYTE)(mix >> 16);
                        table[at + 8 + i * 4 + 2] = (BYTE)(mix >> 8);
                        table[at + 8 + i * 4 + 3] = (BYTE)mix;
                    }
                    /* The SMBIOS UUID is a GUID in memory order, so the version nibble (the high
                       nibble of the canonical string's third group) is byte 7, and the variant is
                       byte 8. */
                    table[at + 8 + 7] = (BYTE)((table[at + 8 + 7] & 0x0f) | 0x40);
                    table[at + 8 + 8] = (BYTE)((table[at + 8 + 8] & 0x3f) | 0x80);
                }
                /* A table that carries an end-of-table checksum has it covering the whole table,
                   strings included: those just changed, so it is recomputed last. Firmware that
                   omits the field (this machine's table ends with a four-byte Type 127) has
                   nothing to fix. */
                if (type == 127 && size > 4) {
                    checksum_at = at + 4;
                    checksum_end = (DWORD)at + size;
                }
            }
            at = end;
            if (type == 127) break;
        }
    }
    if (checksum_at && checksum_end > 8) {
        BYTE sum = 0;
        DWORD at;
        table[checksum_at] = 0;
        for (at = 8; at < checksum_end; at++) sum = (BYTE)(sum + table[at]);
        table[checksum_at] = (BYTE)(0x100 - sum);
    }
#undef HYDRA_SMB_SERIALS
}

static void guid_name(const GUID *id, char out[40]) {
    static const char digits[] = "0123456789ABCDEF";
    BYTE bytes[16];
    int i, at = 0;
    bytes[0] = (BYTE)(id->Data1 >> 24);
    bytes[1] = (BYTE)(id->Data1 >> 16);
    bytes[2] = (BYTE)(id->Data1 >> 8);
    bytes[3] = (BYTE)id->Data1;
    bytes[4] = (BYTE)(id->Data2 >> 8);
    bytes[5] = (BYTE)id->Data2;
    bytes[6] = (BYTE)(id->Data3 >> 8);
    bytes[7] = (BYTE)id->Data3;
    for (i = 0; i < 8; i++) bytes[8 + i] = id->Data4[i];
    out[at++] = '{';
    for (i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[at++] = '-';
        out[at++] = digits[bytes[i] >> 4];
        out[at++] = digits[bytes[i] & 15];
    }
    out[at++] = '}';
    out[at] = 0;
}

static void wide_guid_name(const WCHAR *text, char out[40]) {
    int i = 0;
    while (*text && *text != L'{') text++;
    for (; text[0] && i < 39; text++) {
        out[i++] = (char)text[0];
        if (text[0] == L'}') break;
    }
    out[i] = 0;
}

static void rewrite_row2(PMIB_IF_ROW2 row) {
    char name[40];
    if (row->PhysicalAddressLength != 6) return;
    guid_name(&row->InterfaceGuid, name);
    adapter_mac(name, row->PhysicalAddress);
    if (row->PermanentPhysicalAddress[0] | row->PermanentPhysicalAddress[1] | row->PermanentPhysicalAddress[2] |
        row->PermanentPhysicalAddress[3] | row->PermanentPhysicalAddress[4] | row->PermanentPhysicalAddress[5])
        memcpy(row->PermanentPhysicalAddress, row->PhysicalAddress, 6);
}

static void rewrite_row(PMIB_IFROW row) {
    char name[40];
    if (row->dwPhysAddrLen != 6) return;
    wide_guid_name(row->wszName, name);
    adapter_mac(name, row->bPhysAddr);
}

static BOOL answer_name_w(const WCHAR *name, LPWSTR buffer, LPDWORD size) {
    DWORD need = (DWORD)lstrlenW(name) + 1;
    if (!size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!buffer || *size < need) {
        *size = need;
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    memcpy(buffer, name, need * sizeof(WCHAR));
    *size = need - 1;
    return TRUE;
}

static BOOL answer_name_a(const WCHAR *name, LPSTR buffer, LPDWORD size) {
    DWORD length = (DWORD)lstrlenW(name), need = length + 1, i;
    if (!size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!buffer || *size < need) {
        *size = need;
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    /* The derived names are ASCII, so narrowing cannot lose anything. */
    for (i = 0; i < length; i++) buffer[i] = (CHAR)name[i];
    buffer[length] = 0;
    *size = length;
    return TRUE;
}

static int is_host_w(const WCHAR *text, int chars) { return host_name[0] && same_text(text, chars, host_name); }

static int is_host_a(const char *text, int chars) {
    int i;
    if (!host_name[0]) return 0;
    for (i = 0; i < chars; i++) {
        if (!host_name[i] || upper_w((WCHAR)(BYTE)text[i]) != upper_w(host_name[i])) return 0;
    }
    return host_name[chars] == 0;
}

/* After a successful account lookup: a local account's domain is the computer name, which is
   swapped for the derived one. `capacity` is what the caller offered; if the derived name does
   not fit, the call fails the way the system's does, asking for the size it needs. */
static BOOL swap_domain_w(LPWSTR domain, LPDWORD domain_size, DWORD capacity) {
    DWORD length = (DWORD)lstrlenW(id_computer_name);
    if (!id_computer_name[0] || !domain || !domain_size || !is_host_w(domain, (int)*domain_size)) return TRUE;
    if (capacity < length + 1) {
        *domain_size = length + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memcpy(domain, id_computer_name, (length + 1) * sizeof(WCHAR));
    *domain_size = length;
    return TRUE;
}

static BOOL swap_domain_a(LPSTR domain, LPDWORD domain_size, DWORD capacity) {
    DWORD length = (DWORD)lstrlenW(id_computer_name), i;
    if (!id_computer_name[0] || !domain || !domain_size || !is_host_a(domain, (int)*domain_size)) return TRUE;
    if (capacity < length + 1) {
        *domain_size = length + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    for (i = 0; i <= length; i++) domain[i] = (CHAR)id_computer_name[i];
    *domain_size = length;
    return TRUE;
}

/* A size probe asks for the host's length; the derived name may be longer. */
static void grow_domain_size(LPDWORD domain_size) {
    DWORD need = (DWORD)lstrlenW(id_computer_name) + 1;
    if (domain_size && GetLastError() == ERROR_INSUFFICIENT_BUFFER && *domain_size < need) *domain_size = need;
}

static void grow_name_size(LPDWORD name_size) {
    DWORD need = (DWORD)lstrlenW(id_user_name) + 1;
    if (name_size && GetLastError() == ERROR_INSUFFICIENT_BUFFER && id_user_name[0] && *name_size < need)
        *name_size = need;
}

/* Case-insensitive (ASCII) equality of a counted narrow string with a terminated wide one. */
static int same_text_a(const char *text, int chars, const WCHAR *other) {
    int i;
    for (i = 0; i < chars; i++) {
        if (!other[i] || upper_w((WCHAR)(BYTE)text[i]) != upper_w(other[i])) return 0;
    }
    return other[chars] == 0;
}

/* After a successful lookup: the account's own name is swapped for the derived one. The size it
   reports on success does not count the terminator, and a short buffer fails asking for one. */
static BOOL swap_name_w(LPWSTR name, LPDWORD name_size, DWORD capacity) {
    DWORD length;
    if (!name || !name_size || !id_user_name[0] || !real_user[0]) return TRUE;
    if (!same_text(name, (int)*name_size, real_user)) return TRUE;
    length = (DWORD)lstrlenW(id_user_name);
    if (capacity < length + 1) {
        *name_size = length + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memcpy(name, id_user_name, (length + 1) * sizeof(WCHAR));
    *name_size = length;
    return TRUE;
}

static BOOL swap_name_a(LPSTR name, LPDWORD name_size, DWORD capacity) {
    DWORD length = (DWORD)lstrlenW(id_user_name), i;
    if (!name || !name_size || !id_user_name[0] || !real_user[0]) return TRUE;
    if (!same_text_a(name, (int)*name_size, real_user)) return TRUE;
    if (capacity < length + 1) {
        *name_size = length + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    for (i = 0; i <= length; i++) name[i] = (CHAR)id_user_name[i];
    *name_size = length;
    return TRUE;
}

/* The same `LookupAccount*` contract, for a name this DLL answers itself. */
static BOOL fill_text_w(const WCHAR *text, LPWSTR buffer, LPDWORD size, DWORD capacity) {
    DWORD length = (DWORD)lstrlenW(text);
    if (!size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!buffer || capacity < length + 1) {
        *size = length + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memcpy(buffer, text, (length + 1) * sizeof(WCHAR));
    *size = length;
    return TRUE;
}

static BOOL fill_text_a(const WCHAR *text, LPSTR buffer, LPDWORD size, DWORD capacity) {
    DWORD length = (DWORD)lstrlenW(text), i;
    if (!size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!buffer || capacity < length + 1) {
        *size = length + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    for (i = 0; i <= length; i++) buffer[i] = (CHAR)text[i];
    *size = length;
    return TRUE;
}

/* `GetUserName*` counts the terminator in the size it reports, unlike every `LookupAccount*`
   call above, so its answer is filled by its own pair rather than through fill_text_*. */
static BOOL fill_user_w(const WCHAR *text, LPWSTR buffer, LPDWORD size, DWORD capacity) {
    DWORD length = (DWORD)lstrlenW(text);
    if (!size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!buffer || capacity < length + 1) {
        *size = length + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memcpy(buffer, text, (length + 1) * sizeof(WCHAR));
    *size = length + 1;
    return TRUE;
}

static BOOL fill_user_a(const WCHAR *text, LPSTR buffer, LPDWORD size, DWORD capacity) {
    DWORD length = (DWORD)lstrlenW(text), i;
    if (!size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!buffer || capacity < length + 1) {
        *size = length + 1;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    for (i = 0; i <= length; i++) buffer[i] = (CHAR)text[i];
    *size = length + 1;
    return TRUE;
}

/* The box claims one SID: the token's own, and the text Hydra derived, which is a real SID shape
   and is answered as if it were the account's. Every other SID is the caller's business. */
static int is_sid_named(const BYTE *sid, const BYTE *own, DWORD own_size) {
    DWORD length;
    if (!sid || !own_size || sid[0] != 1 || sid[1] > 15) return 0;
    length = 8 + 4 * (DWORD)sid[1];
    return length == own_size && memcmp(sid, own, length) == 0;
}

/* The derived SID has no account behind it, so the system cannot answer a lookup for it. */
static int is_derived_sid(const BYTE *sid) { return is_sid_named(sid, derived_sid, derived_sid_size); }

static int is_own_sid(const BYTE *sid) {
    return is_sid_named(sid, real_sid, real_sid_size) || is_derived_sid(sid);
}

/* A name lookup answers with the SID of the account it resolved; the box hands back the one it
   claims instead. Both are the same length, so a buffer the caller made large enough still is.
   What the caller's buffer holds decides, not the capacity it offered: the system reports the
   capacity back, so that number says nothing about the length of the SID inside. */
static BOOL swap_sid(PSID sid, LPDWORD sid_size, DWORD capacity) {
    if (!sid || !sid_size || !real_sid_size || !derived_sid_size) return TRUE;
    if (!is_own_sid((const BYTE *)sid)) return TRUE;
    if (capacity < derived_sid_size) {
        *sid_size = derived_sid_size;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memcpy(sid, derived_sid, derived_sid_size);
    return TRUE;
}

/* The derived SID has no account behind it, so the system cannot answer for it: this DLL does. */
static BOOL answer_own_sid_w(LPWSTR name, LPDWORD name_size, LPWSTR domain, LPDWORD domain_size,
                             PSID_NAME_USE use) {
    DWORD name_capacity = name_size ? *name_size : 0, domain_capacity = domain_size ? *domain_size : 0;
    if (!fill_text_w(id_user_name, name, name_size, name_capacity)) return FALSE;
    if (!fill_text_w(id_computer_name[0] ? id_computer_name : host_name, domain, domain_size, domain_capacity))
        return FALSE;
    if (use) *use = SidTypeUser;
    return TRUE;
}

static BOOL answer_own_sid_a(LPSTR name, LPDWORD name_size, LPSTR domain, LPDWORD domain_size,
                             PSID_NAME_USE use) {
    DWORD name_capacity = name_size ? *name_size : 0, domain_capacity = domain_size ? *domain_size : 0;
    if (!fill_text_a(id_user_name, name, name_size, name_capacity)) return FALSE;
    if (!fill_text_a(id_computer_name[0] ? id_computer_name : host_name, domain, domain_size, domain_capacity))
        return FALSE;
    if (use) *use = SidTypeUser;
    return TRUE;
}

/* The name a lookup is for, with any domain in front removed: a local account is accepted with
   the computer name in front of it, and the box accepts any domain for its own name. */
static LPCWSTR bare_name_w(LPCWSTR account) {
    LPCWSTR name;
    if (!account) return NULL;
    for (name = account; *name && *name != L'\\'; name++) {
    }
    return *name ? name + 1 : account;
}

static LPCSTR bare_name_a(LPCSTR account) {
    LPCSTR name;
    if (!account) return NULL;
    for (name = account; *name && *name != '\\'; name++) {
    }
    return *name ? name + 1 : account;
}

static int name_is_derived_w(LPCWSTR account) {
    LPCWSTR name = bare_name_w(account);
    return name && id_user_name[0] && same_text(name, (int)lstrlenW(name), id_user_name);
}

static int name_is_derived_a(LPCSTR account) {
    LPCSTR name = bare_name_a(account);
    int chars;
    if (!name || !id_user_name[0]) return 0;
    for (chars = 0; name[chars]; chars++) {
    }
    return same_text_a(name, chars, id_user_name);
}

/* The derived name has no account behind it either, so the system would answer that it cannot be
   mapped. The box answers with the SID it claims, under the system's contract: the size on
   success is the one the caller offered, and a short buffer asks for the size it needs. */
static BOOL answer_sid_w(PSID sid, LPDWORD sid_size, LPWSTR domain, LPDWORD domain_size, PSID_NAME_USE use) {
    DWORD capacity = sid_size ? *sid_size : 0, domain_capacity = domain_size ? *domain_size : 0;
    if (!sid_size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!sid || capacity < derived_sid_size) {
        *sid_size = derived_sid_size;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memcpy(sid, derived_sid, derived_sid_size);
    if (!fill_text_w(id_computer_name[0] ? id_computer_name : host_name, domain, domain_size, domain_capacity))
        return FALSE;
    if (use) *use = SidTypeUser;
    return TRUE;
}

static BOOL answer_sid_a(PSID sid, LPDWORD sid_size, LPSTR domain, LPDWORD domain_size, PSID_NAME_USE use) {
    DWORD capacity = sid_size ? *sid_size : 0, domain_capacity = domain_size ? *domain_size : 0;
    if (!sid_size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!sid || capacity < derived_sid_size) {
        *sid_size = derived_sid_size;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memcpy(sid, derived_sid, derived_sid_size);
    if (!fill_text_a(id_computer_name[0] ? id_computer_name : host_name, domain, domain_size, domain_capacity))
        return FALSE;
    if (use) *use = SidTypeUser;
    return TRUE;
}

/* userenv names the account in order to open its profile directory, and the profile behind the
   host's account is the one that exists. Answering that one question with the derived account
   points it at a directory that is not there, and `GetUserProfileDirectoryW` then fails with the
   size still zero - which is what Node's `os.userInfo()` reports as out of memory. The system
   component therefore gets the host's own answer, and only its own calls: everything else still
   sees the box's account. */
static int from_userenv(void *caller) {
    static HMODULE userenv;
    void *base = NULL;
    if (!userenv) userenv = GetModuleHandleW(L"userenv.dll");
    if (!userenv || !sys_RtlPcToFileHeader || !caller) return 0;
    return sys_RtlPcToFileHeader(caller, &base) && base == (void *)userenv;
}

/* --- detours: registry ------------------------------------------------------ */
static NTSTATUS NTAPI my_NtQueryValueKey(HANDLE key, PUNICODE_STRING name, ULONG info_class, PVOID info,
                                         ULONG length, PULONG result) {
    const WCHAR *value = NULL, *text;
    /* The value name is compared first: it is cheap, and almost every query is for another value. */
    if (info_class >= 1 && info_class <= 4 && name && name->Buffer &&
        is_identity_name(name->Buffer, name->Length / sizeof(WCHAR))) {
        text = identity_key(key, &value);
        if (text && same_text(name->Buffer, name->Length / sizeof(WCHAR), value))
            return answer_value(info_class, name->Buffer, name->Length, text, info, length, result);
    }
    return sys_NtQueryValueKey(key, name, info_class, info, length, result);
}

/* `reg query <key>` without /v lists every value by index; the identity value must not come
   through with the host's data that way. */
static NTSTATUS NTAPI my_NtEnumerateValueKey(HANDLE key, ULONG index, ULONG info_class, PVOID info, ULONG length,
                                             PULONG result) {
    NTSTATUS status = sys_NtEnumerateValueKey(key, index, info_class, info, length, result);
    const WCHAR *value = NULL, *text;
    struct {
        ULONG title_index, type, name_length; /* KEY_VALUE_BASIC_INFORMATION */
        WCHAR name[64];
    } basic;
    ULONG basic_length = 0;
    if (info_class < 1 || info_class > 4) return status;
    if (!NT_SUCCESS(status) && status != HYDRA_STATUS_BUFFER_OVERFLOW && status != HYDRA_STATUS_BUFFER_TOO_SMALL)
        return status;
    text = identity_key(key, &value);
    if (!text) return status;
    /* The name by index, from the basic class: the partial classes carry no name at all. */
    if (sys_NtEnumerateValueKey(key, index, 0, &basic, sizeof(basic), &basic_length) != 0) return status;
    if (!same_text(basic.name, (int)(basic.name_length / sizeof(WCHAR)), value)) return status;
    return answer_value(info_class, basic.name, basic.name_length, text, info, length, result);
}

/* --- detours: volumes ------------------------------------------------------- */

static NTSTATUS NTAPI my_NtQueryVolumeInformationFile(HANDLE file, PIO_STATUS_BLOCK io, PVOID info, ULONG length,
                                                      ULONG info_class) {
    NTSTATUS status = sys_NtQueryVolumeInformationFile(file, io, info, length, info_class);
    /* FileFsVolumeInformation: VolumeCreationTime (8 bytes), then VolumeSerialNumber. A label
       that does not fit still leaves the fixed part filled in. */
    if (info_class == 1 && info && length >= 12 && (NT_SUCCESS(status) || status == HYDRA_STATUS_BUFFER_OVERFLOW)) {
        DWORD *serial = (DWORD *)((BYTE *)info + 8);
        *serial = volume_serial(*serial);
    }
    return status;
}

/* The file information classes that carry the volume's serial, rewritten the same way whether
   the file was reached by handle or by name:
     - FileIdInformation (59): the 64-bit VolumeSerialNumber comes first;
     - FileStatBasicInformation (77, Windows 11 24H2+): VolumeSerialNumber at offset 80, the same
       64-bit value FileIdInformation reports. GetFileInformationByName(FileStatBasicByNameInfo)
       ends here through NtQueryInformationByName, and libuv's fs.stat() uses it when present while
       fs.fstat() still asks FileFsVolumeInformation; both must agree or Node's same-file checks
       (Claude's "link or placeholder" guard) see two different devices. */
static void rewrite_file_serial(PVOID info, ULONG length, ULONG info_class) {
    if (!info) return;
    if (info_class == 59 && length >= 8) {
        ULONGLONG *serial = (ULONGLONG *)info;
        *serial = volume_serial64(*serial);
    } else if (info_class == 77 && length >= 88) {
        ULONGLONG *serial = (ULONGLONG *)((BYTE *)info + 80);
        *serial = volume_serial64(*serial);
    }
}

static NTSTATUS NTAPI my_NtQueryInformationFile(HANDLE file, PIO_STATUS_BLOCK io, PVOID info, ULONG length,
                                                ULONG info_class) {
    NTSTATUS status = sys_NtQueryInformationFile(file, io, info, length, info_class);
    if (NT_SUCCESS(status)) rewrite_file_serial(info, length, info_class);
    return status;
}

static NTSTATUS NTAPI my_NtQueryInformationByName(POBJECT_ATTRIBUTES name, PIO_STATUS_BLOCK io, PVOID info,
                                                  ULONG length, ULONG info_class) {
    NTSTATUS status = sys_NtQueryInformationByName(name, io, info, length, info_class);
    if (NT_SUCCESS(status)) rewrite_file_serial(info, length, info_class);
    return status;
}

/* --- detours: adapters ------------------------------------------------------ */

static ULONG WINAPI my_GetAdaptersAddresses(ULONG family, ULONG flags, PVOID reserved,
                                            PIP_ADAPTER_ADDRESSES addresses, PULONG size) {
    ULONG result = sys_GetAdaptersAddresses(family, flags, reserved, addresses, size);
    PIP_ADAPTER_ADDRESSES adapter;
    if (result != NO_ERROR || !addresses) return result;
    for (adapter = addresses; adapter; adapter = adapter->Next) {
        if (adapter->PhysicalAddressLength != 6) continue;
        adapter_mac(adapter->AdapterName, adapter->PhysicalAddress);
    }
    return result;
}

static ULONG WINAPI my_GetAdaptersInfo(PIP_ADAPTER_INFO adapters, PULONG size) {
    ULONG result = sys_GetAdaptersInfo(adapters, size);
    PIP_ADAPTER_INFO adapter;
    if (result != NO_ERROR || !adapters) return result;
    for (adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->AddressLength != 6) continue;
        adapter_mac(adapter->AdapterName, adapter->Address);
    }
    return result;
}

static DWORD WINAPI my_GetIfTable(PMIB_IFTABLE table, PULONG size, BOOL order) {
    DWORD result = sys_GetIfTable(table, size, order), i;
    if (result == NO_ERROR && table)
        for (i = 0; i < table->dwNumEntries; i++) rewrite_row(&table->table[i]);
    return result;
}

static DWORD WINAPI my_GetIfEntry(PMIB_IFROW row) {
    DWORD result = sys_GetIfEntry(row);
    if (result == NO_ERROR && row) rewrite_row(row);
    return result;
}

static void rewrite_table2(PMIB_IF_TABLE2 table) {
    ULONG i;
    if (table)
        for (i = 0; i < table->NumEntries; i++) rewrite_row2(&table->Table[i]);
}

static DWORD WINAPI my_GetIfTable2(PMIB_IF_TABLE2 *table) {
    DWORD result = sys_GetIfTable2(table);
    if (result == NO_ERROR && table) rewrite_table2(*table);
    return result;
}

static DWORD WINAPI my_GetIfTable2Ex(MIB_IF_TABLE_LEVEL level, PMIB_IF_TABLE2 *table) {
    DWORD result = sys_GetIfTable2Ex(level, table);
    if (result == NO_ERROR && table) rewrite_table2(*table);
    return result;
}

static DWORD WINAPI my_GetIfEntry2(PMIB_IF_ROW2 row) {
    DWORD result = sys_GetIfEntry2(row);
    if (result == NO_ERROR && row) rewrite_row2(row);
    return result;
}

static DWORD WINAPI my_GetIfEntry2Ex(MIB_IF_ENTRY_LEVEL level, PMIB_IF_ROW2 row) {
    DWORD result = sys_GetIfEntry2Ex(level, row);
    if (result == NO_ERROR && row) rewrite_row2(row);
    return result;
}

/* --- detours: firmware and disks ------------------------------------------- */

/* The SMBIOS table is where the board, BIOS and system serial numbers and the product UUID come
   from, and it is a buffer this process owns: rewriting it covers `GetSystemFirmwareTable` as well
   as the tools built on it, while WMI itself stays closed. The size probe asks with no buffer and
   is left alone. */
static UINT WINAPI my_GetSystemFirmwareTable(DWORD provider, DWORD id, PVOID buffer, DWORD size) {
    UINT result = REAL(sys_GetSystemFirmwareTable)(provider, id, buffer, size);
    if (buffer && provider == 'RSMB' && result > 8 && result <= size) rewrite_smbios((BYTE *)buffer, result);
    return result;
}

/* A disk's serial comes back inside the caller's storage descriptor as a NUL-terminated string at
   an offset the descriptor carries. Rewriting it at the same length keeps every offset valid.
   Overlapped calls have no result in the buffer yet, so they are left alone. */
static BOOL WINAPI my_DeviceIoControl(HANDLE device, DWORD code, LPVOID in, DWORD in_size, LPVOID out, DWORD out_size,
                                      LPDWORD returned, LPOVERLAPPED overlapped) {
    BOOL ok = REAL(sys_DeviceIoControl)(device, code, in, in_size, out, out_size, returned, overlapped);
    STORAGE_PROPERTY_QUERY *query = (STORAGE_PROPERTY_QUERY *)in;
    STORAGE_DEVICE_DESCRIPTOR *descriptor = (STORAGE_DEVICE_DESCRIPTOR *)out;
    DWORD offset, limit, chars;
    char *serial;
    if (!ok || overlapped || code != IOCTL_STORAGE_QUERY_PROPERTY || !in || !out || !returned) return ok;
    if (in_size < sizeof(STORAGE_PROPERTY_QUERY) || query->PropertyId != StorageDeviceProperty) return ok;
    if (*returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return ok;
    offset = descriptor->SerialNumberOffset;
    if (!offset || offset >= *returned) return ok;
    serial = (char *)out + offset;
    limit = *returned - offset;
    for (chars = 0; chars < limit && serial[chars]; chars++) {
    }
    if (chars) rewrite_serial(serial, (int)chars, 'D');
    return ok;
}

/* --- detours: computer name ------------------------------------------------- */

/* Every COMPUTER_NAME_FORMAT is answered with the same name: they all describe one machine. */
static BOOL WINAPI my_GetComputerNameExW(COMPUTER_NAME_FORMAT format, LPWSTR buffer, LPDWORD size) {
    if (!id_computer_name[0]) return REAL(sys_GetComputerNameExW)(format, buffer, size);
    return answer_name_w(id_computer_name, buffer, size);
}

static BOOL WINAPI my_GetComputerNameExA(COMPUTER_NAME_FORMAT format, LPSTR buffer, LPDWORD size) {
    if (!id_computer_name[0]) return REAL(sys_GetComputerNameExA)(format, buffer, size);
    return answer_name_a(id_computer_name, buffer, size);
}

static BOOL WINAPI my_GetComputerNameW(LPWSTR buffer, LPDWORD size) {
    if (!id_computer_name[0]) return REAL(sys_GetComputerNameW)(buffer, size);
    return answer_name_w(id_computer_name, buffer, size);
}

static BOOL WINAPI my_GetComputerNameA(LPSTR buffer, LPDWORD size) {
    if (!id_computer_name[0]) return REAL(sys_GetComputerNameA)(buffer, size);
    return answer_name_a(id_computer_name, buffer, size);
}

/* --- detours: account domain ------------------------------------------------ */

/* A local account's domain is the computer name: `whoami` prints `HOST\user`, and .NET's
   UserDomainName reads it the same way. A SID gives back the name too, and that is the derived
   name: the box claims one account, whichever text is handed in. */
static BOOL WINAPI my_LookupAccountSidW(LPCWSTR system, PSID sid, LPWSTR name, LPDWORD name_size, LPWSTR domain,
                                       LPDWORD domain_size, PSID_NAME_USE use) {
    DWORD domain_capacity = domain_size ? *domain_size : 0, name_capacity = name_size ? *name_size : 0;
    BOOL ok;
    /* The derived SID has no account behind it, so the system cannot answer; this DLL does. */
    if (id_user_name[0] && (!system || !system[0]) && is_derived_sid((const BYTE *)sid))
        return answer_own_sid_w(name, name_size, domain, domain_size, use);
    ok = REAL(sys_LookupAccountSidW)(system, sid, name, name_size, domain, domain_size, use);
    if (!ok) {
        grow_domain_size(domain_size);
        return ok;
    }
    if (!swap_name_w(name, name_size, name_capacity)) return FALSE;
    return swap_domain_w(domain, domain_size, domain_capacity);
}

static BOOL WINAPI my_LookupAccountSidA(LPCSTR system, PSID sid, LPSTR name, LPDWORD name_size, LPSTR domain,
                                       LPDWORD domain_size, PSID_NAME_USE use) {
    DWORD domain_capacity = domain_size ? *domain_size : 0, name_capacity = name_size ? *name_size : 0;
    BOOL ok;
    if (id_user_name[0] && (!system || !system[0]) && is_derived_sid((const BYTE *)sid))
        return answer_own_sid_a(name, name_size, domain, domain_size, use);
    ok = REAL(sys_LookupAccountSidA)(system, sid, name, name_size, domain, domain_size, use);
    if (!ok) {
        grow_domain_size(domain_size);
        return ok;
    }
    if (!swap_name_a(name, name_size, name_capacity)) return FALSE;
    return swap_domain_a(domain, domain_size, domain_capacity);
}

/* A name lookup still has to reach the real account: the derived name is turned into the real
   one, the system resolves it, and the SID it answers with becomes the derived one. */
static BOOL WINAPI my_LookupAccountNameW(LPCWSTR system, LPCWSTR account, PSID sid, LPDWORD sid_size, LPWSTR domain,
                                        LPDWORD domain_size, PSID_NAME_USE use) {
    DWORD domain_capacity = domain_size ? *domain_size : 0, sid_capacity = sid_size ? *sid_size : 0;
    BOOL ok;
    if (derived_sid_size && (!system || !system[0]) && name_is_derived_w(account))
        return answer_sid_w(sid, sid_size, domain, domain_size, use);
    ok = REAL(sys_LookupAccountNameW)(system, account, sid, sid_size, domain, domain_size, use);
    if (!ok) {
        grow_domain_size(domain_size);
        return ok;
    }
    if (!swap_sid(sid, sid_size, sid_capacity)) return FALSE;
    return swap_domain_w(domain, domain_size, domain_capacity);
}

static BOOL WINAPI my_LookupAccountNameA(LPCSTR system, LPCSTR account, PSID sid, LPDWORD sid_size, LPSTR domain,
                                        LPDWORD domain_size, PSID_NAME_USE use) {
    DWORD domain_capacity = domain_size ? *domain_size : 0, sid_capacity = sid_size ? *sid_size : 0;
    BOOL ok;
    if (derived_sid_size && (!system || !system[0]) && name_is_derived_a(account))
        return answer_sid_a(sid, sid_size, domain, domain_size, use);
    ok = REAL(sys_LookupAccountNameA)(system, account, sid, sid_size, domain, domain_size, use);
    if (!ok) {
        grow_domain_size(domain_size);
        return ok;
    }
    if (!swap_sid(sid, sid_size, sid_capacity)) return FALSE;
    return swap_domain_a(domain, domain_size, domain_capacity);
}

/* `LookupAccountSidLocal` and `LookupAccountNameLocal` are the same lookups without the system
   parameter, exported only by sechost. .NET's account APIs go through them, and a hook on
   advapi32 alone would leave every one of them reporting the host. They call their own
   implementation, not advapi32's, so they need their own detours and their own trampolines. */
static BOOL WINAPI my_LookupAccountSidLocalW(PSID sid, LPWSTR name, LPDWORD name_size, LPWSTR domain,
                                             LPDWORD domain_size, PSID_NAME_USE use) {
    DWORD domain_capacity = domain_size ? *domain_size : 0, name_capacity = name_size ? *name_size : 0;
    BOOL ok;
    if (id_user_name[0] && is_derived_sid((const BYTE *)sid))
        return answer_own_sid_w(name, name_size, domain, domain_size, use);
    ok = sys_LookupAccountSidLocalW(sid, name, name_size, domain, domain_size, use);
    if (!ok) {
        grow_domain_size(domain_size);
        return ok;
    }
    if (!swap_name_w(name, name_size, name_capacity)) return FALSE;
    return swap_domain_w(domain, domain_size, domain_capacity);
}

static BOOL WINAPI my_LookupAccountSidLocalA(PSID sid, LPSTR name, LPDWORD name_size, LPSTR domain,
                                             LPDWORD domain_size, PSID_NAME_USE use) {
    DWORD domain_capacity = domain_size ? *domain_size : 0, name_capacity = name_size ? *name_size : 0;
    BOOL ok;
    if (id_user_name[0] && is_derived_sid((const BYTE *)sid))
        return answer_own_sid_a(name, name_size, domain, domain_size, use);
    ok = sys_LookupAccountSidLocalA(sid, name, name_size, domain, domain_size, use);
    if (!ok) {
        grow_domain_size(domain_size);
        return ok;
    }
    if (!swap_name_a(name, name_size, name_capacity)) return FALSE;
    return swap_domain_a(domain, domain_size, domain_capacity);
}

static BOOL WINAPI my_LookupAccountNameLocalW(LPCWSTR account, PSID sid, LPDWORD sid_size, LPWSTR domain,
                                              LPDWORD domain_size, PSID_NAME_USE use) {
    DWORD domain_capacity = domain_size ? *domain_size : 0, sid_capacity = sid_size ? *sid_size : 0;
    BOOL ok;
    if (derived_sid_size && name_is_derived_w(account)) return answer_sid_w(sid, sid_size, domain, domain_size, use);
    ok = sys_LookupAccountNameLocalW(account, sid, sid_size, domain, domain_size, use);
    if (!ok) {
        grow_domain_size(domain_size);
        return ok;
    }
    if (!swap_sid(sid, sid_size, sid_capacity)) return FALSE;
    return swap_domain_w(domain, domain_size, domain_capacity);
}

static BOOL WINAPI my_LookupAccountNameLocalA(LPCSTR account, PSID sid, LPDWORD sid_size, LPSTR domain,
                                              LPDWORD domain_size, PSID_NAME_USE use) {
    DWORD domain_capacity = domain_size ? *domain_size : 0, sid_capacity = sid_size ? *sid_size : 0;
    BOOL ok;
    if (derived_sid_size && name_is_derived_a(account)) return answer_sid_a(sid, sid_size, domain, domain_size, use);
    ok = sys_LookupAccountNameLocalA(account, sid, sid_size, domain, domain_size, use);
    if (!ok) {
        grow_domain_size(domain_size);
        return ok;
    }
    if (!swap_sid(sid, sid_size, sid_capacity)) return FALSE;
    return swap_domain_a(domain, domain_size, domain_capacity);
}

/* A SID in the caller's token-information buffer: the box's own becomes the derived one. The
   replacement never grows the SID (both are shaped S-1-5-21-…-1001), so the rest of the buffer,
   and any SID after it in a group list, stay where the system put them. */
static void replace_own_token_sid(PSID sid, const BYTE *buffer, DWORD capacity) {
    BYTE *bytes = (BYTE *)sid;
    DWORD length, offset;
    if (!bytes || !buffer || !is_own_sid(bytes) || is_derived_sid(bytes)) return;
    length = 8 + 4 * (DWORD)bytes[1];
    if (derived_sid_size > length || bytes < buffer) return;
    offset = (DWORD)(bytes - buffer);
    if (offset + derived_sid_size > capacity) return;
    memcpy(bytes, derived_sid, derived_sid_size);
}

/* The SID the token reports is the host's, and the entry points that only return text never see
   it: `whoami /user` and .NET's account classes read TokenUser and format the SID themselves.
   The SID is rewritten in the buffer the caller supplied, for the caller's own account only.
   userenv is left alone for the same reason as the name: it finds the profile by the token's
   SID. */
static BOOL WINAPI my_GetTokenInformation(HANDLE token, TOKEN_INFORMATION_CLASS cls, LPVOID info, DWORD length,
                                          LPDWORD returned) {
    void *caller = _ReturnAddress();
    BOOL ok = REAL(sys_GetTokenInformation)(token, cls, info, length, returned);
    BYTE *buffer = (BYTE *)info;
    DWORD i, count, header;
    if (!ok || !info || !derived_sid_size || from_userenv(caller)) return ok;
    switch ((int)cls) {
        case TokenUser:
        case TokenOwner:
        case TokenPrimaryGroup:
            if (length >= sizeof(SID_AND_ATTRIBUTES))
                replace_own_token_sid(((SID_AND_ATTRIBUTES *)info)->Sid, buffer, length);
            break;
        case TokenGroups:
        case TokenRestrictedSids: {
            TOKEN_GROUPS *groups = (TOKEN_GROUPS *)info;
            header = (DWORD)FIELD_OFFSET(TOKEN_GROUPS, Groups);
            if (length <= header) break;
            count = groups->GroupCount;
            if (count > (length - header) / sizeof(SID_AND_ATTRIBUTES))
                count = (length - header) / sizeof(SID_AND_ATTRIBUTES);
            for (i = 0; i < count; i++) replace_own_token_sid(groups->Groups[i].Sid, buffer, length);
            break;
        }
        default: break;
    }
    return ok;
}

/* The machine SID behind a local account: S-1-5-21-<three authorities>, the derived SID's first
   four sub-authorities. */
static int is_local_domain_sid(const BYTE *sid) {
    if (!sid || !real_sid_size || sid[0] != 1 || sid[1] != 4) return 0;
    return memcmp(sid, real_sid, 8 + 4 * 4) == 0;
}

/* The domain list behind a lookup names the computer every local account resolves against; the
   box's computer name replaces it there, and its index is what the rewritten names point at. The
   buffer is static for the process lifetime, so it stays valid without being part of the LSA
   block the caller frees. */
static LONG rewrite_domains(HYDRA_DOMAIN_LIST *domains) {
    ULONG i;
    LONG local = -1;
    if (!domains || !domains->Domains) return -1;
    for (i = 0; i < domains->Entries; i++) {
        HYDRA_UNICODE_STRING *name = &domains->Domains[i].Name;
        if (name->Buffer && name->Length && is_host_w(name->Buffer, (int)(name->Length / sizeof(WCHAR))))
            local = (LONG)i;
        else if (is_local_domain_sid((const BYTE *)domains->Domains[i].Sid))
            local = (LONG)i;
    }
    if (local >= 0 && id_computer_name[0]) {
        domains->Domains[local].Name.Buffer = id_computer_name;
        domains->Domains[local].Name.Length = (USHORT)(lstrlenW(id_computer_name) * sizeof(WCHAR));
        domains->Domains[local].Name.MaximumLength = domains->Domains[local].Name.Length;
    }
    return local;
}

/* The names a SID lookup answered: the box's own entries become the derived name in the derived
   domain, and the rest of the system's answer stands. */
static void rewrite_sid_names(ULONG count, const BYTE *own, HYDRA_DOMAIN_LIST **domains, HYDRA_TRANSLATED_NAME **names) {
    ULONG i;
    LONG local;
    HYDRA_DOMAIN_LIST *list = domains ? *domains : NULL;
    if (!names || !*names) return;
    local = rewrite_domains(list);
    if (local < 0 && list && list->Entries > 0) local = 0;
    if (local >= 0 && list) {
        list->Domains[local].Name.Buffer = id_computer_name;
        list->Domains[local].Name.Length = (USHORT)(lstrlenW(id_computer_name) * sizeof(WCHAR));
        list->Domains[local].Name.MaximumLength = list->Domains[local].Name.Length;
    }
    for (i = 0; i < count; i++) {
        if (!own || !own[i]) continue;
        (*names)[i].Use = SidTypeUser;
        (*names)[i].Name.Buffer = id_user_name;
        (*names)[i].Name.Length = (USHORT)(lstrlenW(id_user_name) * sizeof(WCHAR));
        (*names)[i].Name.MaximumLength = (*names)[i].Name.Length;
        (*names)[i].DomainIndex = local;
    }
}

/* A private copy of the SID array with the box's own SIDs mapped back to the host's, so LSA can
   resolve them; `own` marks the entries whose answer is rewritten. */
static int prepare_sids(ULONG count, PSID *sids, PSID **input, BYTE **own) {
    PSID *copy = (PSID *)LocalAlloc(LPTR, count * sizeof(PSID));
    BYTE *flags = (BYTE *)LocalAlloc(LPTR, count);
    ULONG i;
    if (!copy || !flags) {
        LocalFree(copy);
        LocalFree(flags);
        return 0;
    }
    for (i = 0; i < count; i++) {
        copy[i] = sids[i];
        if (sids[i] && is_derived_sid((const BYTE *)sids[i])) {
            flags[i] = 1;
            copy[i] = (PSID)real_sid;
        } else if (sids[i] && is_own_sid((const BYTE *)sids[i])) {
            flags[i] = 1;
        }
    }
    *input = copy;
    *own = flags;
    return 1;
}

static NTSTATUS NTAPI my_LsaLookupSids(void *policy, ULONG count, PSID *sids, HYDRA_DOMAIN_LIST **domains,
                                       HYDRA_TRANSLATED_NAME **names) {
    void *caller = _ReturnAddress();
    PSID *input = NULL;
    BYTE *own = NULL;
    NTSTATUS status;
    if (!sids || !count || !derived_sid_size || from_userenv(caller) || !prepare_sids(count, sids, &input, &own))
        return REAL(sys_LsaLookupSids)(policy, count, sids, domains, names);
    status = REAL(sys_LsaLookupSids)(policy, count, input, domains, names);
    if (NT_SUCCESS(status)) rewrite_sid_names(count, own, domains, names);
    LocalFree(input);
    LocalFree(own);
    return status;
}

static NTSTATUS NTAPI my_LsaLookupSids2(void *policy, ULONG options, ULONG count, PSID *sids,
                                        HYDRA_DOMAIN_LIST **domains, HYDRA_TRANSLATED_NAME **names) {
    void *caller = _ReturnAddress();
    PSID *input = NULL;
    BYTE *own = NULL;
    NTSTATUS status;
    if (!sids || !count || !derived_sid_size || from_userenv(caller) || !prepare_sids(count, sids, &input, &own))
        return REAL(sys_LsaLookupSids2)(policy, options, count, sids, domains, names);
    status = REAL(sys_LsaLookupSids2)(policy, options, count, input, domains, names);
    if (NT_SUCCESS(status)) rewrite_sid_names(count, own, domains, names);
    LocalFree(input);
    LocalFree(own);
    return status;
}

/* A name lookup asks for "domain\name"; a derived name is turned into the real account so LSA
   resolves it, with the derived computer name turned into the host's. Returns the length in
   characters, or 0 when the name is not the box's account. */
static int substitute_account(const HYDRA_UNICODE_STRING *from, WCHAR *out, int capacity) {
    const WCHAR *text = from->Buffer;
    int chars = from->Length / (int)sizeof(WCHAR), at, length = 0, i;
    int domain = -1;
    if (!text || chars <= 0 || chars >= 128 || !id_user_name[0]) return 0;
    for (at = 0; at < chars && text[at] != L'\\'; at++) {
    }
    if (at < chars) domain = at;
    if (!same_text(text + (domain >= 0 ? domain + 1 : 0), chars - (domain >= 0 ? domain + 1 : 0), id_user_name))
        return 0;
    if (domain >= 0 && same_text(text, domain, id_computer_name)) {
        for (i = 0; i < (int)lstrlenW(host_name); i++) out[length++] = host_name[i];
        out[length++] = L'\\';
    } else if (domain >= 0) {
        for (i = 0; i <= domain; i++) out[length++] = text[i];
    }
    for (i = 0; real_user[i]; i++) out[length++] = real_user[i];
    return length < capacity ? length : 0;
}

static NTSTATUS NTAPI my_LsaLookupNames2(void *policy, ULONG flags, ULONG count, HYDRA_UNICODE_STRING *names,
                                         HYDRA_DOMAIN_LIST **domains, HYDRA_TRANSLATED_SID2 **sids) {
    void *caller = _ReturnAddress();
    HYDRA_UNICODE_STRING *input = NULL;
    WCHAR *texts = NULL;
    ULONG i;
    NTSTATUS status;
    if (!names || !count || !derived_sid_size || from_userenv(caller))
        return REAL(sys_LsaLookupNames2)(policy, flags, count, names, domains, sids);
    input = (HYDRA_UNICODE_STRING *)LocalAlloc(LPTR, count * sizeof(*input));
    texts = (WCHAR *)LocalAlloc(LPTR, (size_t)count * 128 * sizeof(WCHAR));
    if (!input || !texts) {
        status = REAL(sys_LsaLookupNames2)(policy, flags, count, names, domains, sids);
    } else {
        for (i = 0; i < count; i++) {
            int length;
            input[i] = names[i];
            length = substitute_account(&names[i], texts + i * 128, 128);
            if (length > 0) {
                input[i].Buffer = texts + i * 128;
                input[i].Length = (USHORT)(length * sizeof(WCHAR));
                input[i].MaximumLength = input[i].Length;
            }
        }
        status = REAL(sys_LsaLookupNames2)(policy, flags, count, input, domains, sids);
        if (NT_SUCCESS(status) && sids && *sids) {
            LONG local = rewrite_domains(domains ? *domains : NULL);
            for (i = 0; i < count; i++) {
                BYTE *sid = (BYTE *)(*sids)[i].Sid;
                if (!sid || !is_own_sid(sid) || is_derived_sid(sid)) continue;
                if (derived_sid_size > 8 + 4 * (DWORD)sid[1]) continue;
                memcpy(sid, derived_sid, derived_sid_size);
                (*sids)[i].Use = SidTypeUser;
                (*sids)[i].DomainIndex = local;
            }
        }
    }
    LocalFree(input);
    LocalFree(texts);
    return status;
}

/* NameSamCompatible is `HOST\user` for a local account; the other formats do not carry the
   computer name. Both halves are the box's, so the answer is rebuilt from the two values. */static BOOLEAN WINAPI my_GetUserNameExW(int format, LPWSTR buffer, PULONG size) {
    void *caller = _ReturnAddress();
    ULONG capacity = size ? *size : 0, host_length = (ULONG)lstrlenW(host_name), length, name_length, rest, total;
    BOOLEAN ok;
    if (from_userenv(caller)) return REAL(sys_GetUserNameExW)(format, buffer, size);
    ok = REAL(sys_GetUserNameExW)(format, buffer, size);
    if (format != 2 || !id_computer_name[0] || !size) return ok;
    length = (ULONG)lstrlenW(id_computer_name);
    name_length = (ULONG)lstrlenW(id_user_name);
    if (!ok) {
        if (GetLastError() == ERROR_MORE_DATA) {
            if (id_user_name[0] && real_user[0]) {
                total = length + 1 + name_length + 1; /* `HOST\user` and its terminator */
                if (*size < total) *size = total;
            } else if (length > host_length) {
                *size += length - host_length;
            }
        }
        return ok;
    }
    if (!buffer || *size <= host_length || buffer[host_length] != L'\\' || !is_host_w(buffer, (int)host_length))
        return ok;
    rest = *size - host_length; /* `\user`, without the terminator */
    if (!id_user_name[0] || !real_user[0]) {
        /* Only the computer name is claimed: move the host and keep the account the system named. */
        if (capacity < length + rest + 1) {
            *size = length + rest + 1;
            SetLastError(ERROR_MORE_DATA);
            return FALSE;
        }
        memmove(buffer + length, buffer + host_length, (rest + 1) * sizeof(WCHAR));
        memcpy(buffer, id_computer_name, length * sizeof(WCHAR));
        *size = length + rest;
        return ok;
    }
    /* The account's half is the real user for a local account; if it is not, this is not the
       account the box claims, and the system's answer stands. */
    if (!same_text(buffer + host_length + 1, (int)(rest - 1), real_user)) return ok;
    total = length + 1 + name_length;
    if (capacity < total + 1) {
        *size = total + 1;
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    memcpy(buffer + length + 1, id_user_name, (name_length + 1) * sizeof(WCHAR));
    memcpy(buffer, id_computer_name, length * sizeof(WCHAR));
    buffer[length] = L'\\';
    *size = total;
    return ok;
}

static BOOLEAN WINAPI my_GetUserNameExA(int format, LPSTR buffer, PULONG size) {
    void *caller = _ReturnAddress();
    ULONG capacity = size ? *size : 0, host_length = (ULONG)lstrlenW(host_name), length, name_length, rest, total, i;
    BOOLEAN ok;
    if (from_userenv(caller)) return REAL(sys_GetUserNameExA)(format, buffer, size);
    ok = REAL(sys_GetUserNameExA)(format, buffer, size);
    if (format != 2 || !id_computer_name[0] || !size) return ok;
    length = (ULONG)lstrlenW(id_computer_name);
    name_length = (ULONG)lstrlenW(id_user_name);
    if (!ok) {
        if (GetLastError() == ERROR_MORE_DATA) {
            if (id_user_name[0] && real_user[0]) {
                total = length + 1 + name_length + 1;
                if (*size < total) *size = total;
            } else if (length > host_length) {
                *size += length - host_length;
            }
        }
        return ok;
    }
    if (!buffer || *size <= host_length || buffer[host_length] != '\\' || !is_host_a(buffer, (int)host_length))
        return ok;
    rest = *size - host_length;
    if (!id_user_name[0] || !real_user[0]) {
        if (capacity < length + rest + 1) {
            *size = length + rest + 1;
            SetLastError(ERROR_MORE_DATA);
            return FALSE;
        }
        memmove(buffer + length, buffer + host_length, rest + 1);
        for (i = 0; i < length; i++) buffer[i] = (CHAR)id_computer_name[i];
        *size = length + rest;
        return ok;
    }
    if (!same_text_a(buffer + host_length + 1, (int)(rest - 1), real_user)) return ok;
    total = length + 1 + name_length;
    if (capacity < total + 1) {
        *size = total + 1;
        SetLastError(ERROR_MORE_DATA);
        return FALSE;
    }
    for (i = 0; i <= name_length; i++) buffer[length + 1 + i] = (CHAR)id_user_name[i];
    for (i = 0; i < length; i++) buffer[i] = (CHAR)id_computer_name[i];
    buffer[length] = '\\';
    *size = total;
    return ok;
}

/* `GetUserName` names the account the process runs as, in that call's own terms: a bare name and
   a size that counts its terminator. A thread impersonating someone else is not the box's
   account, so only the real user's own name is answered with the derived one. */
static BOOL WINAPI my_GetUserNameW(LPWSTR name, LPDWORD size) {
    DWORD capacity = size ? *size : 0;
    BOOL ok = REAL(sys_GetUserNameW)(name, size);
    if (!id_user_name[0]) return ok;
    if (!ok) {
        grow_name_size(size);
        return ok;
    }
    if (!name || !size || !real_user[0] || !same_text(name, (int)lstrlenW(name), real_user)) return ok;
    return fill_user_w(id_user_name, name, size, capacity);
}

static BOOL WINAPI my_GetUserNameA(LPSTR name, LPDWORD size) {
    DWORD capacity = size ? *size : 0;
    BOOL ok = REAL(sys_GetUserNameA)(name, size);
    if (!id_user_name[0]) return ok;
    if (!ok) {
        grow_name_size(size);
        return ok;
    }
    if (!name || !size || !real_user[0] || !same_text_a(name, (int)lstrlenA(name), real_user)) return ok;
    return fill_user_a(id_user_name, name, size, capacity);
}

/* The system formats any valid SID into a LocalAlloc'd string the caller frees. The box's own SID
   must read back as the derived text, so that string is replaced by one allocated the same way;
   the derived SID already formats as its own text, so it is left alone. */
static BOOL WINAPI my_ConvertSidToStringSidW(PSID sid, LPWSTR *text) {
    void *caller = _ReturnAddress();
    BOOL ok;
    DWORD length, i;
    LPWSTR copy;
    if (from_userenv(caller)) return REAL(sys_ConvertSidToStringSidW)(sid, text);
    ok = REAL(sys_ConvertSidToStringSidW)(sid, text);
    if (!ok || !text || !*text || !id_user_sid[0] || !is_own_sid((const BYTE *)sid) ||
        is_derived_sid((const BYTE *)sid))
        return ok;
    length = (DWORD)lstrlenW(id_user_sid);
    copy = (LPWSTR)LocalAlloc(LMEM_FIXED, (length + 1) * sizeof(WCHAR));
    if (!copy) return ok;
    for (i = 0; i <= length; i++) copy[i] = id_user_sid[i];
    LocalFree(*text);
    *text = copy;
    return TRUE;
}

static BOOL WINAPI my_ConvertSidToStringSidA(PSID sid, LPSTR *text) {    void *caller = _ReturnAddress();
    BOOL ok;
    DWORD length, i;
    LPSTR copy;
    if (from_userenv(caller)) return REAL(sys_ConvertSidToStringSidA)(sid, text);
    ok = REAL(sys_ConvertSidToStringSidA)(sid, text);
    if (!ok || !text || !*text || !id_user_sid[0] || !is_own_sid((const BYTE *)sid) ||
        is_derived_sid((const BYTE *)sid))
        return ok;
    length = (DWORD)lstrlenW(id_user_sid);
    copy = (LPSTR)LocalAlloc(LMEM_FIXED, length + 1);
    if (!copy) return ok;
    for (i = 0; i <= length; i++) copy[i] = (CHAR)id_user_sid[i];
    LocalFree(*text);
    *text = copy;
    return TRUE;
}

/* --- entry ----------------------------------------------------------------- */

#define HOOK(module, name) hook(sbie_hook, module, self, #name, (void *)my_##name, (void **)&sys_##name)
#define HOOK_PAIR(first, second, name)                                                                          \
    hook_pair(sbie_hook, first, second, self, #name, (void *)my_##name, (void **)&sys_##name.a,                \
              (void **)&sys_##name.b)

/* Called by Sandboxie after loading this DLL, with SbieDll's module handle. Sandboxie can call it
   again for the same process; the second pass would read the box's own answers through the hooks
   the first pass installed and take them for the host's, and would stack a second set of hooks on
   the first. The first pass is the only one that can see the host. */
__declspec(dllexport) void __stdcall InjectDllMain(HINSTANCE sbie, ULONG_PTR unused) {
    static LONG injected;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    /* advapi32 and kernel32 mostly forward to kernelbase / sechost, and a program whose import
       table was resolved against the target directly - the system's own reg.exe and hostname.exe
       among them - never enters the forwarding stubs, so both copies are hooked. These are not
       always loaded yet when Sandboxie injects, so they are loaded here. */
    HMODULE kernelbase = LoadLibraryW(L"kernelbase.dll");
    HMODULE advapi32 = LoadLibraryW(L"advapi32.dll");
    HMODULE sechost = LoadLibraryW(L"sechost.dll");
    HMODULE secur32, sspicli, iphlpapi;
    HMODULE self = NULL;
    DWORD host_size = (DWORD)(sizeof(host_name) / sizeof(host_name[0]));
    P_SbieDll_Hook sbie_hook = (P_SbieDll_Hook)(void *)GetProcAddress((HMODULE)sbie, "SbieDll_Hook");
    (void)unused;
    if (InterlockedCompareExchange(&injected, 1, 0) != 0) return;
    if (!sbie_hook || !ntdll || !kernel32) return;
    if (!load_identity((HMODULE)sbie)) return;
    /* The account this box really runs as, read before any account hook exists: what the derived
       name has to be turned into for a lookup, and which SID is the box's own. */
    load_account(advapi32);
    /* The host's name, read before GetComputerNameW is hooked. */
    if (!GetComputerNameW(host_name, &host_size)) host_name[0] = 0;
    secur32 = LoadLibraryW(L"secur32.dll");
    sspicli = LoadLibraryW(L"sspicli.dll");
    iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)(void *)&InjectDllMain, &self);

    /* Not hooked, only called: the key name lookup behind the registry detours. */
    sys_NtQueryKey = (P_NtQueryKey)(void *)GetProcAddress(ntdll, "NtQueryKey");
    /* Not hooked, only called: which module a detour's caller belongs to. */
    sys_RtlPcToFileHeader = (P_RtlPcToFileHeader)(void *)GetProcAddress(ntdll, "RtlPcToFileHeader");
    HOOK(ntdll, NtQueryValueKey);
    HOOK(ntdll, NtEnumerateValueKey);
    if (have_volume_serial) {
        HOOK(ntdll, NtQueryVolumeInformationFile);
        HOOK(ntdll, NtQueryInformationFile);
        /* Path-based queries (Windows 10 1703+; the stat class only on 11 24H2+). Absent on older
           systems, where hook() simply finds no export. */
        HOOK(ntdll, NtQueryInformationByName);
    }
    if (have_mac && iphlpapi) {
        HOOK(iphlpapi, GetAdaptersAddresses);
        HOOK(iphlpapi, GetAdaptersInfo);
        HOOK(iphlpapi, GetIfTable);
        HOOK(iphlpapi, GetIfEntry);
        HOOK(iphlpapi, GetIfTable2);
        HOOK(iphlpapi, GetIfTable2Ex);
        HOOK(iphlpapi, GetIfEntry2);
        HOOK(iphlpapi, GetIfEntry2Ex);
    }
    /* The in-process sources of the board, BIOS and disk serials and the product UUID. WMI is
       closed off in the box, so these are what is left of them. */
    HOOK_PAIR(kernel32, kernelbase, GetSystemFirmwareTable);
    HOOK_PAIR(kernel32, kernelbase, DeviceIoControl);
    if (id_computer_name[0]) {
        HOOK_PAIR(kernel32, kernelbase, GetComputerNameExW);
        HOOK_PAIR(kernel32, kernelbase, GetComputerNameExA);
        HOOK_PAIR(kernel32, kernelbase, GetComputerNameW);
        HOOK_PAIR(kernel32, kernelbase, GetComputerNameA);
    }
    if (id_computer_name[0] || have_account()) {
        /* The account: the name it goes by, the text of its SID, and the lookups between the two.
           `whoami` reads all three, and so does anything comparing an account with a SID it read
           from somewhere else. */
        HOOK_PAIR(advapi32, sechost, LookupAccountSidW);
        HOOK_PAIR(advapi32, sechost, LookupAccountSidA);
        HOOK_PAIR(advapi32, sechost, LookupAccountNameW);
        HOOK_PAIR(advapi32, sechost, LookupAccountNameA);
        HOOK(sechost, LookupAccountSidLocalW);
        HOOK(sechost, LookupAccountSidLocalA);
        HOOK(sechost, LookupAccountNameLocalW);
        HOOK(sechost, LookupAccountNameLocalA);
        HOOK_PAIR(secur32, sspicli, GetUserNameExW);
        HOOK_PAIR(secur32, sspicli, GetUserNameExA);
        HOOK_PAIR(advapi32, sechost, GetUserNameW);
        HOOK_PAIR(advapi32, sechost, GetUserNameA);
        HOOK_PAIR(advapi32, sechost, ConvertSidToStringSidW);
        HOOK_PAIR(advapi32, sechost, ConvertSidToStringSidA);
        HOOK_PAIR(advapi32, kernelbase, GetTokenInformation);
        HOOK_PAIR(advapi32, sechost, LsaLookupNames2);
        HOOK_PAIR(advapi32, sechost, LsaLookupSids);
        HOOK_PAIR(advapi32, sechost, LsaLookupSids2);
    }
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(inst);
    return TRUE;
}
