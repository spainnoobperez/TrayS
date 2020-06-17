#ifdef _WIN64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

#include "framework.h"
#include "TrayS.h"
int DPI(int pixel) {
    return pixel * iDPI / 96;
}

HINSTANCE ShellExecute(_In_opt_ HWND hwnd, _In_opt_ LPCWSTR lpOperation, _In_ LPCWSTR lpFile, _In_opt_ LPCWSTR lpParameters, _In_opt_ LPCWSTR lpDirectory, _In_ INT nShowCmd) {
    HINSTANCE hInstance = NULL;
    typedef HINSTANCE(WINAPI * pfnShellExecute)(_In_opt_ HWND hwnd, _In_opt_ LPCWSTR lpOperation, _In_ LPCWSTR lpFile, _In_opt_ LPCWSTR lpParameters, _In_opt_ LPCWSTR lpDirectory, _In_ INT nShowCmd);
    HMODULE hShell32 = LoadLibrary(L"shell32.dll");
    if (hShell32) {
        pfnShellExecute ShellExecuteW = (pfnShellExecute)GetProcAddress(hShell32, "ShellExecuteW");
        if(ShellExecuteW)
            hInstance = ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
        FreeLibrary(hShell32);
    }
    return hInstance;
}

BOOL Shell_NotifyIcon(DWORD dwMessage, _In_ PNOTIFYICONDATAW lpData) {
    typedef BOOL(WINAPI * pfnShell_NotifyIcon)(DWORD dwMessage, _In_ PNOTIFYICONDATAW lpData);
    HMODULE hShell32 = LoadLibrary(L"shell32.dll");
    BOOL ret = FALSE;
    if (hShell32) {
        pfnShell_NotifyIcon Shell_NotifyIconW = (pfnShell_NotifyIcon)GetProcAddress(hShell32, "Shell_NotifyIconW");
        if (Shell_NotifyIconW)
            ret = Shell_NotifyIconW(dwMessage, lpData);
        FreeLibrary(hShell32);
    }
    return ret;
}
BOOL WTSQueryUserToken(ULONG SessionId, PHANDLE phToken) {
    BOOL ret = FALSE;
    typedef BOOL (WINAPI * pfnWTSQueryUserToken)(ULONG SessionId, PHANDLE phToken);
    HMODULE hWTSAPI32 = LoadLibrary(L"wtsapi32.dll");
    if (hWTSAPI32) {
        pfnWTSQueryUserToken WTSQueryUserToken = (pfnWTSQueryUserToken)GetProcAddress(hWTSAPI32, "WTSQueryUserToken");
        if (WTSQueryUserToken)
            ret = WTSQueryUserToken(SessionId, phToken);
        FreeLibrary(hWTSAPI32);
    }
    return ret;
}
BOOL CreateEnvironmentBlock(_At_((PZZWSTR *)lpEnvironment, _Outptr_)LPVOID *lpEnvironment, _In_opt_ HANDLE  hToken, _In_ BOOL bInherit) {
    BOOL ret = FALSE;
    typedef BOOL(WINAPI * pfnCreateEnvironmentBlock)(_At_((PZZWSTR *)lpEnvironment, _Outptr_)LPVOID * lpEnvironment, _In_opt_ HANDLE  hToken, _In_ BOOL bInherit);
    HMODULE hUserenv = LoadLibrary(L"userenv.dll");
    if (hUserenv) {
        pfnCreateEnvironmentBlock CreateEnvironmentBlock = (pfnCreateEnvironmentBlock)GetProcAddress(hUserenv, "CreateEnvironmentBlock");
        if (CreateEnvironmentBlock)
            ret = CreateEnvironmentBlock(lpEnvironment, hToken, bInherit);
        FreeLibrary(hUserenv);
    }
    return ret;
}
ULONG CallNtPowerInformation(_In_ POWER_INFORMATION_LEVEL InformationLevel, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength) {
    ULONG ret = -1;
    typedef BOOL(WINAPI * pfnCallNtPowerInformation)(_In_ POWER_INFORMATION_LEVEL InformationLevel, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer, _In_ ULONG InputBufferLength, _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferLength);
    HMODULE hPowrptof = LoadLibrary(L"powrprof.dll");
    if (hPowrptof) {
        pfnCallNtPowerInformation CallNtPowerInformation = (pfnCallNtPowerInformation)GetProcAddress(hPowrptof, "CallNtPowerInformation");
        if (CallNtPowerInformation)
            ret = CallNtPowerInformation(InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
        FreeLibrary(hPowrptof);
    }
    return ret;
}
BOOL CALLBACK FindWindowFunc(HWND hWnd, LPARAM lpAram) {
    WCHAR szText[16];
    GetWindowText(hWnd, szText, 16);
    if (wcscmp(szText, L"_TrayS_") == 0) {
        SendMessage(hWnd, WM_TRAYS, 0, 0);
        return FALSE;
    }
    return TRUE;
}
BOOL CALLBACK IsZoomedFunc(HWND hWnd, LPARAM lpAram) {
    if (::IsWindowVisible(hWnd) && IsZoomed(hWnd)) {
        if (MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST) == (HMONITOR)lpAram) {
            BOOL Attribute = FALSE;
            if (DwmGetWindowAttribute)
                DwmGetWindowAttribute(hWnd, 14, &Attribute, sizeof(BOOL));
            if (Attribute == FALSE) {
                iWindowMode = 1;
                return FALSE;
            }
        }
    }
    return TRUE;
}
BOOL IsUserAdmin() { 
    BOOL b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    b = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
    if (b) {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &b)) {
            b = FALSE;
        }
        FreeSid(AdministratorsGroup);
    }
    return(b);
}

BOOL LaunchAppIntoDifferentSession(WCHAR *szExe, WCHAR *szDir) { 
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    BOOL bResult = FALSE;

    DWORD winlogonPid;
    ULONG dwSessionId;
    HANDLE hUserToken, hUserTokenDup = NULL, hPToken = NULL, hProcess;
    DWORD dwCreationFlags;

    dwSessionId = WTSGetActiveConsoleSessionId();

    PROCESSENTRY32 procEntry;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    procEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnap, &procEntry)) {
        return FALSE;
    }

    do {
        if (_wcsicmp(procEntry.szExeFile, L"winlogon.exe") == 0) {
            DWORD winlogonSessId = 0;
            if (ProcessIdToSessionId(procEntry.th32ProcessID, &winlogonSessId)
                    && winlogonSessId == dwSessionId) {
                winlogonPid = procEntry.th32ProcessID;
                break;
            }
        }

    } while (Process32Next(hSnap, &procEntry));

    WTSQueryUserToken(dwSessionId, &hUserToken);
    dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = (LPWSTR)L"winsta0\\default";
    ZeroMemory(&pi, sizeof(pi));
    TOKEN_PRIVILEGES tp;
    LUID luid;
    hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, winlogonPid);
    if (hProcess) {
        if (!::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
                                | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID
                                | TOKEN_READ | TOKEN_WRITE, &hPToken)) {
        }

        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        }
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL,
                         SecurityIdentification, TokenPrimary, &hUserTokenDup);
        int dup = GetLastError();

        SetTokenInformation(hUserTokenDup,
                            TokenSessionId, (LPVOID)dwSessionId, sizeof(ULONG));

        if (!AdjustTokenPrivileges(hUserTokenDup, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
                                   (PTOKEN_PRIVILEGES)NULL, NULL)) {
        }

        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        }

        LPVOID pEnv = NULL;

        if (CreateEnvironmentBlock(&pEnv, hUserTokenDup, TRUE)) {
            dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
        } else
            pEnv = NULL;

        bResult = CreateProcessAsUser(
                      hUserTokenDup,                        
                      szExe,       
                      NULL,                   
                      NULL,                
                      NULL,                   
                      FALSE,                  
                      dwCreationFlags,       
                      pEnv,                    
                      szDir,                   
                      &si,                   
                      &pi                     
                  );
    }
    if (hProcess) {
        CloseHandle(hProcess);
        CloseHandle(hUserToken);
        CloseHandle(hUserTokenDup);
        CloseHandle(hPToken);
    }
    return bResult;
}
BOOL bInstallService;
SERVICE_STATUS_HANDLE hServiceStatus;
SERVICE_STATUS status;
void WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv);
HANDLE hEvent = INVALID_HANDLE_VALUE;
void WINAPI ServiceStrl(DWORD dwOpcode) { 
    switch (dwOpcode) {
    case SERVICE_CONTROL_STOP:
        status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hServiceStatus, &status);
        ::SetEvent(hEvent);
        break;
    case SERVICE_CONTROL_PAUSE:
        break;
    case SERVICE_CONTROL_CONTINUE:
        break;
    case SERVICE_CONTROL_INTERROGATE:
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        break;
    default:
        break;
    }
}
void WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv) { 
    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    hServiceStatus = RegisterServiceCtrlHandler(szAppName, ServiceStrl);
    if (hServiceStatus == NULL) {
        return;
    }
    SetServiceStatus(hServiceStatus, &status);
    hEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hEvent == NULL) {
        status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hServiceStatus, &status);
        return;
    }
    status.dwWin32ExitCode = S_OK;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hServiceStatus, &status);
    WCHAR szExe[MAX_TEXT];
    HINSTANCE hInst = GetModuleHandle(NULL);
    GetModuleFileName(hInst, szExe, MAX_TEXT);
    size_t iLen = wcslen(szExe);
    szExe[iLen] = L'\0';
    LaunchAppIntoDifferentSession(szExe, NULL);
    while (WaitForSingleObject(hEvent, 1000) != WAIT_OBJECT_0) {
    }
    status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hServiceStatus, &status);
}
DWORD ServiceRunState() { 
    BOOL bResult = FALSE;
    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM != NULL) {
        SC_HANDLE hService = ::OpenService(hSCM, szAppName, SERVICE_QUERY_STATUS);
        if (hService != NULL) {
            SERVICE_STATUS ss;
            QueryServiceStatus(hService, &ss);
            bResult = ss.dwCurrentState;
            ::CloseServiceHandle(hService);
        }
        ::CloseServiceHandle(hSCM);
    }
    return bResult;
}
BOOL IsServiceInstalled() { 
    BOOL bResult = FALSE;
    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM != NULL) {
        SC_HANDLE hService = ::OpenService(hSCM, szAppName, SERVICE_QUERY_CONFIG);
        if (hService != NULL) {
            bResult = TRUE;
            ::CloseServiceHandle(hService);
        }
        ::CloseServiceHandle(hSCM);
    }
    return bResult;
}
BOOL InstallService() { 
    if (IsServiceInstalled())
        return TRUE;
    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL) {
        return FALSE;
    }
    TCHAR szFilePath[MAX_TEXT];
    ::GetModuleFileName(NULL, szFilePath, MAX_TEXT);
    SC_HANDLE hService = ::CreateService(
                             hSCM,
                             szAppName,
                             szAppName,
                             SERVICE_ALL_ACCESS,
                             SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
                             SERVICE_AUTO_START, 
                             SERVICE_ERROR_NORMAL,
                             szFilePath,
                             NULL,
                             NULL,
                             _T(""),
                             NULL,
                             NULL);
    if (hService == NULL) {
        ::CloseServiceHandle(hSCM);
        return FALSE;
    }
    ::CloseServiceHandle(hService);
    ::CloseServiceHandle(hSCM);
    return TRUE;
}
BOOL UninstallService() { 
    if (!IsServiceInstalled())
        return TRUE;
    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL) {
        return FALSE;
    }
    SC_HANDLE hService = ::OpenService(hSCM, szAppName, SERVICE_STOP | DELETE);
    if (hService == NULL) {
        ::CloseServiceHandle(hSCM);
        return FALSE;
    }
    SERVICE_STATUS status;
    ::ControlService(hService, SERVICE_CONTROL_STOP, &status);
    BOOL bDelete = ::DeleteService(hService);
    ::CloseServiceHandle(hService);
    ::CloseServiceHandle(hSCM);
    if (bDelete)
        return TRUE;
    return FALSE;
}
void Init() { 
    hServiceStatus = NULL;
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    status.dwWin32ExitCode = 0;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
}
BOOL ServiceCtrlStart() { 
    BOOL bRet;
    SC_HANDLE hSCM;
    SC_HANDLE hService;
    hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM != NULL) {
        hService = OpenService(hSCM, szAppName, SERVICE_ALL_ACCESS);
        if (hService != NULL) {
            TCHAR szFilePath[MAX_TEXT];
            ::GetModuleFileName(NULL, szFilePath, MAX_TEXT);
            ChangeServiceConfig(hService, SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, SERVICE_AUTO_START, SERVICE_NO_CHANGE, szFilePath, NULL, NULL, NULL, NULL, NULL, NULL);
            bRet = StartService(hService, 0, NULL);
            CloseServiceHandle(hService);
        } else {
            bRet = FALSE;
        }
        CloseServiceHandle(hSCM);
    } else {
        bRet = FALSE;
    }
    return bRet;
}
BOOL ServiceCtrlStop() { 
    BOOL bRet;
    SC_HANDLE hSCM;
    SC_HANDLE hService;
    SERVICE_STATUS ServiceStatus;
    hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM != NULL) {
        hService = OpenService(hSCM, szAppName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (hService != NULL) {
            QueryServiceStatus(hService, &ServiceStatus);
            if (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
                bRet = ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus);
            } else {
                bRet = FALSE;
            }
            CloseServiceHandle(hService);
        } else {
            bRet = FALSE;
        }
        CloseServiceHandle(hSCM);
    } else {
        bRet = FALSE;
    }
    return bRet;
}



DWORD iCPU;
FILETIME pre_idleTime;
FILETIME pre_kernelTime;
FILETIME pre_userTime;
__int64 CompareFileTime(FILETIME time1, FILETIME time2) {
    __int64 a = time1.dwHighDateTime;
    a = a << 32 | time1.dwLowDateTime;
    __int64 b = time2.dwHighDateTime;
    b = b << 32 | time2.dwLowDateTime;
    return (b - a);
}
typedef struct _PDH_RAW_COUNTER {
    volatile DWORD CStatus;
    FILETIME    TimeStamp;
    LONGLONG    FirstValue;
    LONGLONG    SecondValue;
    DWORD       MultiCount;
} PDH_RAW_COUNTER, * PPDH_RAW_COUNTER;
PDH_RAW_COUNTER m_last_rawData;
BOOL m_first_get_CPU_utility = TRUE;
int GetCPUUseRate() {
    if (TraySave.bMonitorPDH) {
#define PDH_FMT_RAW          ((DWORD) 0x00000010)
#define PDH_FMT_ANSI         ((DWORD) 0x00000020)
#define PDH_FMT_UNICODE      ((DWORD) 0x00000040)
#define PDH_FMT_LONG         ((DWORD) 0x00000100)
#define PDH_FMT_DOUBLE       ((DWORD) 0x00000200)
#define PDH_FMT_LARGE        ((DWORD) 0x00000400)
#define PDH_FMT_NOSCALE      ((DWORD) 0x00001000)
#define PDH_FMT_1000         ((DWORD) 0x00002000)
#define PDH_FMT_NODATA       ((DWORD) 0x00004000)
#define PDH_FMT_NOCAP100     ((DWORD) 0x00008000)
#define PERF_DETAIL_COSTLY   ((DWORD) 0x00010000)
#define PERF_DETAIL_STANDARD ((DWORD) 0x0000FFFF)
        typedef HANDLE       PDH_HCOUNTER;
        typedef HANDLE       PDH_HQUERY;
        typedef HANDLE       PDH_HLOG;

        typedef PDH_HCOUNTER HCOUNTER;
        typedef PDH_HQUERY   HQUERY;

        typedef struct _PDH_FMT_COUNTERVALUE {
            DWORD    CStatus;
            union {
                LONG        longValue;
                double      doubleValue;
                LONGLONG    largeValue;
                LPCSTR      AnsiStringValue;
                LPCWSTR     WideStringValue;
            };
        } PDH_FMT_COUNTERVALUE, * PPDH_FMT_COUNTERVALUE;
        HQUERY hQuery;
        HCOUNTER hCounter;
        DWORD counterType;
        PDH_RAW_COUNTER rawData;
        typedef ULONG(WINAPI * pfnPdhOpenQuery)(_In_opt_ LPCWSTR szDataSource, _In_ DWORD_PTR dwUserData, _Out_ PDH_HQUERY * phQuery);
        typedef ULONG(WINAPI * pfnPdhAddCounter)(_In_ PDH_HQUERY hQuery, _In_ LPCWSTR szFullCounterPath, _In_ DWORD_PTR dwUserData, _Out_ PDH_HCOUNTER * phCounter);
        typedef ULONG(WINAPI * pfnPdhCollectQueryData)(PDH_HQUERY hQuery);
        typedef ULONG(WINAPI * pfnPdhGetRawCounterValue)(PDH_HCOUNTER hCounter, LPDWORD lpdwType, PPDH_RAW_COUNTER pValue);
        typedef ULONG(WINAPI * pfnPdhCalculateCounterFromRawValue)(PDH_HCOUNTER hCounter, DWORD dwFormat, PPDH_RAW_COUNTER rawValue1, PPDH_RAW_COUNTER rawValue2, PPDH_FMT_COUNTERVALUE fmtValue);
        typedef ULONG(WINAPI * pfnPdhCloseQuery)(PDH_HQUERY hQuery);
        if(hPDH == NULL)
            hPDH = LoadLibrary(L"pdh.dll");
        if (hPDH) {
            pfnPdhOpenQuery PdhOpenQuery = (pfnPdhOpenQuery)GetProcAddress(hPDH, "PdhOpenQueryW");
            pfnPdhAddCounter PdhAddCounter = (pfnPdhAddCounter)GetProcAddress(hPDH, "PdhAddCounterW");
            pfnPdhCollectQueryData PdhCollectQueryData = (pfnPdhCollectQueryData)GetProcAddress(hPDH, "PdhCollectQueryData");
            pfnPdhGetRawCounterValue PdhGetRawCounterValue = (pfnPdhGetRawCounterValue)GetProcAddress(hPDH, "PdhGetRawCounterValue");
            pfnPdhCalculateCounterFromRawValue PdhCalculateCounterFromRawValue = (pfnPdhCalculateCounterFromRawValue)GetProcAddress(hPDH, "PdhCalculateCounterFromRawValue");
            pfnPdhCloseQuery PdhCloseQuery = (pfnPdhCloseQuery)GetProcAddress(hPDH, "PdhCloseQuery");
            if (PdhCloseQuery != NULL && PdhAddCounter != NULL && PdhCollectQueryData != NULL && PdhGetRawCounterValue != NULL && PdhCalculateCounterFromRawValue != NULL && PdhCloseQuery != NULL) {
                PdhOpenQuery(NULL, 0, &hQuery);
                const wchar_t *query_str{};

                query_str = L"\\Processor Information(_Total)\\% Processor Utility";
                PdhAddCounter(hQuery, query_str, NULL, &hCounter);
                PdhCollectQueryData(hQuery);
                PdhGetRawCounterValue(hCounter, &counterType, &rawData);
                PDH_FMT_COUNTERVALUE fmtValue;
                PdhCalculateCounterFromRawValue(hCounter, PDH_FMT_DOUBLE, &rawData, &m_last_rawData, &fmtValue);
                iCPU = (int)fmtValue.doubleValue;
                if (iCPU > 100)
                    iCPU = 100;
                m_last_rawData = rawData;
                PdhCloseQuery(hQuery);
            }
        }
        return iCPU;
    } else {
        if (hPDH) {
            FreeLibrary(hPDH);
            hPDH = NULL;
        }
        int nCPUUseRate = -1;
        FILETIME idleTime;
        FILETIME kernelTime;
        FILETIME userTime;
        GetSystemTimes(&idleTime, &kernelTime, &userTime);

        __int64 idle = CompareFileTime(pre_idleTime, idleTime);
        __int64 kernel = CompareFileTime(pre_kernelTime, kernelTime);
        __int64 user = CompareFileTime(pre_userTime, userTime);
        nCPUUseRate = (int)((kernel + user - idle) * 100 / (kernel + user));
        pre_idleTime = idleTime;
        pre_kernelTime = kernelTime;
        pre_userTime = userTime;
        if (nCPUUseRate < 1)
            nCPUUseRate = iCPU;
        else if (nCPUUseRate > 100)
            nCPUUseRate = 100;
        return nCPUUseRate;
    }
}
void ReadReg() { 
    WCHAR szDir[MAX_PATH];
    GetModuleFileName(NULL, szDir, MAX_PATH);
    size_t len = wcslen(szDir);
    for (size_t i = len - 1; i > 0; i--) {
        if (szDir[i] == '\\') {
            szDir[i] = 0;
            SetCurrentDirectory(szDir);
            break;
        }
    }

    HANDLE hFile = CreateFile(szTraySave, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
    if (hFile) {
        DWORD dwBytes;
        ReadFile(hFile, &TraySave, sizeof TraySave, &dwBytes, NULL);
        CloseHandle(hFile);
    }
}
void WriteReg() { 
    WCHAR szDir[MAX_PATH];
    GetModuleFileName(NULL, szDir, MAX_PATH);
    size_t len = wcslen(szDir);
    for (size_t i = len - 1; i > 0; i--) {
        if (szDir[i] == '\\') {
            szDir[i] = 0;
            SetCurrentDirectory(szDir);
            break;
        }
    }
    HANDLE hFile = CreateFile(szTraySave, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_ARCHIVE, NULL);
    if (hFile) {
        DWORD dwBytes;
        WriteFile(hFile, &TraySave, sizeof TraySave, &dwBytes, NULL);
        CloseHandle(hFile);
    }
}
void RunProcess(LPWSTR sz) {

    STARTUPINFO StartInfo;
    PROCESS_INFORMATION procStruct;
    memset(&StartInfo, 0, sizeof(STARTUPINFO));
    StartInfo.cb = sizeof(STARTUPINFO);
    WCHAR szExe[MAX_PATH];
    WCHAR szCommandLine[MAX_PATH];
    szCommandLine[0] = L'\0';
    if (sz)
        wcscpy_s(szCommandLine, MAX_PATH, sz);
    GetModuleFileName(NULL, szExe, MAX_PATH);
    CreateProcess(szExe, 
                  szCommandLine,
                  NULL,
                  NULL,
                  FALSE,
                  NULL, 
                  NULL,
                  NULL,
                  &StartInfo, &procStruct);
    CloseHandle(procStruct.hProcess);
    CloseHandle(procStruct.hThread);
    SetTimer(hMain, 11, 1000, NULL);
}

void OpenTaskBar() {
    if (IsWindow(hTaskBar) == FALSE) {
        hTaskBar = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_TASKBAR), NULL, (DLGPROC)TaskBarProc);
        if (hTaskBar) {
            while (hTray == NULL) {
                hTray = FindWindow(szShellTray, NULL);
                if(hTray == NULL)
                    Sleep(100);
            }
            while (hReBarWnd == NULL) {
                hReBarWnd = FindWindowEx(hTray, 0, L"ReBarWindow32", NULL);
                if (hReBarWnd == NULL)
                    Sleep(100);
            }

            hTaskWnd = FindWindowEx(hReBarWnd, NULL, L"MSTaskSwWClass", NULL);
            if (TraySave.bMonitorFloat) {
                LONG exStyle = WS_EX_LAYERED | WS_EX_TOPMOST;
                if (TraySave.bMonitorTransparent)
                    exStyle |= WS_EX_TRANSPARENT;
                SetWindowLongPtr(hTaskBar, GWL_EXSTYLE, GetWindowLongPtr(hTaskBar, GWL_EXSTYLE) | exStyle);
                SetLayeredWindowAttributes(hTaskBar, RGB(0, 0, 1), 198, LWA_ALPHA | LWA_COLORKEY);
                SetParent(hTaskBar, NULL);
            } else
                SetParent(hTaskBar, hReBarWnd);
            SetWH();
            ShowWindow(hTaskBar, SW_SHOW);
            SetTimer(hTaskBar, 3, 1000, NULL);
        }
    } else {
        if(TraySave.bMonitorTransparent)
            SetWindowLongPtr(hTaskBar, GWL_EXSTYLE, GetWindowLongPtr(hTaskBar, GWL_EXSTYLE) | WS_EX_TRANSPARENT);
        else
            SetWindowLongPtr(hTaskBar, GWL_EXSTYLE, GetWindowLongPtr(hTaskBar, GWL_EXSTYLE) & ~WS_EX_TRANSPARENT);
    }
}
#define MISC_CONTROL_3 0x3+((0x18)<<3)
int GetCpuTemp(DWORD Core) {
    if (bRing0) {
        SetThreadAffinityMask(GetCurrentThread(), Core);
        DWORD eax = 0, ebx, ecx, edx;
        if (!bIntel) {
            Cpuid(1, &eax, &ebx, &ecx, &edx);
            int family = ((eax >> 20) & 0xFF) + ((eax >> 8) & 0xF);
            if (family > 0xf) {
                DWORD miscReg;
                ReadPciConfigDwordEx(MISC_CONTROL_3, 0xa4, &miscReg);
                return (miscReg >> 21) >> 3;
            } else {
                DWORD miscReg;
                ReadPciConfigDwordEx(MISC_CONTROL_3, 0xe4, &miscReg);
                return ((miscReg & 0xFF0000) >> 16) - 49;
            }
        } else {
            DWORD IAcore;
            int Tjunction = 100;
            Rdmsr(0x1A2, &eax, &edx);
            if (eax & 0x20000000)
                Tjunction = 85;
            Rdmsr(0x19C, &eax, &edx);
            IAcore = eax;
            IAcore &= 0xFF0000;
            IAcore = IAcore >> 16;
            return Tjunction - IAcore;
        }
    }
    return 0;
}
void LoadTemperatureDLL() {
    if (!InitOpenLibSys(&m_hOpenLibSys))
        bRing0 = FALSE;
    else {
        bRing0 = TRUE;
        DWORD eax, ebx, ecx, edx;
        Cpuid(0, &eax, &ebx, &ecx, &edx);
        bIntel = TRUE;
        if (ebx == 0x68747541) {
            bIntel = FALSE;
        }
    }
#ifdef _WIN64
    hNVDLL = LoadLibrary(L"nvapi64.dll");
#else
    hNVDLL = LoadLibrary(L"nvapi.dll");
#endif
    if (hNVDLL) {
        NvAPI_QueryInterface = (NvAPI_QueryInterface_t)GetProcAddress(hNVDLL, "nvapi_QueryInterface");
        if (NvAPI_QueryInterface) {
            NvAPI_Initialize_t NvAPI_Initialize = (NvAPI_Initialize_t)NvAPI_QueryInterface(ID_NvAPI_Initialize);
            NvAPI_EnumPhysicalGPUs_t NvAPI_EnumPhysicalGPUs = (NvAPI_EnumPhysicalGPUs_t)NvAPI_QueryInterface(ID_NvAPI_EnumPhysicalGPUs);
            NvAPI_GPU_GetThermalSettings = (NvAPI_GPU_GetThermalSettings_t)NvAPI_QueryInterface(ID_NvAPI_GPU_GetThermalSettings);
            if (NvAPI_Initialize != NULL && NvAPI_EnumPhysicalGPUs != NULL && NvAPI_GPU_GetThermalSettings != NULL) {
                if (NvAPI_Initialize() == 0) {
                    for (NvU32 PhysicalGpuIndex = 0; PhysicalGpuIndex < 4; PhysicalGpuIndex++) {
                        hPhysicalGpu[PhysicalGpuIndex] = 0;
                    }
                    int physicalGpuCount;
                    NvAPI_EnumPhysicalGPUs(hPhysicalGpu, &physicalGpuCount);
                } else {
                    FreeLibrary(hNVDLL);
                    hNVDLL = NULL;
                }
            } else {
                FreeLibrary(hNVDLL);
                hNVDLL = NULL;
            }
        } else {
            FreeLibrary(hNVDLL);
            hNVDLL = NULL;
        }
    }
#ifdef _WIN64
    hATIDLL = LoadLibrary(L"atiadlxx.dll");
#else
    hATIDLL = LoadLibrary(L"atiadlxy.dll");
#endif
    if (hATIDLL) {
        ADL_Main_Control_Create = (ADL_MAIN_CONTROL_CREATE)GetProcAddress(hATIDLL, "ADL_Main_Control_Create");
        ADL_Main_Control_Destroy = (ADL_MAIN_CONTROL_DESTROY)GetProcAddress(hATIDLL, "ADL_Main_Control_Destroy");
        ADL_Overdrive5_Temperature_Get = (ADL_OVERDRIVE5_TEMPERATURE_GET)GetProcAddress(hATIDLL, "ADL_Overdrive5_Temperature_Get");
        if (NULL != ADL_Main_Control_Create &&
                NULL != ADL_Main_Control_Destroy
           ) {
            if (ADL_OK != ADL_Main_Control_Create(ADL_Main_Memory_Alloc, 1)) {
                FreeLibrary(hATIDLL);
                hATIDLL = NULL;
            }
        } else {
            FreeLibrary(hATIDLL);
            hATIDLL = NULL;
        }
    }
}
void FreeTemperatureDLL() {
    if (hATIDLL) {
        ADL_Main_Control_Destroy();
        FreeLibrary(hATIDLL);
        hATIDLL = NULL;
    }
    if (hNVDLL) {
        FreeLibrary(hNVDLL);
        hNVDLL = NULL;
    }
    if (m_hOpenLibSys)
        DeinitOpenLibSys(&m_hOpenLibSys);
    m_hOpenLibSys = NULL;
}
void OpenSetting() {
    if (IsWindow(hSetting)) {
        SetForegroundWindow(hSetting);
        return;
    }
    hSetting = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_SETTING), NULL, (DLGPROC)SettingProc);
    if (!hSetting) {
        return;
    }
    SendMessage(hSetting, WM_SETICON, ICON_BIG, (LPARAM)(HICON)iMain);
    SendMessage(hSetting, WM_SETICON, ICON_SMALL, (LPARAM)(HICON)iMain);
    CheckRadioButton(hSetting, IDC_RADIO_NORMAL, IDC_RADIO_MAXIMIZE, IDC_RADIO_NORMAL);
    iProject = iWindowMode;
    if(iProject == 0)
        CheckRadioButton(hSetting, IDC_RADIO_NORMAL, IDC_RADIO_MAXIMIZE, IDC_RADIO_NORMAL);
    else
        CheckRadioButton(hSetting, IDC_RADIO_NORMAL, IDC_RADIO_MAXIMIZE, IDC_RADIO_MAXIMIZE);
    if (TraySave.aMode[iProject] == ACCENT_DISABLED)
        CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_DEFAULT);
    else if (TraySave.aMode[iProject] == ACCENT_ENABLE_TRANSPARENTGRADIENT)
        CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_TRANSPARENT);
    else if (TraySave.aMode[iProject] == ACCENT_ENABLE_BLURBEHIND)
        CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_BLURBEHIND);
    else if (TraySave.aMode[iProject] == ACCENT_ENABLE_ACRYLICBLURBEHIND)
        CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_ACRYLIC);
    if (TraySave.iPos == 0)
        CheckRadioButton(hSetting, IDC_RADIO_LEFT, IDC_RADIO_RIGHT, IDC_RADIO_LEFT);
    else if (TraySave.iPos == 1)
        CheckRadioButton(hSetting, IDC_RADIO_LEFT, IDC_RADIO_RIGHT, IDC_RADIO_CENTER);
    else if (TraySave.iPos == 2)
        CheckRadioButton(hSetting, IDC_RADIO_LEFT, IDC_RADIO_RIGHT, IDC_RADIO_RIGHT);
    if (LOWORD(TraySave.iUnit) == 0)
        CheckRadioButton(hSetting, IDC_RADIO_AUTO, IDC_RADIO_MB, IDC_RADIO_AUTO);
    else if (LOWORD(TraySave.iUnit) == 1)
        CheckRadioButton(hSetting, IDC_RADIO_AUTO, IDC_RADIO_MB, IDC_RADIO_KB);
    else if (LOWORD(TraySave.iUnit) == 2)
        CheckRadioButton(hSetting, IDC_RADIO_AUTO, IDC_RADIO_MB, IDC_RADIO_MB);
    if (HIWORD(TraySave.iUnit) == 0)
        CheckRadioButton(hSetting, IDC_RADIO_BYTE, IDC_RADIO_BIT, IDC_RADIO_BYTE);
    else
        CheckRadioButton(hSetting, IDC_RADIO_BYTE, IDC_RADIO_BIT, IDC_RADIO_BIT);
    CheckDlgButton(hSetting, IDC_CHECK_TRAYICON, TraySave.bTrayIcon);
    CheckDlgButton(hSetting, IDC_CHECK_MONITOR, TraySave.bMonitor);
    CheckDlgButton(hSetting, IDC_CHECK_TRAFFIC, TraySave.bMonitorTraffic);
    CheckDlgButton(hSetting, IDC_CHECK_TEMPERATURE, TraySave.bMonitorTemperature);
    CheckDlgButton(hSetting, IDC_CHECK_USAGE, TraySave.bMonitorUsage);
    CheckDlgButton(hSetting, IDC_CHECK_SOUND, TraySave.bSound);
    CheckDlgButton(hSetting, IDC_CHECK_MONITOR_PDH, TraySave.bMonitorPDH);
    CheckDlgButton(hSetting, IDC_CHECK_MONITOR_SIMPLE, TraySave.iMonitorSimple);
    CheckDlgButton(hSetting, IDC_CHECK_MONITOR_LEFT, TraySave.bMonitorLeft);
    CheckDlgButton(hSetting, IDC_CHECK_MONITOR_FLOAT, TraySave.bMonitorFloat);
    CheckDlgButton(hSetting, IDC_CHECK_TRANSPARENT, TraySave.bMonitorTransparent);
    CheckDlgButton(hSetting, IDC_CHECK_TIPS, TraySave.bMonitorTips);
    SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA, TBM_SETRANGE, 0, MAKELPARAM(0, 255));
    SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA, TBM_SETPOS, TRUE, TraySave.bAlpha[iProject]);
    SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA_B, TBM_SETRANGE, 0, MAKELPARAM(0, 255));
    BYTE bAlphaB = TraySave.dAlphaColor[iProject] >> 24;
    SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA_B, TBM_SETPOS, TRUE, bAlphaB);
    SendDlgItemMessage(hSetting, IDC_CHECK_AUTORUN, BM_SETCHECK, AutoRun(FALSE, FALSE), NULL);
    bSettingInit = TRUE;
    SetDlgItemInt(hSetting, IDC_EDIT1, TraySave.dNumValues[0] / 1048576, 0);
    SetDlgItemInt(hSetting, IDC_EDIT2, TraySave.dNumValues[1] / 1048576, 0);
    SetDlgItemInt(hSetting, IDC_EDIT3, TraySave.dNumValues[2], 0);
    SetDlgItemInt(hSetting, IDC_EDIT4, TraySave.dNumValues[3], 0);
    SetDlgItemInt(hSetting, IDC_EDIT5, TraySave.dNumValues[4], 0);
    SetDlgItemInt(hSetting, IDC_EDIT6, TraySave.dNumValues[5], 0);
    SetDlgItemInt(hSetting, IDC_EDIT7, TraySave.dNumValues[6], 0);
    SetDlgItemInt(hSetting, IDC_EDIT8, TraySave.dNumValues[7], 0);
    SetDlgItemInt(hSetting, IDC_EDIT9, TraySave.dNumValues[8] / 1048576, 0);
    SetDlgItemInt(hSetting, IDC_EDIT10, TraySave.dNumValues[9], 0);
    SetDlgItemInt(hSetting, IDC_EDIT11, TraySave.dNumValues[10], 0);
    SetDlgItemInt(hSetting, IDC_EDIT12, TraySave.dNumValues[11], 0);
    SetDlgItemInt(hSetting, IDC_EDIT_TIME, TraySave.FlushTime, 0);
    SetDlgItemText(hSetting, IDC_EDIT14, TraySave.szTrafficOut);
    SetDlgItemText(hSetting, IDC_EDIT15, TraySave.szTrafficIn);
    SetDlgItemText(hSetting, IDC_EDIT16, TraySave.szTemperatureCPU);
    SetDlgItemText(hSetting, IDC_EDIT17, TraySave.szTemperatureGPU);
    SetDlgItemText(hSetting, IDC_EDIT18, TraySave.szTemperatureCPUUnit);
    SetDlgItemText(hSetting, IDC_EDIT19, TraySave.szTemperatureGPUUnit);
    SetDlgItemText(hSetting, IDC_EDIT20, TraySave.szUsageCPU);
    SetDlgItemText(hSetting, IDC_EDIT21, TraySave.szUsageMEM);
    SetDlgItemText(hSetting, IDC_EDIT22, TraySave.szUsageCPUUnit);
    SetDlgItemText(hSetting, IDC_EDIT23, TraySave.szUsageMEMUnit);
    bSettingInit = FALSE;
    oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
    oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_BACKGROUND), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
    oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_TRAFFIC_LOW), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
    oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_TRAFFIC_MEDIUM), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
    oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_TRAFFIC_HIGH), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
    oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_LOW), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
    oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_MEDUIM), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
    oldColorButtonPoroc = (WNDPROC)SetWindowLongPtr(GetDlgItem(hSetting, IDC_BUTTON_COLOR_HIGH), GWLP_WNDPROC, (LONG_PTR)ColorButtonProc);
    ShowWindow(hSetting, SW_SHOW);
    UpdateWindow(hSetting);
    SetForegroundWindow(hSetting);
}
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                      _In_opt_ HINSTANCE hPrevInstance,
                      _In_ LPWSTR    lpCmdLine,
                      _In_ int       nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);


    if (lpCmdLine[0] == L'c') {
        CloseHandle(ShellExecute(NULL, L"open", L"control.exe", &lpCmdLine[1], NULL, SW_SHOW));
        return 0;
    } else if (lpCmdLine[0] == L'o') {
        CloseHandle(ShellExecute(NULL, L"open", &lpCmdLine[1], NULL, NULL, SW_SHOW));
        return 0;
    }
    if (IsUserAdmin()) {
        Init();
        SERVICE_TABLE_ENTRY st[] = {
            { szAppName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
            { NULL, NULL }
        };
        if (_wcsicmp(lpCmdLine, L"/install") == 0) {
            InstallService();
            return 0;
        } else if (_wcsicmp(lpCmdLine, L"/uninstall") == 0) {
            UninstallService();
            return 0;
        } else if (_wcsicmp(lpCmdLine, L"/start") == 0) {
            ServiceCtrlStart();
            return 0;
        } else if (_wcsicmp(lpCmdLine, L"/stop") == 0) {
            ServiceCtrlStop();
            return 0;
        }
        if (ServiceRunState() != SERVICE_RUNNING) {
            if (IsServiceInstalled()) {
                if (ServiceRunState() == SERVICE_STOPPED)
                    ServiceCtrlStart();
                StartServiceCtrlDispatcher(st);
                return 0;
            }
        }
        ServiceCtrlStop();
    }
    while (hTray == NULL) {
        hTray = FindWindow(szShellTray, NULL);
        if (hTray == NULL)
            Sleep(100);
    }
    hInst = hInstance;  
    ReadReg();
    hMutex = CreateMutex(NULL, TRUE, L"_TrayS_");
    if (hMutex != NULL) {
        if (ERROR_ALREADY_EXISTS == GetLastError()) {
            CloseHandle(hMutex);
            if (FindWindow(NULL, szAppName))
                return 0;
            EnumWindows((WNDENUMPROC)FindWindowFunc, 0);
        } else {
            iMain = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_TRAYS));
            hDwmapi = LoadLibrary(L"dwmapi.dll");
            if (hDwmapi) {
                DwmGetWindowAttribute = (pfnDwmGetWindowAttribute)GetProcAddress(hDwmapi, "DwmGetWindowAttribute");
            }

            SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
            if(TraySave.bMonitorTemperature)
                LoadTemperatureDLL();
            pProcessTime = NULL;
            EnableDebugPrivilege(TRUE);
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            dNumProcessor = si.dwNumberOfProcessors;
            ppmu[0] = &pmu[0];
            ppmu[1] = &pmu[1];
            ppmu[2] = &pmu[2];
            ppcu[0] = &pcu[0];
            ppcu[1] = &pcu[1];
            ppcu[2] = &pcu[2];
            if (!InitInstance(hInstance, nCmdShow)) {
                return FALSE;
            }
            MSG msg;
            while (GetMessage(&msg, nullptr, 0, 0)) {
                if (!IsDialogMessage(hMain, &msg) && !IsDialogMessage(hSetting, &msg)) {
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }
            }
            DestroyWindow(hTaskBar);
            DestroyWindow(hTaskTips);
            DestroyWindow(hMain);
            Shell_NotifyIcon(NIM_DELETE, &nid);
            DestroyIcon(iMain);
            DeleteObject(hFont);
            FreeLibrary(hDwmapi);
            FreeLibrary(hIphlpapi);
            FreeLibrary(hOleacc);
            FreeLibrary(hPDH);
            free(mi);
            free(piaa);
            free(traffic);
            if(hMutex)
                CloseHandle(hMutex);
            FreeTemperatureDLL();
        }
    }

    return (int) 0;
}
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    hMain = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_MAIN), NULL, (DLGPROC)MainProc);
    if (!hMain) {
        return FALSE;
    }
    ChangeWindowMessageFilter(WM_TRAYS, MSGFLT_ADD);
    nid.cbSize = sizeof NOTIFYICONDATA;
    nid.uID = WM_IAWENTRAY;
    nid.hWnd = hMain;
    nid.hIcon = iMain;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_IAWENTRAY;
    LoadString(hInst, IDS_TIPS, nid.szTip, 88);
    if (TraySave.bTrayIcon)
        ::Shell_NotifyIcon(NIM_ADD, &nid);

    MemoryStatusEx.dwLength = sizeof MEMORYSTATUSEX;
    HDC hdc = GetDC(hMain);
    iDPI = GetDeviceCaps(hdc, LOGPIXELSY);
    ::ReleaseDC(hMain, hdc);
    if (TraySave.bMonitor) { 
        OpenTaskBar();
    }
    if (TraySave.aMode[0] != ACCENT_DISABLED || TraySave.aMode[1] != ACCENT_DISABLED)
        SetTimer(hMain, 3, TraySave.FlushTime, NULL);
    if(TraySave.iPos || TraySave.bMonitor)
        SetTimer(hMain, 6, 1000, NULL);
    SetTimer(hMain, 11, 6000, NULL);
    return TRUE;
}
BOOL Find(IAccessible *paccParent, int iRole, IAccessible **paccChild) { 
    HRESULT hr;
    long numChildren;
    unsigned long numFetched;
    VARIANT varChild;
    int indexCount;
    IAccessible *pChild = NULL;
    IEnumVARIANT *pEnum = NULL;
    IDispatch *pDisp = NULL;
    BOOL found = false;
    hr = paccParent->QueryInterface(IID_IEnumVARIANT, (PVOID *)& pEnum);
    if (pEnum)
        pEnum->Reset();
    paccParent->get_accChildCount(&numChildren);
    for (indexCount = 1; indexCount <= numChildren && !found; indexCount++) {
        pChild = NULL;
        if (pEnum)
            hr = pEnum->Next(1, &varChild, &numFetched);
        else {
            varChild.vt = VT_I4;
            varChild.lVal = indexCount;
        }
        if (varChild.vt == VT_I4) {
            pDisp = NULL;
            hr = paccParent->get_accChild(varChild, &pDisp);
        } else
            pDisp = varChild.pdispVal;
        if (pDisp) {
            hr = pDisp->QueryInterface(IID_IAccessible, (void **)&pChild);
            hr = pDisp->Release();
        }
        if (pChild) {
            VariantInit(&varChild);
            varChild.vt = VT_I4;
            varChild.lVal = CHILDID_SELF;
            *paccChild = pChild;
        }
        VARIANT varState;
        pChild->get_accState(varChild, &varState);
        if ((varState.intVal & STATE_SYSTEM_INVISIBLE) == 0) {
            VARIANT varRole;
            pChild->get_accRole(varChild, &varRole);
            if (varRole.lVal == iRole) {
                paccParent->Release();
                found = true;
                break;
            }
        }
        if (!found && pChild) {
            pChild->Release();
        }
    }
    if (pEnum)
        pEnum->Release();
    return found;
}
int oleft = 0, otop = 0;
void SetTaskBarPos(HWND hTaskListWnd, HWND hTrayWnd, HWND hTaskWnd, HWND hReBarWnd, BOOL bMainTray) { 
    if (hOleacc == NULL) {
        hOleacc = LoadLibrary(L"oleacc.dll");
        if (hOleacc) {
            AccessibleObjectFromWindowT = (pfnAccessibleObjectFromWindow)GetProcAddress(hOleacc, "AccessibleObjectFromWindow");
            AccessibleChildrenT = (pfnAccessibleChildren)GetProcAddress(hOleacc, "AccessibleChildren");
        }
    }
    if (hOleacc == NULL)
        return;
    IAccessible *pAcc = NULL;
    AccessibleObjectFromWindowT(hTaskListWnd, OBJID_WINDOW, IID_IAccessible, (void **)&pAcc);
    IAccessible *paccChlid = NULL;
    if (pAcc) {
        if (Find(pAcc, 22, &paccChlid) == FALSE) {
            return;
        }
    } else
        return;
    long childCount;
    long returnCount;
    LONG left, top, width, height;
    LONG ol = 0, ot = 0;
    int tWidth = 0;
    int tHeight = 0;
    if (paccChlid) {
        if (paccChlid->get_accChildCount(&childCount) == S_OK && childCount != 0) {
            VARIANT *pArray = new VARIANT[childCount];
            if (AccessibleChildrenT(paccChlid, 0L, childCount, pArray, &returnCount) == S_OK) {
                for (int x = 0; x < returnCount; x++) {
                    VARIANT vtChild = pArray[x];
                    {

                        VARIANT varState;
                        paccChlid->get_accState(vtChild, &varState);
                        if ((varState.intVal & STATE_SYSTEM_INVISIBLE) == 0) {
                            VARIANT varRole;
                            paccChlid->get_accRole(vtChild, &varRole);
                            if (varRole.intVal == 0x2b || varRole.intVal == 0x39) {
                                paccChlid->accLocation(&left, &top, &width, &height, vtChild);
                                if (ol != left) {
                                    tWidth += width;
                                    ol = left;
                                }
                                if (ot != top) {
                                    tHeight += height;
                                    ot = top;
                                }
                            }
                        }
                    }
                }
            }
            delete[] pArray;
        }
        paccChlid->Release();
    } else
        return;

    RECT lrc, src, trc;
    GetWindowRect(hTaskListWnd, &lrc);
    GetWindowRect(hTrayWnd, &src);
    GetWindowRect(hTaskWnd, &trc);
    BOOL Vertical = FALSE;
    if (src.right - src.left < src.bottom - src.top)
        Vertical = TRUE;
    SendMessage(hReBarWnd, WM_SETREDRAW, TRUE, 0);
    int lr, tb;
    if (Vertical) {
        int t = trc.left - src.left;
        int b = src.bottom - trc.bottom;
        if (bMainTray && TraySave.bMonitor && TraySave.bMonitorFloat == FALSE) {
            if (TraySave.bMonitorLeft == FALSE)
                b += mHeight;
            else
                t += mHeight;
        }
        if (t > b)
            tb = t;
        else
            tb = b;
    } else {
        int l = trc.left - src.left;
        int r = src.right - trc.right;
        if (TraySave.bMonitor && bMainTray && TraySave.bMonitorFloat == FALSE) {
            if (TraySave.bMonitorLeft == FALSE)
                r += mWidth;
            else
                l += mWidth;
        }
        if (l > r)
            lr = l;
        else
            lr = r;
    }
    int nleft, ntop;
    if ((TraySave.iPos == 2 || (Vertical == FALSE && tWidth >= trc.right - trc.left - lr ) || (Vertical && tHeight >= trc.bottom - trc.top - tb)) && TraySave.iPos != 0) {
        if (Vertical) {
            ntop = trc.bottom - trc.top - tHeight;
            if (TraySave.bMonitorLeft == FALSE && TraySave.bMonitor && bMainTray && TraySave.bMonitorFloat == FALSE)
                ntop -= mHeight + 2;
        } else {
            nleft = trc.right - trc.left - tWidth;
            if (TraySave.bMonitorLeft == FALSE && TraySave.bMonitor && bMainTray && TraySave.bMonitorFloat == FALSE)
                nleft -= mWidth + 2;
        }
    } else if (TraySave.iPos == 0) {
        if (TraySave.bMonitorLeft && TraySave.bMonitor && bMainTray && TraySave.bMonitorFloat == FALSE) {
            nleft = mWidth;
            ntop = mHeight;
        } else {
            nleft = 0;
            ntop = 0;
            if (TraySave.bMonitor == FALSE) {
                KillTimer(hMain, 6);
                SetTimer(hMain, 11, 1000, NULL);
            }
        }
    } else if (TraySave.iPos == 1) {
        if (Vertical)
            ntop = src.top + (src.bottom - src.top) / 2 - trc.top  - tHeight / 2;
        else
            nleft = src.left + (src.right - src.left) / 2 - trc.left  - tWidth / 2;
        if (bMainTray) {
            if(Vertical)
                ntop -= 2;
            else
                nleft -= 2;
        }
    }
    if (Vertical) {
        if (bMainTray) {
            if (otop == 0)
                lrc.top = ntop;
            else
                lrc.top = otop;
            otop = ntop;
            while (ntop != lrc.top) {
                if (ntop > lrc.top)
                    ++lrc.top;
                else
                    --lrc.top;
                SetWindowPos(hTaskListWnd, 0, 0, lrc.top, lrc.right - lrc.left, lrc.bottom - lrc.top, SWP_NOSIZE | SWP_ASYNCWINDOWPOS | SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOSENDCHANGING);
            }
        }
        SetWindowPos(hTaskListWnd, 0, 0, ntop, lrc.right - lrc.left, lrc.bottom - lrc.top, SWP_NOSIZE | SWP_ASYNCWINDOWPOS | SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOSENDCHANGING);
    } else {
        if (bMainTray) {
            if (oleft == 0)
                lrc.left = nleft;
            else
                lrc.left = oleft;
            oleft = nleft;
            while (nleft != lrc.left) {
                if (nleft > lrc.left)
                    ++lrc.left;
                else
                    --lrc.left;
                SetWindowPos(hTaskListWnd, 0, lrc.left, 0, lrc.right - lrc.left, lrc.bottom - lrc.top, SWP_NOSIZE | SWP_ASYNCWINDOWPOS | SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOSENDCHANGING);
            }
        }
        SetWindowPos(hTaskListWnd, 0, nleft, 0, lrc.right - lrc.left, lrc.bottom - lrc.top, SWP_NOSIZE | SWP_ASYNCWINDOWPOS | SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOSENDCHANGING);
    }
    if (TraySave.iPos != 0)
        SendMessage(hReBarWnd, WM_SETREDRAW, FALSE, 0);
    ShowWindow(hTaskWnd, SW_SHOWNOACTIVATE);
}
int otleft, ottop;
void SetWH() {
    mWidth = 0;
    mHeight = 0;
    HDC mdc = GetDC(hMain);
    TraySave.TraybarFont.lfHeight = DPI(TraySave.TraybarFontSize);
    DeleteObject(hFont);
    hFont = CreateFontIndirect(&TraySave.TraybarFont); 
    HFONT oldFont = (HFONT)SelectObject(mdc, hFont);
    SIZE tSize;
    WCHAR sz[16];
    if (TraySave.bMonitorTraffic) {
        if (TraySave.iMonitorSimple == 1)
            ::GetTextExtentPoint(mdc, L"↓:8.88M", wcslen(L"↓:8.88M"), &tSize);
        else if (TraySave.iMonitorSimple == 2)
            ::GetTextExtentPoint(mdc, L"8.88M", wcslen(L"8.88M"), &tSize);
        else {
            swprintf_s(sz, 16, L"%s8.88M", TraySave.szTrafficOut);
            ::GetTextExtentPoint(mdc, sz, wcslen(sz), &tSize);
        }
        wTraffic = tSize.cx + tSize.cy / 4;
        mWidth += wTraffic;
        mHeight += tSize.cy * 2;
        wHeight = tSize.cy;
    }
    if (TraySave.bMonitorTemperature) {
        if (TraySave.iMonitorSimple == 1)
            ::GetTextExtentPoint(mdc, L"88℃", wcslen(L"88℃"), &tSize);
        else if (TraySave.iMonitorSimple == 2)
            ::GetTextExtentPoint(mdc, L"88", wcslen(L"88"), &tSize);
        else {
            swprintf_s(sz, 16, L"%s88%s", TraySave.szTemperatureGPU, TraySave.szTemperatureGPUUnit);
            ::GetTextExtentPoint(mdc, sz, wcslen(sz), &tSize);
        }
        wTemperature = tSize.cx + tSize.cy / 4;
        mWidth += wTemperature;
        wHeight = tSize.cy;
        if (bRing0)
            mHeight += tSize.cy * 2;
        else
            mHeight += tSize.cy;
    }
    if (TraySave.bMonitorUsage) {
        if (TraySave.iMonitorSimple == 1)
            ::GetTextExtentPoint(mdc, L"88%", wcslen(L"88%"), &tSize);
        else if (TraySave.iMonitorSimple == 2)
            ::GetTextExtentPoint(mdc, L"88", wcslen(L"88"), &tSize);
        else {
            swprintf_s(sz, 16, L"%s88%s", TraySave.szUsageMEM, TraySave.szUsageMEMUnit);
            ::GetTextExtentPoint(mdc, sz, wcslen(sz), &tSize);
        }
        wUsage = tSize.cx + tSize.cy / 4;
        mWidth += wUsage;
        wHeight = tSize.cy;
        mHeight += tSize.cy * 2;
    }
    SelectObject(mdc, oldFont);
    ReleaseDC(hMain, mdc);
    ottop = -1;
    otleft = -1;
    AdjustWindowPos();
}
void AdjustWindowPos() { 
    if (IsWindow(hTaskBar) == FALSE)
        OpenTaskBar();
    if (TraySave.bMonitorFloat) {
        RECT ScreenRect;
        GetScreenRect(hTaskBar, &ScreenRect, FALSE);
        if (TraySave.dMonitorPoint.x + mWidth > ScreenRect.right)
            TraySave.dMonitorPoint.x = ScreenRect.right - mWidth;
        if (TraySave.dMonitorPoint.y + wHeight * 2 > ScreenRect.bottom)
            TraySave.dMonitorPoint.y = ScreenRect.bottom - wHeight * 2;
        SetWindowPos(hTaskBar, HWND_TOPMOST, TraySave.dMonitorPoint.x, TraySave.dMonitorPoint.y, mWidth, wHeight * 2, SWP_NOACTIVATE);
        VTray = FALSE;
        return;
    }
    RECT rrc, trc;
    GetWindowRect(hReBarWnd, &rrc);
    GetWindowRect(hTaskWnd, &trc);
    if (rrc.right - rrc.left > rrc.bottom - rrc.top)
        VTray = FALSE;
    else
        VTray = TRUE;
    if(VTray == FALSE) {
        int nleft;
        if (TraySave.bMonitorLeft)
            nleft = trc.left - rrc.left;
        else
            nleft = trc.right - trc.left - mWidth + (trc.left - rrc.left);
        int h = wHeight * 2;
        int ntop;
        BOOL sTray = FALSE;
        if (rrc.bottom - rrc.top < h) {
            sTray = TRUE;
            h = rrc.bottom - rrc.top - 2;
            ntop = 1;
        } else
            ntop = (trc.bottom - trc.top - h) / 2;
        if (nleft != otleft || ottop != ntop) {
            HDC hdc = GetDC(hTaskBar);
            RECT crc;
            GetClientRect(hTaskBar, &crc);
            HBRUSH hb = CreateSolidBrush(RGB(0, 0, 0));
            FillRect(hdc, &crc, hb);
            DeleteObject(hb);
            ReleaseDC(hTaskBar, hdc);
            otleft = nleft;
            ottop = ntop;
            MoveWindow(hTaskBar, nleft, ntop, mWidth, h, FALSE);
        }
    } else {
        int ntop;
        if (TraySave.bMonitorLeft)
            ntop = trc.top - rrc.top;
        else
            ntop = trc.bottom - trc.top - mHeight + (trc.top - rrc.top);
        int nleft = 2;
        int w = trc.right - trc.left - 4;
        if (ntop != ottop || otleft != w) {
            HDC hdc = GetDC(hTaskBar);
            RECT crc;
            GetClientRect(hTaskBar, &crc);
            HBRUSH hb = CreateSolidBrush(RGB(0, 0, 0));
            FillRect(hdc, &crc, hb);
            DeleteObject(hb);
            ReleaseDC(hTaskBar, hdc);
            ottop = ntop;
            otleft = w;
            MoveWindow(hTaskBar, nleft, ntop, w, mHeight, FALSE);
        }
    }
}
DWORD dwIPSize = 0;
DWORD dwMISize = 0;
INT_PTR CALLBACK TaskTipsProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) { 
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;
    case WM_MOUSEMOVE: {
        POINT pt;
        pt.x = GET_X_LPARAM(lParam);
        pt.y = GET_Y_LPARAM(lParam);
        RECT rc;
        GetClientRect(hDlg, &rc);
        rc.top = nTraffic * wTipsHeight;
        rc.bottom = (nTraffic + 6) * wTipsHeight;
        rc.left = rc.right * 100 / 160;
        rc.right = rc.right * 100 / 148;
        if (PtInRect(&rc, pt)) {
            inTipsProcessX = TRUE;
            ::InvalidateRect(hDlg, NULL, TRUE);
        } else {
            inTipsProcessX = FALSE;
        }
    }
    break;
    case WM_LBUTTONDOWN: {
        POINT pt;
        pt.x = GET_X_LPARAM(lParam);
        pt.y = GET_Y_LPARAM(lParam);
        if(pt.y < nTraffic * wTipsHeight)
            RunProcess(szNetCpl);
        else if (pt.y < (nTraffic + 6) * wTipsHeight) {
            RECT rc;
            GetClientRect(hDlg, &rc);
            rc.left = rc.right * 100 / 160;
            rc.right = rc.right * 100 / 148;
            if (PtInRect(&rc, pt)) {
                int x = (pt.y / wTipsHeight) - nTraffic;
                DWORD pid;
                if (x < 3)
                    pid = ppcu[x]->dwProcessID;
                else
                    pid = ppmu[x - 3]->dwProcessID;
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                if (hProc) {
                    TerminateProcess(hProc, 0);
                    CloseHandle(hProc);
                    inTipsProcessX = FALSE;
                    GetCursorPos(&pt);
                    SetCursorPos(pt.x + 88, pt.y);
                }
            } else
                RunProcess(szTaskmgr);
        } else
            RunProcess(szPowerCpl);
        return TRUE;
    }
    break;
    case WM_MOUSELEAVE: {
        POINT pt;
        GetCursorPos(&pt);
        if (WindowFromPoint(pt) != hTaskBar) {
            if (pProcessTime != NULL) {
                delete[]pProcessTime;
                pProcessTime = NULL;
            }
            ShowWindow(hTaskTips, SW_HIDE);
            SetTimer(hMain, 11, 1000, NULL);
        }
    }
    break;
    case WM_ERASEBKGND:
        HDC hdc = (HDC)wParam; 
        RECT rc, crc;
        GetClientRect(hDlg, &rc);
        crc = rc;
        HDC mdc = CreateCompatibleDC(hdc);
        HBITMAP hMemBmp = CreateCompatibleBitmap(hdc, rc.right - rc.left, rc.bottom - rc.top);
        HBITMAP oldBmp = (HBITMAP)SelectObject(mdc, hMemBmp);
        {
            TraySave.TipsFont.lfHeight = TraySave.TipsFontSize;
            HFONT hTipsFont = CreateFontIndirect(&TraySave.TipsFont); 
            HFONT oldFont = (HFONT)SelectObject(mdc, hTipsFont);
            WCHAR sz[64];
            SetBkMode(mdc, TRANSPARENT);
            COLORREF rgb;
            rgb = RGB(192, 192, 192);
            SetTextColor(mdc, rgb);
            rc.bottom = wTipsHeight;
            HBRUSH hb = CreateSolidBrush(RGB(22, 22, 22));
            for (int i = 0; i < nTraffic / 2 + 4; i++) {
                FillRect(mdc, &rc, hb);
                OffsetRect(&rc, 0, wTipsHeight * 2);
            }
            DeleteObject(hb);
            HPEN hp = CreatePen(PS_DOT, 1, RGB(98, 98, 98));
            HPEN oldpen = (HPEN)SelectObject(mdc, hp);
            MoveToEx(mdc, crc.right * 10 / 23, 0, NULL);
            LineTo(mdc, crc.right * 10 / 23, wTipsHeight * nTraffic);
            MoveToEx(mdc, crc.right * 7 / 10, 0, NULL);
            LineTo(mdc, crc.right * 7 / 10, wTipsHeight * nTraffic);
            MoveToEx(mdc, crc.right * 85 / 100, 0, NULL);
            LineTo(mdc, crc.right * 85 / 100, wTipsHeight * nTraffic);

            MoveToEx(mdc, crc.right * 100 / 124, wTipsHeight * nTraffic, NULL);
            LineTo(mdc, crc.right * 100 / 124, wTipsHeight * (nTraffic + 6));
            MoveToEx(mdc, crc.right * 100 / 148, wTipsHeight * nTraffic, NULL);
            LineTo(mdc, crc.right * 100 / 148, wTipsHeight * (nTraffic + 6));
            MoveToEx(mdc, crc.right * 100 / 160, wTipsHeight * nTraffic, NULL);
            LineTo(mdc, crc.right * 100 / 160, wTipsHeight * (nTraffic + 6));
            MoveToEx(mdc, 0, wTipsHeight * nTraffic, NULL);
            LineTo(mdc, crc.right, wTipsHeight * nTraffic);
            MoveToEx(mdc, 0, wTipsHeight * (nTraffic + 3), NULL);
            LineTo(mdc, crc.right, wTipsHeight * (nTraffic + 3));
            MoveToEx(mdc, 0, wTipsHeight * (nTraffic + 6), NULL);
            LineTo(mdc, crc.right, wTipsHeight * (nTraffic + 6));
            SelectObject(mdc, oldpen);
            DeleteObject(hp);
            rc.bottom = wTipsHeight;
            rc.top = 0;
            for (int i = 0; i < nTraffic; i++) {
                rc.left = 2;
                DrawText(mdc, traffic[i].FriendlyName, (int)wcslen(traffic[i].FriendlyName), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                rc.left = crc.right * 10 / 23;
                rc.right = crc.right * 7 / 10;
                DrawText(mdc, traffic[i].IP4, (int)wcslen(traffic[i].IP4), &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                float f_in_byte = (float)traffic[i].in_byte;
                if (traffic[i].in_byte < 1000)
                    swprintf_s(sz, 16, L"↓:%db", traffic[i].in_byte);
                else if (traffic[i].in_byte < 1000000) {
                    f_in_byte /= 1000;
                    if (f_in_byte >= 100)
                        swprintf_s(sz, 16, L"↓:%.fk", f_in_byte);
                    else if (f_in_byte >= 10)
                        swprintf_s(sz, 16, L"↓:%.1fk", f_in_byte);
                    else
                        swprintf_s(sz, 16, L"↓:%.2fk", f_in_byte);
                } else if (traffic[i].in_byte < 1000000000) {
                    f_in_byte /= 1000000;
                    if (f_in_byte >= 100)
                        swprintf_s(sz, 16, L"↓:%.fm", f_in_byte);
                    else if (f_in_byte >= 10)
                        swprintf_s(sz, 16, L"↓:%.1fm", f_in_byte);
                    else
                        swprintf_s(sz, 16, L"↓:%.2fm", f_in_byte);
                } else {
                    f_in_byte /= 1000000000;
                    if (f_in_byte >= 100)
                        swprintf_s(sz, 16, L"↓:%.fG", f_in_byte);
                    else if (f_in_byte >= 10)
                        swprintf_s(sz, 16, L"↓:%.1fG", f_in_byte);
                    else
                        swprintf_s(sz, 16, L"↓:%.2fG", f_in_byte);
                }
                rc.left = crc.right * 7 / 10 + 2;
                rc.right += crc.right;
                DrawText(mdc, sz, (int)wcslen(sz), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                float f_out_byte = (float)traffic[i].out_byte;
                if (traffic[i].out_byte < 1000)
                    swprintf_s(sz, 16, L"↑:%db", traffic[i].out_byte);
                else if (traffic[i].out_byte < 1000000) {
                    f_out_byte /= 1000;
                    if (f_out_byte >= 100)
                        swprintf_s(sz, 16, L"↑:%.fk", f_out_byte);
                    else if (f_out_byte >= 10)
                        swprintf_s(sz, 16, L"↑:%.1fk", f_out_byte);
                    else
                        swprintf_s(sz, 16, L"↑:%.2fk", f_out_byte);
                } else if (traffic[i].out_byte < 1000000000) {
                    f_out_byte /= 1000000;
                    if (f_out_byte >= 100)
                        swprintf_s(sz, 16, L"↑:%.fm", f_out_byte);
                    else if (f_out_byte >= 10)
                        swprintf_s(sz, 16, L"↑:%.1fm", f_out_byte);
                    else
                        swprintf_s(sz, 16, L"↑:%.2fm", f_out_byte);
                } else {
                    f_out_byte /= 1000000000;
                    if (f_out_byte >= 100)
                        swprintf_s(sz, 16, L"↑:%.fg", f_out_byte);
                    else if (f_out_byte >= 10)
                        swprintf_s(sz, 16, L"↑:%.1fg", f_out_byte);
                    else
                        swprintf_s(sz, 16, L"↑:%.2fg", f_out_byte);
                }
                rc.left = crc.right * 85 / 100 + 2;
                DrawText(mdc, sz, (int)wcslen(sz), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                OffsetRect(&rc, 0, wTipsHeight);
            }
            rc.left = 2;
            rc.right = crc.right - 2;
            POINT pt;
            GetCursorPos(&pt);
            ScreenToClient(hDlg, &pt);
            for (int i = 0; i < 3; i++) {
                SetTextColor(mdc, RGB(192, 192, 0));
                DrawText(mdc, ppcu[i]->szExe, (int)wcslen(ppcu[i]->szExe), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                swprintf_s(sz, 16, L"%.2f%%", ppcu[i]->fCpuUsage);
                DrawText(mdc, sz, (int)wcslen(sz), &rc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
                RECT cr = rc;
                cr.left = crc.right * 100 / 148;
                cr.right = crc.right * 8 / 10;
                swprintf_s(sz, 16, L"%d", ppcu[i]->dwProcessID);
                DrawText(mdc, sz, (int)wcslen(sz), &cr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                cr.left = crc.right * 100 / 160;
                cr.right = crc.right * 100 / 148;
                if(PtInRect(&cr, pt))
                    SetTextColor(mdc, RGB(255, 255, 255));
                DrawText(mdc, L"X", 1, &cr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                OffsetRect(&rc, 0, wTipsHeight);
            }
            for (int i = 0; i < 3; i++) {
                SetTextColor(mdc, RGB(0, 192, 192));
                DrawText(mdc, ppmu[i]->szExe, (int)wcslen(ppmu[i]->szExe), &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                float fMemUsage = (float)ppmu[i]->dwMemUsage;
                if (fMemUsage >= 1048576000) {
                    fMemUsage /= 1073741824;
                    swprintf_s(sz, 16, L"%.2fGB", fMemUsage);
                } else {
                    fMemUsage /= 1048576;
                    swprintf_s(sz, 16, L"%.2fMB", fMemUsage);
                }
                DrawText(mdc, sz, (int)wcslen(sz), &rc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
                RECT cr = rc;
                cr.left = crc.right * 100 / 148;
                cr.right = crc.right * 8 / 10;
                swprintf_s(sz, 16, L"%d", ppmu[i]->dwProcessID);
                DrawText(mdc, sz, (int)wcslen(sz), &cr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                cr.left = crc.right * 100 / 160;
                cr.right = crc.right * 100 / 148;
                if (PtInRect(&cr, pt))
                    SetTextColor(mdc, RGB(255, 255, 255));
                DrawText(mdc, L"X", 1, &cr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                OffsetRect(&rc, 0, wTipsHeight);
            }
            SetTextColor(mdc, RGB(192, 192, 192));
            rc.left = 2;
            rc.right -= 2;
            PROCESSOR_POWER_INFORMATION *pi = new PROCESSOR_POWER_INFORMATION[dNumProcessor];
            if (CallNtPowerInformation(ProcessorInformation, NULL, 0, &pi[0], sizeof PROCESSOR_POWER_INFORMATION * dNumProcessor) == 0) {
                swprintf_s(sz, 63, L"%d个逻辑处理器 当前频率%.2fGHz 最大频率%.2fGHz", dNumProcessor, ((float)pi[0].CurrentMhz) / 1000, ((float)pi[0].MaxMhz) / 1000);
            }
            delete[]pi;
            DrawText(mdc, sz, (int)wcslen(sz), &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            OffsetRect(&rc, 0, wTipsHeight);
            float availPage, totalPage, avail, total;
            availPage = (float)MemoryStatusEx.ullAvailPageFile;
            availPage /= 1073741824;
            totalPage = (float)MemoryStatusEx.ullTotalPageFile;
            totalPage /= 1073741824;
            avail = (float)MemoryStatusEx.ullAvailPhys;
            avail /= 1073741824;
            total = (float)MemoryStatusEx.ullTotalPhys;
            total /= 1073741824;
            swprintf_s(sz, 63, L"虚拟内存:%.2f/%.2fGB,可用内存:%.2f/%.2fGB", availPage, totalPage, avail, total);
            DrawText(mdc, sz, (int)wcslen(sz), &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            DeleteObject(hTipsFont);
            SelectObject(mdc, oldFont);
        }
        GetClientRect(hDlg, &rc);
        BitBlt(hdc, 0, 0, rc.right - rc.left, rc.bottom - rc.top, mdc, 0, 0, SRCCOPY);
        SelectObject(mdc, oldBmp);
        DeleteObject(hMemBmp);
        DeleteDC(mdc);
        return TRUE;
        break;
    }
    return (INT_PTR)FALSE;
}
int GetScreenRect(HWND hWnd, LPRECT lpRect, BOOL bTray) { 
    HMONITOR hMon = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi;
    mi.cbSize = sizeof mi;
    GetMonitorInfo(hMon, &mi);
    if (bTray) {
        RECT TrayRect;
        if (mi.rcMonitor.left == 0 && mi.rcMonitor.top == 0) {
            HWND hTrayWnd = ::FindWindow(szShellTray, NULL);
            GetWindowRect(hTrayWnd, &TrayRect);
        } else {
            HWND hSecondaryTray;
            hSecondaryTray = FindWindow(szSecondaryTray, NULL);
            while (hSecondaryTray) {
                GetWindowRect(hSecondaryTray, &TrayRect);
                POINT pt;
                pt.x = TrayRect.left;
                pt.y = TrayRect.top;
                if (PtInRect(lpRect, pt))
                    break;
                hSecondaryTray = FindWindowEx(NULL, hSecondaryTray, szSecondaryTray, NULL);
            }
        }
        RECT dRect;
        SubtractRect(&dRect, &mi.rcMonitor, &TrayRect);
        CopyRect(lpRect, &dRect);
    } else
        CopyRect(lpRect, &mi.rcMonitor);
    return 0;
}
void GetProcessCpuUsage() { 
    if(!inTipsProcessX) {
        ppcu[0] = &pcu[0];
        ppcu[1] = &pcu[1];
        ppcu[2] = &pcu[2];
        ZeroMemory(pcu, sizeof pcu);
        pcu[0].fCpuUsage = 0;
        pcu[1].fCpuUsage = 0;
        pcu[2].fCpuUsage = 0;
    }
    DWORD dCurID = GetCurrentProcessId();
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hs != INVALID_HANDLE_VALUE) {
        BOOL ret = Process32First(hs, &pe);
        while (ret) {
            if (pe.th32ProcessID != dCurID) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    int n = -1;
                    for (int i = 0; i < nProcess + 31; i++) {
                        if (pProcessTime[i].dwProcessID == pe.th32ProcessID) {
                            n = i;
                            break;
                        } else if (n == -1 && pProcessTime[i].dwProcessID == NULL)
                            n = i;
                    }
                    FILETIME CreateTime, ExitTime, KernelTime, UserTime;
                    if (GetProcessTimes(hProc, &CreateTime, &ExitTime, &KernelTime, &UserTime)) {
                        float nProcCpuPercent = 0;
                        BOOL bRetCode = FALSE;
                        FILETIME CreateTime, ExitTime, KernelTime, UserTime;
                        LARGE_INTEGER lgKernelTime;
                        LARGE_INTEGER lgUserTime;
                        LARGE_INTEGER lgCurTime;

                        bRetCode = GetProcessTimes(hProc, &CreateTime, &ExitTime, &KernelTime, &UserTime);
                        if (bRetCode) {
                            lgKernelTime.HighPart = KernelTime.dwHighDateTime;
                            lgKernelTime.LowPart = KernelTime.dwLowDateTime;

                            lgUserTime.HighPart = UserTime.dwHighDateTime;
                            lgUserTime.LowPart = UserTime.dwLowDateTime;

                            lgCurTime.QuadPart = (lgKernelTime.QuadPart + lgUserTime.QuadPart) / 10000;
                            if (pProcessTime[n].g_slgProcessTimeOld.QuadPart == 0)
                                nProcCpuPercent = 0;
                            else
                                nProcCpuPercent = (float)((lgCurTime.QuadPart - pProcessTime[n].g_slgProcessTimeOld.QuadPart) * 100 / 1000);
                            pProcessTime[n].g_slgProcessTimeOld = lgCurTime;
                            pProcessTime[n].dwProcessID = pe.th32ProcessID;
                            nProcCpuPercent = nProcCpuPercent / dNumProcessor;
                        } else {
                            nProcCpuPercent = 0;
                        }
                        if (nProcCpuPercent > 100)
                            nProcCpuPercent = 0;
                        if (!inTipsProcessX) {
                            PROCESSCPUUSAGE *ppc;
                            if (ppcu[0]->fCpuUsage <= nProcCpuPercent) {
                                ppc = ppcu[2];
                                ppcu[2] = ppcu[1];
                                ppcu[1] = ppcu[0];
                                ppcu[0] = ppc;
                                ppcu[0]->dwProcessID = pe.th32ProcessID;
                                ppcu[0]->fCpuUsage = nProcCpuPercent;
                                wcsncpy_s(ppcu[0]->szExe, 25, pe.szExeFile, 24);
                            } else if (ppcu[1]->fCpuUsage <= nProcCpuPercent) {
                                ppc = ppcu[2];
                                ppcu[2] = ppcu[1];
                                ppcu[1] = ppc;
                                ppcu[1]->dwProcessID = pe.th32ProcessID;
                                ppcu[1]->fCpuUsage = nProcCpuPercent;
                                wcsncpy_s(ppcu[1]->szExe, 25, pe.szExeFile, 24);
                            } else if (ppcu[2]->fCpuUsage <= nProcCpuPercent) {
                                ppcu[2]->dwProcessID = pe.th32ProcessID;
                                ppcu[2]->fCpuUsage = nProcCpuPercent;
                                wcsncpy_s(ppcu[2]->szExe, 25, pe.szExeFile, 24);
                            }
                        }
                    }
                    CloseHandle(hProc);
                }
            }
            ret = Process32Next(hs, &pe);
        }
        CloseHandle(hs);
    }

}
int GetProcessMemUsage() { 
    if(!inTipsProcessX) {
        ppmu[0] = &pmu[0];
        ppmu[1] = &pmu[1];
        ppmu[2] = &pmu[2];
        ZeroMemory(pmu, sizeof pmu);
        pmu[0].dwMemUsage = 0;
        pmu[1].dwMemUsage = 0;
        pmu[2].dwMemUsage = 0;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    int n = 0;
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hs != INVALID_HANDLE_VALUE) {
        BOOL ret = Process32First(hs, &pe);
        while (ret) {
            ++n;
            if (wcscmp(pe.szExeFile, L"Memory Compression") != 0 && !inTipsProcessX) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    PROCESS_MEMORY_COUNTERS_EX pmc;
                    if (GetProcessMemoryInfo(hProc, (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof(pmc))) {
                        PROCESSMEMORYUSAGE *ppm;
                        if (ppmu[0]->dwMemUsage <= pmc.WorkingSetSize) {
                            ppm = ppmu[2];
                            ppmu[2] = ppmu[1];
                            ppmu[1] = ppmu[0];
                            ppmu[0] = ppm;
                            ppmu[0]->dwProcessID = pe.th32ProcessID;
                            ppmu[0]->dwMemUsage = pmc.WorkingSetSize;
                            wcsncpy_s(ppmu[0]->szExe, 25, pe.szExeFile, 24);

                        } else if (ppmu[1]->dwMemUsage <= pmc.WorkingSetSize) {
                            ppm = ppmu[2];
                            ppmu[2] = ppmu[1];
                            ppmu[1] = ppm;
                            ppmu[1]->dwProcessID = pe.th32ProcessID;
                            ppmu[1]->dwMemUsage = pmc.WorkingSetSize;
                            wcsncpy_s(ppmu[1]->szExe, 25, pe.szExeFile, 24);
                        } else if (ppmu[2]->dwMemUsage <= pmc.WorkingSetSize) {
                            ppmu[2]->dwProcessID = pe.th32ProcessID;
                            ppmu[2]->dwMemUsage = pmc.WorkingSetSize;
                            wcsncpy_s(ppmu[2]->szExe, 25, pe.szExeFile, 24);
                        }
                    }
                    CloseHandle(hProc);
                }
            }
            ret = Process32Next(hs, &pe);
        }
        CloseHandle(hs);
    }
    return n;
}
void DrawTraffic(HDC mdc, LPRECT lpRect, DWORD dwByte, BOOL bInOut) {
    WCHAR szInS[] = L"↓:";
    WCHAR szInS2[] = L"";
    WCHAR szOutS[] = L"↑:";
    WCHAR szOutS2[] = L"";
    WCHAR *szT;
    if (bInOut) {
        if (TraySave.iMonitorSimple == 1)
            szT = szInS;
        else if (TraySave.iMonitorSimple == 2)
            szT = szInS2;
        else
            szT = TraySave.szTrafficIn;
    } else {
        if (TraySave.iMonitorSimple == 1)
            szT = szOutS;
        else if (TraySave.iMonitorSimple == 2)
            szT = szOutS2;
        else
            szT = TraySave.szTrafficOut;
    }
    WCHAR sz[24];
    COLORREF rgb;
    if (dwByte < TraySave.dNumValues[0])
        rgb = TraySave.cMonitorColor[1];
    else if (dwByte < TraySave.dNumValues[1])
        rgb = TraySave.cMonitorColor[2];
    else
        rgb = TraySave.cMonitorColor[3];
    SetTextColor(mdc, rgb);
    if (HIWORD(TraySave.iUnit))
        dwByte *= 8;
    float f_byte = (float)dwByte;
    if (dwByte < 1000 && LOWORD(TraySave.iUnit) == 0)
        swprintf_s(sz, 16, L"%s%dB", szT, dwByte);
    else if ((dwByte < 1024000 || (dwByte < 1000000 && HIWORD(TraySave.iUnit))) && LOWORD(TraySave.iUnit) != 2) {
        if (HIWORD(TraySave.iUnit))
            f_byte /= 1000;
        else
            f_byte /= 1024;
        if (f_byte >= 100)
            swprintf_s(sz, 16, L"%s%.fK", szT, f_byte);
        else if (f_byte >= 10)
            swprintf_s(sz, 16, L"%s%.1fK", szT, f_byte);
        else
            swprintf_s(sz, 16, L"%s%.2fK", szT, f_byte);
    } else if (dwByte < 1048576000 || (dwByte < 1000000000 && HIWORD(TraySave.iUnit))) {
        if (HIWORD(TraySave.iUnit))
            f_byte /= 1000000;
        else
            f_byte /= 1048576;
        if (f_byte >= 100)
            swprintf_s(sz, 16, L"%s%.fM", szT, f_byte);
        else if (f_byte >= 10)
            swprintf_s(sz, 16, L"%s%.1fM", szT, f_byte);
        else
            swprintf_s(sz, 16, L"%s%.2fM", szT, f_byte);
    } else {
        if (HIWORD(TraySave.iUnit))
            f_byte /= 1000000000;
        else
            f_byte /= 1073741824;
        if (f_byte >= 100)
            swprintf_s(sz, 16, L"%s%.fG", szT, f_byte);
        else if (f_byte >= 10)
            swprintf_s(sz, 16, L"%s%.1fG", szT, f_byte);
        else
            swprintf_s(sz, 16, L"%s%.2fG", szT, f_byte);
    }
    if (HIWORD(TraySave.iUnit))
        _wcslwr_s(sz, 16);
    if(VTray)
        DrawText(mdc, sz, (int)wcslen(sz), lpRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    else
        DrawText(mdc, sz, (int)wcslen(sz), lpRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}
BOOL bEvent = FALSE;
int iGetAddressTime = 10; 
INT_PTR CALLBACK TaskBarProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) { 
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;
    case WM_COMMAND:
        if (LOWORD(wParam) >= IDC_SELECT_ALL && LOWORD(wParam) <= IDC_SELECT_ALL + 99) {
            if (LOWORD(wParam) == IDC_SELECT_ALL)
                TraySave.AdpterName[0] = L'\0';
            else {
                int x = LOWORD(wParam) - IDC_SELECT_ALL;
                PIP_ADAPTER_ADDRESSES paa;
                paa = &piaa[0];
                int n = 1;
                while (paa) {
                    if (paa->IfType != IF_TYPE_SOFTWARE_LOOPBACK && paa->IfType != IF_TYPE_TUNNEL) {
                        if (n == x) {
                            strncpy_s(TraySave.AdpterName, 39, paa->AdapterName, 38);
                            break;
                        }
                        n++;
                    }
                    paa = paa->Next;
                }
            }
            WriteReg();
            m_last_in_bytes = 0;
            m_last_out_bytes = 0;
            s_in_byte = 0;
            s_out_byte = 0;
        }
        break;
    case WM_MOUSEMOVE:
        if (bEvent == FALSE && TraySave.bMonitorTips) {
            TRACKMOUSEEVENT csTME;
            csTME.cbSize = sizeof(csTME);
            csTME.dwFlags = TME_LEAVE | TME_HOVER;
            csTME.hwndTrack = hTaskBar;   
            csTME.dwHoverTime = 300;      
            TrackMouseEvent(&csTME);
            bEvent = TRUE;
        }
        break;
    case WM_MOUSEHOVER: {
        if (!IsWindowVisible(hTaskTips)) {
            if (!IsWindow(hTaskTips)) {
                hTaskTips = ::CreateDialog(hInst, MAKEINTRESOURCE(IDD_TIPS), NULL, (DLGPROC)TaskTipsProc);
                SetLayeredWindowAttributes(hTaskTips, 0, 255, LWA_ALPHA);
            }
            nProcess = GetProcessMemUsage();
            if (pProcessTime == NULL) {
                pProcessTime = new PROCESSTIME[nProcess + 32];
                ZeroMemory(pProcessTime, sizeof(PROCESSTIME) * (nProcess + 32));
            }
            GetProcessCpuUsage();
            HDC mdc = GetDC(hMain);
            TraySave.TipsFont.lfHeight = DPI(TraySave.TipsFontSize);
            HFONT hTipsFont = CreateFontIndirect(&TraySave.TipsFont); 
            HFONT oldFont = (HFONT)SelectObject(mdc, hTipsFont);
            SIZE tSize;
            ::GetTextExtentPoint(mdc, L"虚拟内存虚拟内存虚拟内存虚拟内存虚拟内存虚拟内存虚拟内存虚拟内存", 32, &tSize);
            SelectObject(mdc, oldFont);
            DeleteObject(hTipsFont);
            ::ReleaseDC(hMain, mdc);
            int x, y, w, h;
            w = tSize.cx;
            wTipsHeight = tSize.cy;
            h = wTipsHeight * (nTraffic + 8);
            RECT wrc, src;
            GetWindowRect(hDlg, &wrc);
            GetScreenRect(hDlg, &src, TRUE);
            if (wrc.bottom + h > src.bottom)
                y = wrc.top - h;
            else
                y = wrc.bottom;
            if (wrc.right - (wrc.right - wrc.left) / 2 + w / 2 > src.right)
                x = src.right - w;
            else if (wrc.right - (wrc.right - wrc.left) / 2 - w / 2 < src.left)
                x = src.left;
            else
                x = wrc.right - (wrc.right - wrc.left) / 2 - w / 2;
            SetWindowPos(hTaskTips, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE | SWP_SHOWWINDOW);
            HRGN hRgn = CreateRoundRectRgn(0, 0, w + 1, h + 1, 3, 3);
            SetWindowRgn(hTaskTips, hRgn, FALSE);
        }
    }
    break;
    case WM_MOUSELEAVE:
        if (TraySave.bMonitorFloat) {
            RECT wrc;
            GetWindowRect(hDlg, &wrc);
            TraySave.dMonitorPoint.x = wrc.left;
            TraySave.dMonitorPoint.y = wrc.top;
            WriteReg();
            bTaskBarMoveing = FALSE;
        }
        POINT pt;
        GetCursorPos(&pt);
        if (WindowFromPoint(pt) != hTaskTips) {
            if (pProcessTime != NULL) {
                delete[]pProcessTime;
                pProcessTime = NULL;
            }
            DestroyWindow(hTaskTips);
            SetTimer(hMain, 11, 1000, NULL);
        }
        TRACKMOUSEEVENT csTME;
        csTME.cbSize = sizeof(csTME);
        csTME.dwFlags = TME_LEAVE ;
        csTME.hwndTrack = hTaskTips;   
        csTME.dwHoverTime = 100;      
        TrackMouseEvent(&csTME);
        bEvent = FALSE;
        break;
    case  WM_RBUTTONDOWN: {
        POINT pt;
        GetCursorPos(&pt);
        ScreenToClient(hDlg, &pt);
        if (TraySave.bMonitorTraffic && pt.x < wTraffic && pt.y < wHeight * 2) {

            HMENU hMenu = LoadMenu(hInst, MAKEINTRESOURCEW(IDR_MENU));
            HMENU subMenu = GetSubMenu(hMenu, 0);
            PIP_ADAPTER_ADDRESSES paa;
            paa = &piaa[0];
            int n = 1;
            CheckMenuRadioItem(subMenu, IDC_SELECT_ALL, IDC_SELECT_ALL + 99, IDC_SELECT_ALL, MF_BYCOMMAND);
            while (paa) {
                if (paa->IfType != IF_TYPE_SOFTWARE_LOOPBACK && paa->IfType != IF_TYPE_TUNNEL) {
                    AppendMenu(subMenu, MF_BYCOMMAND, IDC_SELECT_ALL + n, paa->FriendlyName);
                    if (strncmp(paa->AdapterName, TraySave.AdpterName, 38) == 0)
                        CheckMenuRadioItem(subMenu, IDC_SELECT_ALL, IDC_SELECT_ALL + 99, IDC_SELECT_ALL + n, MF_BYCOMMAND);
                    n++;
                }
                paa = paa->Next;
            }
            POINT point;
            GetCursorPos(&point);
            SetTimer(hDlg, 5, 1200, NULL);
            TrackPopupMenu(subMenu, TPM_LEFTALIGN, point.x, point.y, NULL, hDlg, NULL);
            DestroyMenu(hMenu);
        } else
            OpenSetting();
        return TRUE;
    }
    break;
    case WM_LBUTTONDOWN: {
        if (TraySave.bMonitorFloat) {
            bTaskBarMoveing = TRUE;
            PostMessage(hDlg, WM_NCLBUTTONDOWN, HTCAPTION, lParam);
        }
        return TRUE;
    }
    break;
    case WM_LBUTTONUP:
        if (!TraySave.bMonitorFloat) {
            ShowWindow(hDlg, SW_HIDE);
            SetTimer(hDlg, 9, 100, NULL);
            return TRUE;
        }
        break;
    case WM_TIMER:
        if (wParam == 9) {
            KillTimer(hDlg, wParam);
            POINT pt;
            GetCursorPos(&pt);
            mouse_event(MOUSEEVENTF_LEFTDOWN, pt.x, pt.y, 0, 0);
            mouse_event(MOUSEEVENTF_LEFTUP, pt.x, pt.y, 0, 0);
            ShowWindow(hDlg, SW_SHOWNOACTIVATE);
        } else if (wParam == 5) { 

            HWND hMenu = FindWindow(L"#32768", NULL);
            POINT pt;
            GetCursorPos(&pt);
            if (WindowFromPoint(pt) != hMenu) {
                KillTimer(hDlg, wParam);
                PostMessage(hMenu, WM_CLOSE, NULL, NULL);
            }
        } else if (wParam == 3) {
            if (IsWindowVisible(hTaskTips)) {
                nProcess = GetProcessMemUsage();
                GetProcessCpuUsage();
            }
            if (TraySave.bMonitorUsage) {
                iCPU = GetCPUUseRate();
                GlobalMemoryStatusEx(&MemoryStatusEx);
            }
            if (TraySave.bMonitorTemperature) {
                if (bRing0) {
                    iTemperature1 = GetCpuTemp(1);
                    iTemperature2 = GetCpuTemp(dNumProcessor);
                }
                int iATITemperature = 0;
                int iNVTemperature = 0;
                if (hNVDLL) {
                    NV_GPU_THERMAL_SETTINGS currentTemp;
                    currentTemp.version = NV_GPU_THERMAL_SETTINGS_VER;
                    for (int GpuIndex = 0; GpuIndex < 4; GpuIndex++) {
                        if (NvAPI_GPU_GetThermalSettings(hPhysicalGpu[GpuIndex], 15, &currentTemp) == 0) {
                            iNVTemperature = currentTemp.sensor[0].currentTemp;
                            break;
                        }
                    }
                }
                if (hATIDLL) {
                    adlTemperature.iSize = sizeof(ADLTemperature);
                    ADL_Overdrive5_Temperature_Get(0, 0, &adlTemperature);
                    iATITemperature = adlTemperature.iTemperature / 1000;
                }
                if (iATITemperature != 0 || iNVTemperature != 0) {
                    if (iATITemperature > iNVTemperature)
                        iTemperature2 = iATITemperature;
                    else
                        iTemperature2 = iNVTemperature;
                }
            }
            if (TraySave.bMonitorTraffic) {
                if (hIphlpapi == NULL) {
                    hIphlpapi = LoadLibrary(L"iphlpapi.dll");
                    if (hIphlpapi) {
                        GetAdaptersAddressesT = (pfnGetAdaptersAddresses)GetProcAddress(hIphlpapi, "GetAdaptersAddresses");
                        GetIfTableT = (pfnGetIfTable)GetProcAddress(hIphlpapi, "GetIfTable");
                    }
                }
                if (hIphlpapi) {
                    PIP_ADAPTER_ADDRESSES paa;
                    if (iGetAddressTime == 10) {
                        dwIPSize = 0;
                        if (GetAdaptersAddressesT(AF_INET, 0, 0, piaa, &dwIPSize) == ERROR_BUFFER_OVERFLOW) {
                            {

                                free(piaa);
                                int n = 0;
                                piaa = (PIP_ADAPTER_ADDRESSES)malloc(dwIPSize);
                                if (GetAdaptersAddressesT(AF_INET, 0, 0, piaa, &dwIPSize) == ERROR_SUCCESS) {
                                    paa = &piaa[0];
                                    while (paa) {
                                        if (paa->IfType != IF_TYPE_SOFTWARE_LOOPBACK && paa->IfType != IF_TYPE_TUNNEL) {
                                            ++n;
                                        }
                                        paa = paa->Next;
                                    }
                                    if (n != nTraffic) {
                                        free(traffic);
                                        nTraffic = n;
                                        traffic = (TRAFFIC *)malloc(nTraffic * sizeof TRAFFIC);
                                    }
                                }
                            }
                        }
                        iGetAddressTime = 0;
                    } else
                        iGetAddressTime++;
                    if (GetIfTableT(mi, &dwMISize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
                        free(mi);
                        mi = (MIB_IFTABLE *)malloc(dwMISize);
                        GetIfTableT(mi, &dwMISize, FALSE);
                    }
                    DWORD m_in_bytes = 0;
                    DWORD m_out_bytes = 0;
                    for (DWORD i = 0; i < mi->dwNumEntries; i++) {
                        int l = 0;
                        paa = &piaa[0];
                        while (paa) {
                            if (paa->IfType != IF_TYPE_SOFTWARE_LOOPBACK && paa->IfType != IF_TYPE_TUNNEL) {
                                if (paa->IfIndex == mi->table[i].dwIndex) {
                                    traffic[l].in_byte = (mi->table[i].dwInOctets - traffic[l].in_bytes) * 8;
                                    traffic[l].out_byte = (mi->table[i].dwOutOctets - traffic[l].out_bytes) * 8;
                                    traffic[l].in_bytes = mi->table[i].dwInOctets;
                                    traffic[l].out_bytes = mi->table[i].dwOutOctets;

                                    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = paa->FirstUnicastAddress;
                                    while (pUnicast) {
                                        if (AF_INET == pUnicast->Address.lpSockaddr->sa_family) {     
                                            void *pAddr = &((sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr;
                                            byte *bp = (byte *)pAddr;
                                            swprintf_s(traffic[l].IP4, 16, L"%d.%d.%d.%d", bp[0], bp[1], bp[2], bp[3]);
                                            break;
                                        }
                                        pUnicast = pUnicast->Next;
                                    }
                                    traffic[l].FriendlyName = paa->FriendlyName;
                                    if (wcslen(paa->FriendlyName) > 19) {
                                        paa->FriendlyName[16] = L'.';
                                        paa->FriendlyName[17] = L'.';
                                        paa->FriendlyName[18] = L'.';
                                        paa->FriendlyName[19] = L'\0';
                                    }
                                    if (TraySave.AdpterName[0] == L'\0' || strncmp(paa->AdapterName, TraySave.AdpterName, 38) == 0) {
                                        m_in_bytes += mi->table[i].dwInOctets;
                                        m_out_bytes += mi->table[i].dwOutOctets;
                                    }
                                }
                                ++l;
                            }
                            paa = paa->Next;
                        }
                    }
                    if (m_last_in_bytes != 0) {
                        s_in_byte = m_in_bytes - m_last_in_bytes;
                        s_out_byte = m_out_bytes - m_last_out_bytes;
                    }
                    m_last_out_bytes = m_out_bytes;
                    m_last_in_bytes = m_in_bytes;
                }
            } else {
                if (hIphlpapi) {
                    FreeLibrary(hIphlpapi);
                    hIphlpapi = NULL;
                }
            }
            if (TraySave.bSound) {
                if ((TraySave.dNumValues[8] != 0 && (s_in_byte > TraySave.dNumValues[8] || s_out_byte > TraySave.dNumValues[8]))
                        || (TraySave.dNumValues[9] != 0 && ((DWORD)iTemperature1 > TraySave.dNumValues[9] || (DWORD)iTemperature2 > TraySave.dNumValues[9]))
                        || (TraySave.dNumValues[10] != 0 && (DWORD)iCPU > TraySave.dNumValues[10])
                        || (TraySave.dNumValues[11] != 0 && MemoryStatusEx.dwMemoryLoad > TraySave.dNumValues[11])) {
                    MessageBeep(MB_ICONHAND);
                }
            }
            ::InvalidateRect(hTaskBar, NULL, TRUE);
        }
    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam; 
        RECT rc;
        GetClientRect(hDlg, &rc);
        HDC mdc = CreateCompatibleDC(hdc);
        HBITMAP hMemBmp = CreateCompatibleBitmap(hdc, rc.right - rc.left, rc.bottom - rc.top);
        HBITMAP oldBmp = (HBITMAP)SelectObject(mdc, hMemBmp);
        if (TraySave.cMonitorColor[0] != 0) {
            HBRUSH hb = CreateSolidBrush(TraySave.cMonitorColor[0]);
            FillRect(mdc, &rc, hb);
            DeleteObject(hb);
        }
        {
            if (VTray) {
            } else {
                InflateRect(&rc, -1, 0);
            }
            HFONT oldFont = (HFONT)SelectObject(mdc, hFont);
            WCHAR sz[16];
            SetBkMode(mdc, TRANSPARENT);
            COLORREF rgb;
            if (TraySave.bMonitorTraffic) {
                RECT crc = rc;
                if (VTray) {
                    crc.bottom = wHeight;
                    DrawTraffic(mdc, &crc, s_out_byte, FALSE);
                    OffsetRect(&crc, 0, wHeight);
                    DrawTraffic(mdc, &crc, s_in_byte, TRUE);
                } else {
                    crc.bottom /= 2;
                    DrawTraffic(mdc, &crc, s_out_byte, FALSE);
                    OffsetRect(&crc, 0, crc.bottom);
                    DrawTraffic(mdc, &crc, s_in_byte, TRUE);
                }
            }
            if (TraySave.bMonitorTemperature) {
                RECT crc = rc;
                if (VTray) {
                    if (TraySave.bMonitorTraffic)
                        crc.top = wHeight * 2;
                    crc.bottom = crc.top + wHeight;
                } else {

                    if (TraySave.bMonitorTraffic)
                        crc.left = wTraffic;
                    else
                        crc.left = 0;
                    crc.bottom /= 2;
                }
                if (bRing0) {
                    if (iTemperature1 <= TraySave.dNumValues[2])
                        rgb = TraySave.cMonitorColor[4];
                    else if (iTemperature1 <= TraySave.dNumValues[3])
                        rgb = TraySave.cMonitorColor[5];
                    else
                        rgb = TraySave.cMonitorColor[6];
                    SetTextColor(mdc, rgb);
                    if(TraySave.iMonitorSimple == 1)
                        swprintf_s(sz, 16, L"%.2d℃", iTemperature1);
                    else if (TraySave.iMonitorSimple == 2)
                        swprintf_s(sz, 16, L"%.2d", iTemperature1);
                    else
                        swprintf_s(sz, 16, L"%s%.2d%s", TraySave.szTemperatureCPU, iTemperature1, TraySave.szTemperatureCPUUnit);

                    if(VTray)
                        DrawText(mdc, sz, (int)wcslen(sz), &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                    else
                        DrawText(mdc, sz, (int)wcslen(sz), &crc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                }
                if (bRing0) {
                    if (VTray)
                        OffsetRect(&crc, 0, wHeight);
                    else
                        OffsetRect(&crc, 0, crc.bottom - crc.top);
                } else {
                    if (VTray) {
                    } else
                        crc.bottom += (crc.bottom - crc.top);
                }
                if (iTemperature2 <= TraySave.dNumValues[2])
                    rgb = TraySave.cMonitorColor[4];
                else if (iTemperature2 <= TraySave.dNumValues[3])
                    rgb = TraySave.cMonitorColor[5];
                else
                    rgb = TraySave.cMonitorColor[6];
                SetTextColor(mdc, rgb);
                if(TraySave.iMonitorSimple == 0)
                    swprintf_s(sz, 16, L"%s%.2d%s", TraySave.szTemperatureGPU, iTemperature2, TraySave.szTemperatureGPUUnit);
                else if (TraySave.iMonitorSimple == 1)
                    swprintf_s(sz, 16, L"%.2d℃", iTemperature2);
                else
                    swprintf_s(sz, 16, L"%.2d", iTemperature2);
                if (VTray)
                    DrawText(mdc, sz, (int)wcslen(sz), &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                else
                    DrawText(mdc, sz, (int)wcslen(sz), &crc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            }
            if (TraySave.bMonitorUsage) {
                if (iCPU <= TraySave.dNumValues[4])
                    rgb = TraySave.cMonitorColor[4];
                else if (iCPU <= TraySave.dNumValues[5])
                    rgb = TraySave.cMonitorColor[5];
                else
                    rgb = TraySave.cMonitorColor[6];
                SetTextColor(mdc, rgb);
                if(TraySave.iMonitorSimple == 1)
                    swprintf_s(sz, 16, L"%.2d%%", iCPU);
                else if (TraySave.iMonitorSimple == 2)
                    swprintf_s(sz, 16, L"%.2d", iCPU);
                else
                    swprintf_s(sz, 16, L"%s%.2d%s", TraySave.szUsageCPU, iCPU, TraySave.szUsageCPUUnit);

                size_t sLen = wcslen(sz);
                RECT crc = rc;
                if (VTray) {
                    if (TraySave.bMonitorTraffic)
                        crc.top = wHeight * 2;
                    if (TraySave.bMonitorTemperature) {
                        crc.top += wHeight;
                        if (bRing0)
                            crc.top += wHeight;
                    }
                    crc.bottom = crc.top + wHeight;
                    DrawText(mdc, sz, (int)sLen, &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                } else {
                    crc.bottom /= 2;
                    DrawText(mdc, sz, (int)sLen, &crc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
                }
                if(TraySave.iMonitorSimple == 1)
                    swprintf_s(sz, 16, L"%.2d%%", MemoryStatusEx.dwMemoryLoad);
                else if (TraySave.iMonitorSimple == 2)
                    swprintf_s(sz, 16, L"%.2d", MemoryStatusEx.dwMemoryLoad);
                else
                    swprintf_s(sz, 16, L"%s%.2d%s", TraySave.szUsageMEM, MemoryStatusEx.dwMemoryLoad, TraySave.szUsageMEMUnit);
                sLen = wcslen(sz);
                if (MemoryStatusEx.dwMemoryLoad <= TraySave.dNumValues[6])
                    rgb = TraySave.cMonitorColor[4];
                else if (MemoryStatusEx.dwMemoryLoad <= TraySave.dNumValues[7])
                    rgb = TraySave.cMonitorColor[5];
                else
                    rgb = TraySave.cMonitorColor[6];
                SetTextColor(mdc, rgb);
                if (VTray) {
                    OffsetRect(&crc, 0, wHeight);
                    DrawText(mdc, sz, (int)sLen, &crc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                } else {
                    OffsetRect(&crc, 0, crc.bottom);
                    DrawText(mdc, sz, (int)sLen, &crc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
                }
            }
            SelectObject(mdc, oldFont);
        }
        InflateRect(&rc, 1, 0);
        BitBlt(hdc, 0, 0, rc.right - rc.left, rc.bottom - rc.top, mdc, 0, 0, SRCCOPY);
        SelectObject(mdc, oldBmp);
        DeleteObject(hMemBmp);
        DeleteDC(mdc);
        return TRUE;
    }
    break;
    }
    return FALSE;
}
INT_PTR CALLBACK MainProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) { 
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;
    case WM_TRAYS:
        OpenSetting();
        break;
    case WM_DPICHANGED: {
        iDPI = LOWORD(wParam);
        SetTimer(hDlg, 8, 1000, NULL);
    }
    break;
    case WM_CLOSE: {
        KillTimer(hDlg, 6);
        KillTimer(hDlg, 3);
        SendMessage(hReBarWnd, WM_SETREDRAW, TRUE, 0);
        HWND hSecondaryTray;
        hSecondaryTray = FindWindow(szSecondaryTray, NULL);
        while (hSecondaryTray) {
            HWND hSReBarWnd = FindWindowEx(hSecondaryTray, 0, L"WorkerW", NULL);
            SendMessage(hSReBarWnd, WM_SETREDRAW, TRUE, 0);
            ShowWindow(hSReBarWnd, SW_SHOWNOACTIVATE);
            hSecondaryTray = FindWindowEx(NULL, hSecondaryTray, szSecondaryTray, NULL);
        }
        PostQuitMessage(0);
    }
    break;
    case WM_TIMER: {
        if (wParam == 8) {
            KillTimer(hDlg, wParam);
            SetWH();
        } else if (wParam == 11) { 
            KillTimer(hDlg, wParam);
            SetTimer(hDlg, wParam, 60000, NULL);
            HANDLE hProcess = GetCurrentProcess();
            SetProcessWorkingSetSize(hProcess, -1, -1);
            EmptyWorkingSet(hProcess);
        } else if (wParam == 6) { 
            hTray = FindWindow(szShellTray, NULL);
            hReBarWnd = FindWindowEx(hTray, 0, L"ReBarWindow32", NULL);
            hTaskWnd = FindWindowEx(hReBarWnd, NULL, L"MSTaskSwWClass", NULL);
            HWND hTaskListWnd = FindWindowEx(hTaskWnd, NULL, L"MSTaskListWClass", NULL);
            if (TraySave.bMonitor) {
                if(!bTaskBarMoveing)
                    AdjustWindowPos();
                if(IsWindowVisible(hTaskTips))
                    ::InvalidateRect(hTaskTips, NULL, TRUE);
            }
            SetTaskBarPos(hTaskListWnd, hTray, hTaskWnd, hReBarWnd, TRUE);
            HWND hSecondaryTray;
            hSecondaryTray = FindWindow(szSecondaryTray, NULL);
            while (hSecondaryTray) {
                HWND hSReBarWnd = FindWindowEx(hSecondaryTray, 0, L"WorkerW", NULL);
                if (hSReBarWnd) {
                    HWND hSTaskListWnd = FindWindowEx(hSReBarWnd, NULL, L"MSTaskListWClass", NULL);
                    if (hSTaskListWnd) {
                        SetTaskBarPos(hSTaskListWnd, hSecondaryTray, hSReBarWnd, hSReBarWnd, FALSE);
                    }
                }
                hSecondaryTray = FindWindowEx(NULL, hSecondaryTray, szSecondaryTray, NULL);
            }
        } else if (wParam == 3) { 

            {
                HWND hTray = FindWindow(szShellTray, NULL);
                if (hTray) {
                    if (iProject == 0)
                        iWindowMode = 0;
                    else if(iProject == 1)
                        iWindowMode = 1;
                    else {
                        iWindowMode = 0;
                        EnumWindows(IsZoomedFunc, (LPARAM)MonitorFromWindow(hTray, MONITOR_DEFAULTTONEAREST));
                    }
                    SetWindowCompositionAttribute(hTray, TraySave.aMode[iWindowMode], TraySave.dAlphaColor[iWindowMode]);
                    LONG_PTR exStyle = GetWindowLongPtr(hTray, GWL_EXSTYLE);
                    exStyle |= WS_EX_LAYERED;
                    SetWindowLongPtr(hTray, GWL_EXSTYLE, exStyle);
                    SetLayeredWindowAttributes(hTray, 0, (BYTE)TraySave.bAlpha[iWindowMode], LWA_ALPHA);
                }
                HWND hSecondaryTray = FindWindow(szSecondaryTray, NULL);
                while (hSecondaryTray) {
                    if (iProject == 0)
                        iWindowMode = 0;
                    else if (iProject == 1)
                        iWindowMode = 1;
                    else {
                        iWindowMode = 0;
                        EnumWindows(IsZoomedFunc, (LPARAM)MonitorFromWindow(hSecondaryTray, MONITOR_DEFAULTTONEAREST));
                    }
                    SetWindowCompositionAttribute(hSecondaryTray, TraySave.aMode[iWindowMode], TraySave.dAlphaColor[iWindowMode]);
                    LONG_PTR exStyle = GetWindowLongPtr(hSecondaryTray, GWL_EXSTYLE);
                    exStyle |= WS_EX_LAYERED;
                    SetWindowLongPtr(hSecondaryTray, GWL_EXSTYLE, exStyle);
                    SetLayeredWindowAttributes(hSecondaryTray, 0, (BYTE)TraySave.bAlpha[iWindowMode], LWA_ALPHA);
                    hSecondaryTray = FindWindowEx(NULL, hSecondaryTray, szSecondaryTray, NULL);
                }
            }
            if (TraySave.aMode[0] == ACCENT_DISABLED && TraySave.aMode[1] == ACCENT_DISABLED) 
                KillTimer(hDlg, 3);
        }
    }
    break;
    case WM_IAWENTRAY: { 
        if (wParam == WM_IAWENTRAY) {
            if (lParam == WM_LBUTTONDOWN || lParam == WM_RBUTTONDOWN) {
                RunProcess(NULL);
            }
        }
        break;
    }
    break;
    }
    return FALSE;
}
INT_PTR CALLBACK SettingProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) { 
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;
    case WM_NOTIFY:
        switch (((LPNMHDR)lParam)->code) {
        case NM_CLICK:
        case NM_RETURN: {
            HWND g_hLink = GetDlgItem(hDlg, IDC_SYSLINK);
            PNMLINK pNMLink = (PNMLINK)lParam;
            LITEM item = pNMLink->item;
            if ((((LPNMHDR)lParam)->hwndFrom == g_hLink) && (item.iLink == 0)) {
                CloseHandle(ShellExecute(NULL, L"open", L"https://gitee.com/cgbsmy/TrayS", NULL, NULL, SW_SHOW));
            } else {
                CloseHandle(ShellExecute(NULL, L"open", L"https://www.52pojie.cn/thread-1182669-1-1.html", NULL, NULL, SW_SHOW));
            }
            break;
        }
        }
        break;
    case WM_HSCROLL: { 
        HWND hSlider = GetDlgItem(hDlg, IDC_SLIDER_ALPHA);
        HWND hSliderB = GetDlgItem(hDlg, IDC_SLIDER_ALPHA_B);
        if (hSlider == (HWND)lParam) {
            TraySave.bAlpha[iProject] = (int)SendDlgItemMessage(hDlg, IDC_SLIDER_ALPHA, TBM_GETPOS, 0, 0);
        } else if (hSliderB == (HWND)lParam) {
            DWORD bAlphaB = (int)SendDlgItemMessage(hDlg, IDC_SLIDER_ALPHA_B, TBM_GETPOS, 0, 0);
            bAlphaB = bAlphaB << 24;
            TraySave.dAlphaColor[iProject] = bAlphaB + (TraySave.dAlphaColor[iProject] & 0xffffff);
        }
        SetTimer(hDlg, 3, 500, NULL);
        break;
    }
    case WM_TIMER:
        if (wParam == 3) {
            KillTimer(hDlg, wParam);
            WriteReg();
        }
        break;
    case WM_COMMAND:
        if (HIWORD(wParam) == EN_CHANGE && !bSettingInit) {
            if (LOWORD(wParam) >= IDC_EDIT1 && LOWORD(wParam) <= IDC_EDIT12) {
                int index = LOWORD(wParam) - IDC_EDIT1;
                TraySave.dNumValues[index] = GetDlgItemInt(hDlg, LOWORD(wParam), NULL, 0);
                if (index == 0 || index == 1 || index == 8)
                    TraySave.dNumValues[index] *= 1048576;
                SetTimer(hDlg, 3, 500, NULL);
            } else if (LOWORD(wParam) == IDC_EDIT_TIME) {
                TraySave.FlushTime = GetDlgItemInt(hDlg, LOWORD(wParam), NULL, 0);
                if (TraySave.aMode[0] != ACCENT_DISABLED || TraySave.aMode[1] != ACCENT_DISABLED)
                    SetTimer(hMain, 3, TraySave.FlushTime, NULL);
                SetTimer(hDlg, 3, 500, NULL);
            } else if (LOWORD(wParam) >= IDC_EDIT14 && LOWORD(wParam) <= IDC_EDIT23) {
                GetDlgItemText(hDlg, IDC_EDIT14, TraySave.szTrafficOut, 8);
                GetDlgItemText(hDlg, IDC_EDIT15, TraySave.szTrafficIn, 8);
                GetDlgItemText(hDlg, IDC_EDIT16, TraySave.szTemperatureCPU, 8);
                GetDlgItemText(hDlg, IDC_EDIT17, TraySave.szTemperatureGPU, 8);
                GetDlgItemText(hDlg, IDC_EDIT18, TraySave.szTemperatureCPUUnit, 4);
                GetDlgItemText(hDlg, IDC_EDIT19, TraySave.szTemperatureGPUUnit, 4);
                GetDlgItemText(hDlg, IDC_EDIT20, TraySave.szUsageCPU, 8);
                GetDlgItemText(hDlg, IDC_EDIT21, TraySave.szUsageMEM, 8);
                GetDlgItemText(hDlg, IDC_EDIT22, TraySave.szUsageCPUUnit, 4);
                GetDlgItemText(hDlg, IDC_EDIT23, TraySave.szUsageMEMUnit, 4);
                SetTimer(hDlg, 3, 1500, NULL);
                if(TraySave.iMonitorSimple == 0)
                    SetWH();
            }
        } else if (LOWORD(wParam) >= IDC_RADIO_DEFAULT && LOWORD(wParam) <= IDC_RADIO_ACRYLIC) {
            if (IsDlgButtonChecked(hDlg, IDC_RADIO_DEFAULT))
                TraySave.aMode[iProject] = ACCENT_DISABLED;
            else if (IsDlgButtonChecked(hDlg, IDC_RADIO_TRANSPARENT))
                TraySave.aMode[iProject] = ACCENT_ENABLE_TRANSPARENTGRADIENT;
            else if (IsDlgButtonChecked(hDlg, IDC_RADIO_BLURBEHIND))
                TraySave.aMode[iProject] = ACCENT_ENABLE_BLURBEHIND;
            else if (IsDlgButtonChecked(hDlg, IDC_RADIO_ACRYLIC))
                TraySave.aMode[iProject] = ACCENT_ENABLE_ACRYLICBLURBEHIND;
            WriteReg();
            if (TraySave.aMode[0] != ACCENT_DISABLED || TraySave.aMode[1] != ACCENT_DISABLED)
                SetTimer(hMain, 3, TraySave.FlushTime, NULL);
            else
                KillTimer(hMain, 3);

        } else if (LOWORD(wParam) >= IDC_RADIO_LEFT && LOWORD(wParam) <= IDC_RADIO_RIGHT) {
            if (IsDlgButtonChecked(hDlg, IDC_RADIO_LEFT)) {
                TraySave.iPos = 0;
            } else if (IsDlgButtonChecked(hDlg, IDC_RADIO_CENTER)) {
                TraySave.iPos = 1;
            } else if (IsDlgButtonChecked(hDlg, IDC_RADIO_RIGHT)) {
                TraySave.iPos = 2;
            }
            WriteReg();
            if (TraySave.iPos || TraySave.bMonitor)
                SetTimer(hMain, 6, 1000, NULL);
            else
                KillTimer(hMain, 6);
        } else if (LOWORD(wParam) >= IDC_RADIO_BYTE && LOWORD(wParam) <= IDC_RADIO_MB) {
            if (IsDlgButtonChecked(hDlg, IDC_RADIO_AUTO))
                TraySave.iUnit = 0;
            else if (IsDlgButtonChecked(hDlg, IDC_RADIO_KB))
                TraySave.iUnit = 1;
            else if (IsDlgButtonChecked(hDlg, IDC_RADIO_MB))
                TraySave.iUnit = 2;
            if (IsDlgButtonChecked(hDlg, IDC_RADIO_BIT))
                TraySave.iUnit |= 0x10000;
            WriteReg();
        }
        if (LOWORD(wParam) == IDC_RADIO_NORMAL || LOWORD(wParam) == IDC_RADIO_MAXIMIZE) {
            if (IsDlgButtonChecked(hDlg, IDC_RADIO_NORMAL))
                iProject = 0;
            else
                iProject = 1;
            if (TraySave.aMode[iProject] == ACCENT_DISABLED)
                CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_DEFAULT);
            else if (TraySave.aMode[iProject] == ACCENT_ENABLE_TRANSPARENTGRADIENT)
                CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_TRANSPARENT);
            else if (TraySave.aMode[iProject] == ACCENT_ENABLE_BLURBEHIND)
                CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_BLURBEHIND);
            else if (TraySave.aMode[iProject] == ACCENT_ENABLE_ACRYLICBLURBEHIND)
                CheckRadioButton(hSetting, IDC_RADIO_DEFAULT, IDC_RADIO_ACRYLIC, IDC_RADIO_ACRYLIC);
            SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA, TBM_SETPOS, TRUE, TraySave.bAlpha[iProject]);
            BYTE bAlphaB = TraySave.dAlphaColor[iProject] >> 24;
            SendDlgItemMessage(hSetting, IDC_SLIDER_ALPHA_B, TBM_SETPOS, TRUE, bAlphaB);
            ::InvalidateRect(GetDlgItem(hSetting, IDC_BUTTON_COLOR), NULL, FALSE);
        } else if (LOWORD(wParam) == IDC_CHECK_SOUND) {
            TraySave.bSound = IsDlgButtonChecked(hDlg, IDC_CHECK_SOUND);
            WriteReg();
        } else if (LOWORD(wParam) == IDC_CHECK_TIPS) {
            TraySave.bMonitorTips = IsDlgButtonChecked(hDlg, IDC_CHECK_TIPS);
            WriteReg();
        } else if (LOWORD(wParam) == IDC_CHECK_TRAYICON) {
            TraySave.bTrayIcon = IsDlgButtonChecked(hDlg, IDC_CHECK_TRAYICON);
            WriteReg();
            DestroyWindow(hTaskBar);
            if (TraySave.bTrayIcon)
                Shell_NotifyIcon(NIM_ADD, &nid);
            else
                Shell_NotifyIcon(NIM_DELETE, &nid);
            if (TraySave.bMonitor)
                OpenTaskBar();
        } else if (LOWORD(wParam) == IDC_CHECK_MONITOR) {
            TraySave.bMonitor = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR);
            WriteReg();
            if (TraySave.bMonitor) {
                OpenTaskBar();
            } else {
                DestroyWindow(hTaskBar);
                if (TraySave.iPos == 0)
                    KillTimer(hMain, 6);
            }
        } else if (LOWORD(wParam) == IDC_CHECK_TRAFFIC) {
            TraySave.bMonitorTraffic = IsDlgButtonChecked(hDlg, IDC_CHECK_TRAFFIC);
            WriteReg();
            SetWH();
        } else if (LOWORD(wParam) == IDC_CHECK_TEMPERATURE) {
            TraySave.bMonitorTemperature = IsDlgButtonChecked(hDlg, IDC_CHECK_TEMPERATURE);
            if (TraySave.bMonitorTemperature)
                LoadTemperatureDLL();
            else
                FreeTemperatureDLL();
            WriteReg();
            SetWH();
        } else if (LOWORD(wParam) == IDC_CHECK_MONITOR_SIMPLE) {
            TraySave.iMonitorSimple = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_SIMPLE);
            WriteReg();
            SetWH();
        } else if (LOWORD(wParam) == IDC_CHECK_USAGE) {
            TraySave.bMonitorUsage = IsDlgButtonChecked(hDlg, IDC_CHECK_USAGE);
            WriteReg();
            SetWH();
        } else if (LOWORD(wParam) == IDC_CHECK_MONITOR_PDH) {
            TraySave.bMonitorPDH = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_PDH);
            WriteReg();
        } else if (LOWORD(wParam) == IDC_CHECK_MONITOR_LEFT) {
            TraySave.bMonitorLeft = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_LEFT);
            WriteReg();
        } else if (LOWORD(wParam) == IDC_CHECK_MONITOR_FLOAT) {
            TraySave.bMonitorFloat = IsDlgButtonChecked(hDlg, IDC_CHECK_MONITOR_FLOAT);
            WriteReg();
            DestroyWindow(hTaskBar);
            DestroyWindow(hTaskTips);
            OpenTaskBar();
        } else if (LOWORD(wParam) == IDC_CHECK_TRANSPARENT) {
            TraySave.bMonitorTransparent = IsDlgButtonChecked(hDlg, IDC_CHECK_TRANSPARENT);
            WriteReg();
        } else if (LOWORD(wParam) == IDC_CHECK_AUTORUN) {
            if (IsDlgButtonChecked(hDlg, IDC_CHECK_AUTORUN))
                AutoRun(TRUE, TRUE);
            else
                AutoRun(TRUE, FALSE);
        } else if (LOWORD(wParam) == IDC_RESTORE_DEFAULT) {
            DeleteFile(szTraySave);
            SendMessage(hDlg, WM_COMMAND, IDCANCEL, 0);
        } else if(LOWORD(wParam) == IDCANCEL) {
            FreeTemperatureDLL();
            CloseHandle(hMutex);
            hMutex = NULL;
            SendMessage(hMain, WM_CLOSE, NULL, NULL);
            DestroyWindow(hDlg);
            RunProcess(NULL);
            PostQuitMessage(0);

            return (INT_PTR)TRUE;
        } else if (LOWORD(wParam) == IDC_CLOSE) {
            FreeTemperatureDLL();
            CloseHandle(hMutex);
            hMutex = NULL;
            SendMessage(hMain, WM_CLOSE, NULL, NULL);
            DestroyWindow(hDlg);
            PostQuitMessage(0);
        } else if (LOWORD(wParam) == IDC_BUTTON_FONT || LOWORD(wParam) == IDC_BUTTON_TIPS_FONT) {
#define CF_SCREENFONTS             0x00000001
#define CF_PRINTERFONTS            0x00000002
#define CF_BOTH                    (CF_SCREENFONTS | CF_PRINTERFONTS)
#define CF_SHOWHELP                0x00000004L
#define CF_ENABLEHOOK              0x00000008L
#define CF_ENABLETEMPLATE          0x00000010L
#define CF_ENABLETEMPLATEHANDLE    0x00000020L
#define CF_INITTOLOGFONTSTRUCT     0x00000040L
#define CF_USESTYLE                0x00000080L
#define CF_EFFECTS                 0x00000100L
#define CF_APPLY                   0x00000200L
#define CF_ANSIONLY                0x00000400L
#if(WINVER >= 0x0400)
#define CF_SCRIPTSONLY             CF_ANSIONLY
#endif     
#define CF_NOVECTORFONTS           0x00000800L
#define CF_NOOEMFONTS              CF_NOVECTORFONTS
#define CF_NOSIMULATIONS           0x00001000L
#define CF_LIMITSIZE               0x00002000L
#define CF_FIXEDPITCHONLY          0x00004000L
#define CF_WYSIWYG                 0x00008000L       
#define CF_FORCEFONTEXIST          0x00010000L
#define CF_SCALABLEONLY            0x00020000L
#define CF_TTONLY                  0x00040000L
#define CF_NOFACESEL               0x00080000L
#define CF_NOSTYLESEL              0x00100000L
#define CF_NOSIZESEL               0x00200000L
#if(WINVER >= 0x0400)
#define CF_SELECTSCRIPT            0x00400000L
#define CF_NOSCRIPTSEL             0x00800000L
#define CF_NOVERTFONTS             0x01000000L
#endif     
#if(WINVER >= 0x0601)
#define CF_INACTIVEFONTS           0x02000000L
#endif     

#define SIMULATED_FONTTYPE    0x8000
#define PRINTER_FONTTYPE      0x4000
#define SCREEN_FONTTYPE       0x2000
#define BOLD_FONTTYPE         0x0100
#define ITALIC_FONTTYPE       0x0200
#define REGULAR_FONTTYPE      0x0400
            typedef UINT_PTR(CALLBACK * LPCFHOOKPROC) (HWND, UINT, WPARAM, LPARAM);
            typedef struct tagCHOOSEFONTW {
                DWORD           lStructSize;
                HWND            hwndOwner;             
                HDC             hDC;                    
                LPLOGFONTW      lpLogFont;               
                INT             iPointSize;                 
                DWORD           Flags;                 
                COLORREF        rgbColors;             
                LPARAM          lCustData;               
                LPCFHOOKPROC    lpfnHook;               
                LPCWSTR         lpTemplateName;        
                HINSTANCE       hInstance;              
                LPWSTR          lpszStyle;               
                WORD            nFontType;                
                WORD            ___MISSING_ALIGNMENT__;
                INT             nSizeMin;                
                INT             nSizeMax;                
            } CHOOSEFONT;
            TraySave.TraybarFont.lfHeight = TraySave.TraybarFontSize;
            TraySave.TipsFont.lfHeight = TraySave.TipsFontSize;
            CHOOSEFONT cf;
            cf.lStructSize = sizeof cf;
            cf.hwndOwner = hDlg;
            cf.hDC = NULL;
            if(LOWORD(wParam) == IDC_BUTTON_FONT)
                cf.lpLogFont = &TraySave.TraybarFont;
            else
                cf.lpLogFont = &TraySave.TipsFont;
            cf.Flags = CF_SCREENFONTS | CF_INITTOLOGFONTSTRUCT | CF_EFFECTS;
            cf.nFontType = SCREEN_FONTTYPE;
            cf.rgbColors = RGB(0, 0, 0);
            typedef BOOL(WINAPI * pfnChooseFont)(CHOOSEFONT * lpcf);
            HMODULE hComdlg32 = LoadLibrary(L"comdlg32.dll");
            if (hComdlg32) {
                pfnChooseFont ChooseFont = (pfnChooseFont)GetProcAddress(hComdlg32, "ChooseFontW");
                if (ChooseFont) {
                    if (ChooseFont(&cf)) {
                        if (LOWORD(wParam) == IDC_BUTTON_FONT) {
                            TraySave.TraybarFontSize = TraySave.TraybarFont.lfHeight;
                            otleft = -1;
                            SetWH();
                            AdjustWindowPos();
                        } else
                            TraySave.TipsFontSize = TraySave.TipsFont.lfHeight;
                        WriteReg();
                    }
                }
                FreeLibrary(hComdlg32);
            }
        } else if (LOWORD(wParam) == IDC_BUTTON_COLOR || (LOWORD(wParam) >= IDC_BUTTON_COLOR_BACKGROUND && LOWORD(wParam) <= IDC_BUTTON_COLOR_HIGH)) {
            CHOOSECOLOR stChooseColor;
            stChooseColor.lStructSize = sizeof(CHOOSECOLOR);
            stChooseColor.hwndOwner = hDlg;
            if (LOWORD(wParam) == IDC_BUTTON_COLOR) {
                stChooseColor.rgbResult = TraySave.dAlphaColor[iProject];
                stChooseColor.lpCustColors = (LPDWORD)&TraySave.dAlphaColor[iProject];
            } else {
                stChooseColor.rgbResult = TraySave.cMonitorColor[LOWORD(wParam) - IDC_BUTTON_COLOR_BACKGROUND];
                stChooseColor.lpCustColors = TraySave.cMonitorColor;
            }
            stChooseColor.Flags = CC_RGBINIT | CC_FULLOPEN;
            stChooseColor.lCustData = 0;
            stChooseColor.lpfnHook = NULL;
            stChooseColor.lpTemplateName = NULL;
            typedef BOOL(WINAPI * pfnChooseColor)(LPCHOOSECOLOR lpcc);
            HMODULE hComdlg32 = LoadLibrary(L"comdlg32.dll");
            if (hComdlg32) {
                pfnChooseColor ChooseColor = (pfnChooseColor)GetProcAddress(hComdlg32, "ChooseColorW");
                if (ChooseColor) {
                    if (ChooseColor(&stChooseColor)) {
                        if (LOWORD(wParam) == IDC_BUTTON_COLOR) {
                            TraySave.dAlphaColor[iProject] = stChooseColor.rgbResult;
                            DWORD bAlphaB = (int)SendDlgItemMessage(hDlg, IDC_SLIDER_ALPHA_B, TBM_GETPOS, 0, 0);
                            bAlphaB = bAlphaB << 24;
                            TraySave.dAlphaColor[iProject] = bAlphaB + (TraySave.dAlphaColor[iProject] & 0xffffff);
                        } else {
                            TraySave.cMonitorColor[LOWORD(wParam - IDC_BUTTON_COLOR_BACKGROUND)] = stChooseColor.rgbResult;
                        }
                        ::InvalidateRect(GetDlgItem(hMain, LOWORD(wParam)), NULL, FALSE);
                    }
                }
                FreeLibrary(hComdlg32);
            }
            WriteReg();
        }
        break;
    }
    return (INT_PTR)FALSE;
}
typedef BOOL(WINAPI *pfnSetWindowCompositionAttribute)(HWND, struct _WINDOWCOMPOSITIONATTRIBDATA *);
BOOL SetWindowCompositionAttribute(HWND hWnd, ACCENT_STATE mode, DWORD AlphaColor) { 
    if (mode == ACCENT_DISABLED) {
        if (bAccentNormal == FALSE) {
            SendMessage(hWnd, WM_THEMECHANGED, 0, 0);
            bAccentNormal = TRUE;
        }
        return TRUE;
    }
    bAccentNormal = FALSE;
    BOOL ret = FALSE;
    HMODULE hUser = GetModuleHandle(L"user32.dll");
    if (hUser) {
        pfnSetWindowCompositionAttribute setWindowCompositionAttribute = (pfnSetWindowCompositionAttribute)GetProcAddress(hUser, "SetWindowCompositionAttribute");
        if (setWindowCompositionAttribute) {
            ACCENT_POLICY accent = { mode, 2, AlphaColor, 0 };
            _WINDOWCOMPOSITIONATTRIBDATA data;
            data.Attrib = WCA_ACCENT_POLICY;
            data.pvData = &accent;
            data.cbData = sizeof(accent);
            ret = setWindowCompositionAttribute(hWnd, &data);
        }
    }
    return ret;
}
typedef BOOL(WINAPI *pfnGetWindowCompositionAttribute)(HWND, struct _WINDOWCOMPOSITIONATTRIBDATA *);
BOOL AutoRun(BOOL GetSet, BOOL bAuto) { 
    BOOL ret = FALSE;
    WCHAR sFileName[MAX_PATH];
    GetModuleFileName(NULL, sFileName, MAX_PATH);
    if (IsUserAdmin()) {
        if (GetSet) {
            HKEY pKey;
            RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &pKey);
            if (pKey) {
                RegDeleteValue(pKey, szAppName);
                RegCloseKey(pKey);
            }
            RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &pKey);
            if (pKey) {
                RegDeleteValue(pKey, szAppName);
                RegCloseKey(pKey);
            }
            if (bAuto) {
                InstallService();
            } else {
                if (IsServiceInstalled())
                    UninstallService();
            }
        } else {
            return IsServiceInstalled();
        }
    } else {
        HKEY pKey;
        RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &pKey);
        if (pKey) {
            if (GetSet) {
                if (bAuto) {
                    RegSetValueEx(pKey, szAppName, NULL, REG_SZ, (BYTE *)sFileName, (DWORD)wcslen(sFileName) * 2);
                } else {
                    RegDeleteValue(pKey, szAppName);
                }
                ret = TRUE;
            } else {
                WCHAR nFileName[MAX_PATH];
                DWORD cbData = MAX_PATH * sizeof WCHAR;
                DWORD dType = REG_SZ;
                if (RegQueryValueEx(pKey, szAppName, NULL, &dType, (LPBYTE)nFileName, &cbData) == ERROR_SUCCESS) {
                    if (wcscmp(sFileName, nFileName) == 0)
                        ret = TRUE;
                    else
                        ret = FALSE;
                }
            }
            RegCloseKey(pKey);
        }
    }
    return ret;
}
INT_PTR CALLBACK ColorButtonProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) { 
    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc;
        GetClientRect(hWnd, &rc);
        HBRUSH hb;
        int id = GetDlgCtrlID(hWnd);
        if (id >= IDC_BUTTON_COLOR_BACKGROUND && id <= IDC_BUTTON_COLOR_HIGH) {
            hb = CreateSolidBrush(TraySave.cMonitorColor[id - IDC_BUTTON_COLOR_BACKGROUND]);
        } else
            hb = CreateSolidBrush(TraySave.dAlphaColor[iProject] & 0xffffff);
        FillRect(hdc, &rc, hb);
        DeleteObject(hb);
        EndPaint(hWnd, &ps);
        return TRUE;
    }
    }
    return CallWindowProc(oldColorButtonPoroc, hWnd, message, wParam, lParam);
}
BOOL EnableDebugPrivilege(BOOL bEnableDebugPrivilege) { 
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
            tp.PrivilegeCount = 1;
            if (bEnableDebugPrivilege)
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            else
                tp.Privileges[0].Attributes = 0;
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
                ::CloseHandle(hToken);
                return TRUE;
            }
        }
        CloseHandle(hToken);
    }
    return FALSE;
}
