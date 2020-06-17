#pragma once

#include "resource.h"
#include <commctrl.h>
//#pragma comment(lib, "comctl32.lib")
//#include <Commdlg.h>
#define CC_RGBINIT               0x00000001
#define CC_FULLOPEN              0x00000002
#define CC_PREVENTFULLOPEN       0x00000004
#define CC_SHOWHELP              0x00000008
#define CC_ENABLEHOOK            0x00000010
#define CC_ENABLETEMPLATE        0x00000020
#define CC_ENABLETEMPLATEHANDLE  0x00000040
#if(WINVER >= 0x0400)
#define CC_SOLIDCOLOR            0x00000080
#define CC_ANYCOLOR              0x00000100
#endif /* WINVER >= 0x0400 */
typedef UINT_PTR(CALLBACK *LPCCHOOKPROC) (HWND, UINT, WPARAM, LPARAM);
typedef struct tagCHOOSECOLORW {
    DWORD        lStructSize;
    HWND         hwndOwner;
    HWND         hInstance;
    COLORREF     rgbResult;
    COLORREF *lpCustColors;
    DWORD        Flags;
    LPARAM       lCustData;
    LPCCHOOKPROC lpfnHook;
    LPCWSTR      lpTemplateName;
} CHOOSECOLORW, * LPCHOOSECOLORW;
typedef CHOOSECOLORW CHOOSECOLOR;
typedef LPCHOOSECOLORW LPCHOOSECOLOR;
//#include <Shellapi.h>
typedef struct _NOTIFYICONDATAW {
    DWORD cbSize;
    HWND hWnd;
    UINT uID;
    UINT uFlags;
    UINT uCallbackMessage;
    HICON hIcon;
#if (NTDDI_VERSION < NTDDI_WIN2K)
    WCHAR  szTip[64];
#endif
#if (NTDDI_VERSION >= NTDDI_WIN2K)
    WCHAR  szTip[128];
    DWORD dwState;
    DWORD dwStateMask;
    WCHAR  szInfo[256];
#ifndef _SHELL_EXPORTS_INTERNALAPI_H_
    union {
        UINT  uTimeout;
        UINT  uVersion;  // used with NIM_SETVERSION, values 0, 3 and 4
    } DUMMYUNIONNAME;
#endif
    WCHAR  szInfoTitle[64];
    DWORD dwInfoFlags;
#endif
#if (NTDDI_VERSION >= NTDDI_WINXP)
    GUID guidItem;
#endif
#if (NTDDI_VERSION >= NTDDI_VISTA)
    HICON hBalloonIcon;
#endif
} NOTIFYICONDATAW, * PNOTIFYICONDATAW;
#ifdef UNICODE
typedef NOTIFYICONDATAW NOTIFYICONDATA;
typedef PNOTIFYICONDATAW PNOTIFYICONDATA;
#else
typedef NOTIFYICONDATAA NOTIFYICONDATA;
typedef PNOTIFYICONDATAA PNOTIFYICONDATA;
#endif // UNICODE
#define NIF_MESSAGE     0x00000001
#define NIF_ICON        0x00000002
#define NIF_TIP         0x00000004
#define NIF_STATE       0x00000008
#define NIF_INFO        0x00000010
#if (_WIN32_IE >= 0x600)
#define NIF_GUID        0x00000020
#endif
#if (NTDDI_VERSION >= NTDDI_VISTA)
#define NIF_REALTIME    0x00000040
#define NIF_SHOWTIP     0x00000080
#endif // (NTDDI_VERSION >= NTDDI_VISTA)
#define NIM_ADD         0x00000000
#define NIM_MODIFY      0x00000001
#define NIM_DELETE      0x00000002
#define NIM_SETFOCUS    0x00000003
#define NIM_SETVERSION  0x00000004


#include <Oleacc.h>
//#pragma comment(lib, "Oleacc.lib")
#include <winsock2.h>


#include <Iphlpapi.h>
//#pragma comment(lib, "Iphlpapi.lib")


#include <Tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
//WINRING0
#include "OlsDef.h"
#include "OlsApiInit.h"
//ATIGPU
#include "adl_sdk.h"

//#include <Powrprof.h>
//#pragma comment(lib, "Powrprof.lib")

//#include <WtsApi32.h>
//#pragma comment(lib, "WtsApi32.lib")
//#include <Userenv.h>
//#pragma comment(lib, "Userenv.lib")

//#include <pdh.h>
//#pragma comment(lib, "pdh.lib")

#define GET_X_LPARAM(lp)                        ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp)                        ((int)(short)HIWORD(lp))
#define MAX_LOADSTRING 100
#define MAX_TEXT 2048
#define  WM_IAWENTRAY WM_USER+8//通知栏消息
#define  WM_TRAYS WM_USER+8888
extern "C" WINUSERAPI BOOL WINAPI TrackMouseEvent(LPTRACKMOUSEEVENT lpEventTrack);
// 全局变量:
typedef enum _WINDOWCOMPOSITIONATTRIB {
    WCA_UNDEFINED = 0,
    WCA_NCRENDERING_ENABLED = 1,
    WCA_NCRENDERING_POLICY = 2,
    WCA_TRANSITIONS_FORCEDISABLED = 3,
    WCA_ALLOW_NCPAINT = 4,
    WCA_CAPTION_BUTTON_BOUNDS = 5,
    WCA_NONCLIENT_RTL_LAYOUT = 6,
    WCA_FORCE_ICONIC_REPRESENTATION = 7,
    WCA_EXTENDED_FRAME_BOUNDS = 8,
    WCA_HAS_ICONIC_BITMAP = 9,
    WCA_THEME_ATTRIBUTES = 10,
    WCA_NCRENDERING_EXILED = 11,
    WCA_NCADORNMENTINFO = 12,
    WCA_EXCLUDED_FROM_LIVEPREVIEW = 13,
    WCA_VIDEO_OVERLAY_ACTIVE = 14,
    WCA_FORCE_ACTIVEWINDOW_APPEARANCE = 15,
    WCA_DISALLOW_PEEK = 16,
    WCA_CLOAK = 17,
    WCA_CLOAKED = 18,
    WCA_ACCENT_POLICY = 19,
    WCA_FREEZE_REPRESENTATION = 20,
    WCA_EVER_UNCLOAKED = 21,
    WCA_VISUAL_OWNER = 22,
    WCA_LAST = 23
} WINDOWCOMPOSITIONATTRIB;
typedef struct _WINDOWCOMPOSITIONATTRIBDATA {
    WINDOWCOMPOSITIONATTRIB Attrib;
    PVOID pvData;
    SIZE_T cbData;
} WINDOWCOMPOSITIONATTRIBDATA;
typedef enum _ACCENT_STATE {
    ACCENT_DISABLED = 0,
    ACCENT_ENABLE_GRADIENT = 1,
    ACCENT_ENABLE_TRANSPARENTGRADIENT = 2,
    ACCENT_ENABLE_BLURBEHIND = 3,
    ACCENT_ENABLE_ACRYLICBLURBEHIND = 4,
    ACCENT_INVALID_STATE = 5,
    ACCENT_ENABLE_TRANSPARENT = 6,
    ACCENT_NORMAL = 150
} ACCENT_STATE;
typedef struct _ACCENT_POLICY {
    ACCENT_STATE AccentState;
    DWORD AccentFlags;
    DWORD GradientColor;
    DWORD AnimationId;
} ACCENT_POLICY;
/////////////////////////////////////////////自定义结构
typedef struct {
    DWORD in_bytes;
    DWORD out_bytes;
    DWORD in_byte;
    DWORD out_byte;
    PWCHAR FriendlyName;
    WCHAR IP4[16];
} TRAFFIC;
typedef struct {
    WCHAR szExe[25];
    DWORD dwProcessID;
    SIZE_T dwMemUsage;
} PROCESSMEMORYUSAGE;
typedef struct {
    WCHAR szExe[25];
    DWORD dwProcessID;
    float fCpuUsage;
} PROCESSCPUUSAGE;
typedef struct {
    DWORD dwProcessID;
    LARGE_INTEGER g_slgProcessTimeOld;
} PROCESSTIME;
DWORD dNumProcessor = 0;//CPU数量
HINSTANCE hInst;// 当前实例
HWND hMain;//主窗口句柄
HWND hSetting;//设置窗口句柄
HWND hTaskBar;//工具窗口句柄
HWND hTaskTips;//提示窗口句柄
//HWND hForeground;
HWND hTray = NULL; //系统主任务栏窗口句柄
HWND hTaskWnd;//系统主任务列表窗口句柄
HWND hReBarWnd = NULL; //系统主任务工具窗口句柄
HICON iMain;//窗口图标
HANDLE hMutex;//只能运行一个程序
WCHAR szShellTray[] = L"Shell_TrayWnd";//主任务栏类名
WCHAR szSecondaryTray[] = L"Shell_SecondaryTrayWnd";//副任务栏类名
//WCHAR szSubKey[] = L"SOFTWARE\\TrayPro";//程序注册表键名
WCHAR szAppName[] = L"TrayS";//程序名
WCHAR szNetCpl[] = L" cncpa.cpl";//打开网络设置
WCHAR szTaskmgr[] = L" oTaskmgr";//打开任务管理器
WCHAR szPowerCpl[] = L" cpowercfg.cpl";//打开电源设置
WCHAR szTraySave[] = L"TrayS.dat";
MIB_IFTABLE *mi;//网速结构
//PIP_ADAPTER_INFO ipinfo;
PIP_ADAPTER_ADDRESSES piaa;//网卡结构
TRAFFIC *traffic;//每个网卡速度
int nTraffic = 0; //有几张网卡
DWORD m_last_in_bytes = 0;//总上一秒下载速度
DWORD m_last_out_bytes = 0;//总上一秒上传速度
DWORD s_in_byte = 0;//总下载速度
DWORD s_out_byte = 0;//总上传速度
int mWidth;//工具窗口宽度
int mHeight;//工具窗口竖排高度
int iDPI = 96;//当前DPI
BOOL VTray = FALSE;//竖的任务栏
struct { //默认参数
    DWORD Ver = 96;
    ACCENT_STATE aMode[2] = { ACCENT_ENABLE_TRANSPARENTGRADIENT, ACCENT_ENABLE_BLURBEHIND };
    DWORD dAlphaColor[2] = { 0x00111111, 0x66000000 };
    DWORD bAlpha[2] = { 255, 255 };
    DWORD dNumValues[12] = { 10 * 1024 * 1024, 64 * 1024 * 1024, 60, 80, 39, 81, 39, 81, 98 * 1048576, 88, 0, 0 };
    BOOL bSound;
    int iPos = 1;
    int iUnit = 1;
    BOOL bTrayIcon = FALSE;
    BOOL bMonitor = TRUE;
    BOOL bMonitorLeft = TRUE;
    BOOL bMonitorFloat = FALSE;
    BOOL bMonitorTransparent = FALSE;
    BOOL bMonitorTraffic = TRUE;
    BOOL bMonitorTemperature = FALSE;
    BOOL bMonitorUsage = TRUE;
    BOOL bMonitorPDH = FALSE;
    int iMonitorSimple = 1;
    COLORREF cMonitorColor[8] = { RGB(0, 0, 0), RGB(128, 128, 128), RGB(192, 192, 192), RGB(255, 255, 255), RGB(0, 168, 0), RGB(168, 168, 0), RGB(168, 0, 0), RGB(0, 0, 0) };
    POINT dMonitorPoint = { 666, 666 };
    CHAR AdpterName[39] = { 0 };
    DWORD FlushTime = 33;
    BOOL bMonitorTips = TRUE;

    LOGFONT TraybarFont = {-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, 0, L"微软雅黑"};
    int TraybarFontSize = -12;
    LOGFONT TipsFont = { -12, 0, 0, 0, FW_NORMAL, 0, 0, 0, 0, 0, 0, 0, 0, L"微软雅黑" };
    int TipsFontSize = -12;
    WCHAR szTrafficOut[8] = L"上传:";
    WCHAR szTrafficIn[8] = L"下载:";
    WCHAR szTemperatureCPU[8] = L"CPU:";
    WCHAR szTemperatureCPUUnit[4] = L"℃";
    WCHAR szTemperatureGPU[8] = L"GPU:";
    WCHAR szTemperatureGPUUnit[4] = L"℃";
    WCHAR szUsageCPU[8] = L"CPU:";
    WCHAR szUsageCPUUnit[4] = L"%";
    WCHAR szUsageMEM[8] = L"内存:";
    WCHAR szUsageMEMUnit[4] = L"%";
} TraySave;
int wTraffic;//流量宽度
int wTemperature;//温度宽度
int wUsage;//利用率宽度
int wHeight;//监控字符高度
HFONT hFont;//监控窗口字体
BOOL bSettingInit = FALSE; //设置在初始化
int wTipsHeight;//提示字符高度
BOOL inTipsProcessX = FALSE;//是否在X按键中
/*
WCHAR szTrayIcon[] = L"TrayIcon";
WCHAR szPos[] = L"Pos";
WCHAR szUnit[] = L"Unit";
WCHAR szMode[] = L"StyleMode";
WCHAR szAlphaColor[] = L"AlphaColor";
WCHAR szAlpha[] = L"Alpha";
WCHAR szMonitor[] = L"Monitor";
WCHAR szMonitorLeft[] = L"MonitorLeft";
WCHAR szMonitorFloat[] = L"MonitorFloat";
WCHAR szMonitorTransparent[] = L"MonitorT";
WCHAR szMonitorPoint[] = L"MonitorPoint";
WCHAR szMonitorTraffic[] = L"MonitorTraffic";
WCHAR szMonitorTemperature[] = L"MonitorTemperature";
WCHAR szMonitorUsage[] = L"MonitorUsage";
WCHAR szMonitorPDH[] = L"MonitorPDH";
WCHAR szMonitorColor[] = L"MonitorColor";
WCHAR szSound[] = L"Sound";
WCHAR szNumValues[] = L"NumValues";
WCHAR szMonitorSimple[] = L"MonitorSimple";
WCHAR szAdapterName[] = L"AdpterName";
*/
NOTIFYICONDATA nid = { 0 };//通知栏传入结构
//RTL_OSVERSIONINFOW rovi;
//BOOL bErasebkgnd = TRUE;
int iProject = -1;
int iWindowMode = FALSE;
BOOL bAccentNormal = FALSE;
MEMORYSTATUSEX MemoryStatusEx;
BOOL bTaskBarMoveing = FALSE;
PROCESSMEMORYUSAGE pmu[3];
PROCESSMEMORYUSAGE *ppmu[3];
PROCESSCPUUSAGE pcu[3];
PROCESSCPUUSAGE *ppcu[3];
int nProcess;
PROCESSTIME *pProcessTime;
BOOL bTaskOther = FALSE;

HMODULE hPDH = NULL;

////////////////////////////////////////////////查找隐藏试最大化窗口
HMODULE hDwmapi = NULL;
typedef BOOL(WINAPI *pfnDwmGetWindowAttribute)(HWND hwnd, DWORD dwAttribute, PVOID pvAttribute, DWORD cbAttribute);
pfnDwmGetWindowAttribute DwmGetWindowAttribute;
////////////////////////////////////////////////获取网速
HMODULE hIphlpapi = NULL;
typedef ULONG(WINAPI *pfnGetAdaptersAddresses)(_In_ ULONG Family, _In_ ULONG Flags, _Reserved_ PVOID Reserved, _Out_writes_bytes_opt_(*SizePointer) PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer);
typedef DWORD(WINAPI *pfnGetIfTable)(_Out_writes_bytes_opt_(*pdwSize) PMIB_IFTABLE pIfTable, _Inout_ PULONG pdwSize, _In_ BOOL bOrder);
pfnGetAdaptersAddresses GetAdaptersAddressesT;
pfnGetIfTable GetIfTableT;
HMODULE hOleacc = NULL;
typedef ULONG(WINAPI *pfnAccessibleObjectFromWindow)(_In_ HWND hwnd, _In_ DWORD dwId, _In_ REFIID riid, _Outptr_ void **ppvObject);
typedef ULONG(WINAPI *pfnAccessibleChildren)(_In_ IAccessible *paccContainer, _In_ LONG iChildStart, _In_ LONG cChildren, _Out_writes_(cChildren) VARIANT *rgvarChildren, _Out_ LONG *pcObtained);
pfnAccessibleObjectFromWindow AccessibleObjectFromWindowT;
pfnAccessibleChildren AccessibleChildrenT;
/////////////////////////////////////////////////CPU温度
BOOL bRing0 = NULL;
HMODULE m_hOpenLibSys = NULL;
DWORD iTemperature1;
DWORD iTemperature2;
BOOL bIntel;
////////////////////////////////////////////////ATI显卡温度
// Memory allocation function
void *__stdcall ADL_Main_Memory_Alloc(int iSize) {
    void *lpBuffer = malloc(iSize);
    return lpBuffer;
}
// Optional Memory de-allocation function
void __stdcall ADL_Main_Memory_Free(void **lpBuffer) {
    if (NULL != *lpBuffer) {
        free(*lpBuffer);
        *lpBuffer = NULL;
    }
}
// Definitions of the used function pointers. Add more if you use other ADL APIs
typedef int(*ADL_MAIN_CONTROL_CREATE)(ADL_MAIN_MALLOC_CALLBACK, int);
typedef int(*ADL_MAIN_CONTROL_DESTROY)();
typedef int(*ADL_OVERDRIVE5_TEMPERATURE_GET) (int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature);
ADL_MAIN_CONTROL_CREATE					ADL_Main_Control_Create;
ADL_MAIN_CONTROL_DESTROY				ADL_Main_Control_Destroy;
ADL_OVERDRIVE5_TEMPERATURE_GET			ADL_Overdrive5_Temperature_Get;
ADLTemperature adlTemperature = { 0 };
HMODULE hATIDLL = NULL;
///////////////////////////////////////////////NVIDIA显卡温度
// 接口ID值
#define ID_NvAPI_Initialize                     0x0150E828
#define ID_NvAPI_GPU_GetFullName                0xCEEE8E9F
#define ID_NvAPI_GPU_GetThermalSettings         0xE3640A56
#define ID_NvAPI_EnumNvidiaDisplayHandle        0x9ABDD40D
#define ID_NvAPI_GetPhysicalGPUsFromDisplay     0x34EF9506
#define ID_NvAPI_EnumPhysicalGPUs               0xE5AC921F
#define ID_NvAPI_GPU_GetTachReading             0x5F608315
#define ID_NvAPI_GPU_GetAllClocks               0x1BD69F49
#define ID_NvAPI_GPU_GetPStates                 0x60DED2ED
#define ID_NvAPI_GPU_GetUsages                  0x189A1FDF
#define ID_NvAPI_GPU_GetCoolerSettings          0xDA141340
#define ID_NvAPI_GPU_SetCoolerLevels            0x891FA0AE
#define ID_NvAPI_GPU_GetMemoryInfo              0x774AA982
#define ID_NvAPI_GetDisplayDriverVersion        0xF951A4D1
#define ID_NvAPI_GetInterfaceVersionString      0x01053FA5
#define ID_NvAPI_GPU_GetPCIIdentifiers          0x2DDFB66E
#define NVAPI_MAX_THERMAL_SENSORS_PER_GPU 3
#define NVAPI_MAX_PHYSICAL_GPUS 64
#define NvU32 unsigned long
#define NvS32 signed int
#define MAKE_NVAPI_VERSION(typeName,ver)(NvU32)(sizeof(typeName) | ((ver) << 16))
typedef int NvPhysicalGpuHandle;
typedef int NvDisplayHandle;
#define MAX_THERMAL_SENSORS_PER_GPU     3
typedef enum {
    NVAPI_THERMAL_CONTROLLER_NONE = 0,
    NVAPI_THERMAL_CONTROLLER_GPU_INTERNAL,
    NVAPI_THERMAL_CONTROLLER_ADM1032,
    NVAPI_THERMAL_CONTROLLER_MAX6649,
    NVAPI_THERMAL_CONTROLLER_MAX1617,
    NVAPI_THERMAL_CONTROLLER_LM99,
    NVAPI_THERMAL_CONTROLLER_LM89,
    NVAPI_THERMAL_CONTROLLER_LM64,
    NVAPI_THERMAL_CONTROLLER_ADT7473,
    NVAPI_THERMAL_CONTROLLER_SBMAX6649,
    NVAPI_THERMAL_CONTROLLER_VBIOSEVT,
    NVAPI_THERMAL_CONTROLLER_OS,
    NVAPI_THERMAL_CONTROLLER_UNKNOWN = -1,
} NV_THERMAL_CONTROLLER;
typedef enum {
    NVAPI_THERMAL_TARGET_NONE = 0,
    NVAPI_THERMAL_TARGET_GPU = 1,     //!< GPU core temperature requires NvPhysicalGpuHandle
    NVAPI_THERMAL_TARGET_MEMORY = 2,     //!< GPU memory temperature requires NvPhysicalGpuHandle
    NVAPI_THERMAL_TARGET_POWER_SUPPLY = 4,     //!< GPU power supply temperature requires NvPhysicalGpuHandle
    NVAPI_THERMAL_TARGET_BOARD = 8,     //!< GPU board ambient temperature requires NvPhysicalGpuHandle
    NVAPI_THERMAL_TARGET_VCD_BOARD = 9,     //!< Visual Computing Device Board temperature requires NvVisualComputingDeviceHandle
    NVAPI_THERMAL_TARGET_VCD_INLET = 10,    //!< Visual Computing Device Inlet temperature requires NvVisualComputingDeviceHandle
    NVAPI_THERMAL_TARGET_VCD_OUTLET = 11,    //!< Visual Computing Device Outlet temperature requires NvVisualComputingDeviceHandle

    NVAPI_THERMAL_TARGET_ALL = 15,
    NVAPI_THERMAL_TARGET_UNKNOWN = -1,
} NV_THERMAL_TARGET;
typedef struct {
    NvU32   version;                //!< structure version
    NvU32   count;                  //!< number of associated thermal sensors
    struct {
        NV_THERMAL_CONTROLLER       controller;        //!< internal, ADM1032, MAX6649...
        NvU32                       defaultMinTemp;    //!< The min default temperature value of the thermal sensor in degree Celsius
        NvU32                       defaultMaxTemp;    //!< The max default temperature value of the thermal sensor in degree Celsius
        NvU32                       currentTemp;       //!< The current temperature value of the thermal sensor in degree Celsius
        NV_THERMAL_TARGET           target;            //!< Thermal sensor targeted @ GPU, memory, chipset, powersupply, Visual Computing Device, etc.
    } sensor[NVAPI_MAX_THERMAL_SENSORS_PER_GPU];

} NV_GPU_THERMAL_SETTINGS_V1;
typedef struct {
    NvU32   version;                //!< structure version
    NvU32   count;                  //!< number of associated thermal sensors
    struct {
        NV_THERMAL_CONTROLLER       controller;         //!< internal, ADM1032, MAX6649...
        NvS32                       defaultMinTemp;     //!< Minimum default temperature value of the thermal sensor in degree Celsius
        NvS32                       defaultMaxTemp;     //!< Maximum default temperature value of the thermal sensor in degree Celsius
        NvS32                       currentTemp;        //!< Current temperature value of the thermal sensor in degree Celsius
        NV_THERMAL_TARGET           target;             //!< Thermal sensor targeted - GPU, memory, chipset, powersupply, Visual Computing Device, etc
    } sensor[NVAPI_MAX_THERMAL_SENSORS_PER_GPU];

} NV_GPU_THERMAL_SETTINGS_V2;
typedef NV_GPU_THERMAL_SETTINGS_V2  NV_GPU_THERMAL_SETTINGS;
#define NV_GPU_THERMAL_SETTINGS_VER_1   MAKE_NVAPI_VERSION(NV_GPU_THERMAL_SETTINGS_V1,1)
#define NV_GPU_THERMAL_SETTINGS_VER_2   MAKE_NVAPI_VERSION(NV_GPU_THERMAL_SETTINGS_V2,2)
#define NV_GPU_THERMAL_SETTINGS_VER     NV_GPU_THERMAL_SETTINGS_VER_2
typedef UINT32 NvAPI_Status;
typedef void *(*NvAPI_QueryInterface_t)(UINT32 offset);
typedef NvAPI_Status(__cdecl *NvAPI_Initialize_t)(void);
typedef NvAPI_Status(*NvAPI_EnumPhysicalGPUs_t)(NvPhysicalGpuHandle *pGpuHandles, int *pGpuCount);
typedef NvAPI_Status(__cdecl *NvAPI_GPU_GetThermalSettings_t)(const NvPhysicalGpuHandle gpuHandle, int sensorIndex, NV_GPU_THERMAL_SETTINGS *pnvGPUThermalSettings);
NvAPI_QueryInterface_t NvAPI_QueryInterface;
NvAPI_GPU_GetThermalSettings_t NvAPI_GPU_GetThermalSettings;
HMODULE hNVDLL = NULL;
NvPhysicalGpuHandle hPhysicalGpu[4];
/////////////////////////////////////////////////////CPU频率
typedef struct _PROCESSOR_POWER_INFORMATION {
    ULONG Number;
    ULONG MaxMhz;
    ULONG CurrentMhz;
    ULONG MhzLimit;
    ULONG MaxIdleState;
    ULONG CurrentIdleState;
} PROCESSOR_POWER_INFORMATION, *PPROCESSOR_POWER_INFORMATION;

// 此代码模块中包含的函数的前向声明:
INT_PTR CALLBACK    ColorButtonProc(HWND, UINT, WPARAM, LPARAM);//颜色按钮子类化过程
WNDPROC oldColorButtonPoroc;//原来的颜色按钮控件过程

void AdjustWindowPos();
BOOL                InitInstance(HINSTANCE, int);
INT_PTR CALLBACK    MainProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    SettingProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    TaskBarProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    TaskTipsProc(HWND, UINT, WPARAM, LPARAM);
BOOL AutoRun(BOOL GetSet, BOOL bAuto);
BOOL SetWindowCompositionAttribute(HWND, ACCENT_STATE, DWORD);//设置磨砂
BOOL GetWindowCompositionAttribute(HWND, ACCENT_POLICY *);//获取磨砂
void SetTaskBarPos(HWND, HWND, HWND, HWND, BOOL);
int GetScreenRect(HWND, LPRECT, BOOL);
BOOL EnableDebugPrivilege(BOOL bEnableDebugPrivilege);
//int DrawShadowText(HDC hDC, LPCTSTR lpString, int nCount, LPRECT lpRect, UINT uFormat);
BOOL ServiceCtrlStop();
void FreeTemperatureDLL();
void LoadTemperatureDLL();
void SetWH();
int GetProcessMemUsage();
void GetProcessCpuUsage();