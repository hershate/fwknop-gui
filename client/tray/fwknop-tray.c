/*
 * \file client/tray/fwknop-tray.c
 *
 * \brief fwknop Windows 便携版托盘程序。
 *
 * 启动后在系统托盘显示彩色图标表示运行状态（绿=空闲 / 黄=敲门中 / 红=失败），
 * 右键菜单列出 ~/.fwknoprc 中的 profile，点击即调用同目录下的 fwknop.exe
 * 发送真实 SPA 单包（含 TOTP 端口跳变与 v4 device_id），实现 Windows 上的
 * 端口敲门。敲门在后台线程异步执行，结果以气泡通知反馈，不阻塞 UI。
 *
 * 便携包目录结构：
 *   fwknop-tray.exe   本程序（托盘 GUI，不依赖 libfko）
 *   fwknop.exe        fwknop 客户端（v4 敲门器，随包提供）
 *
 * 编译（MinGW）：
 *   gcc -municode -mwindows -O2 -Wall fwknop-tray.c tray_res.o \
 *       -o fwknop-tray.exe -lshlwapi -lshell32
 *
 * License: GPL v2 or later（与 fwknop 一致）。
 */
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0600   /* Vista+：Shell_NotifyIconW 气泡通知 */
#define _WIN32_IE    0x0600

#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>           /* _beginthreadex */

/* ---- 消息与菜单 ID ---- */
#define WM_TRAYICON      (WM_USER + 1)   /* 托盘图标回调消息 */
#define WM_KNOCK_DONE    (WM_APP  + 1)   /* 敲门线程完成通知主线程 */
#define IDM_PROFILE_BASE 1000            /* 动态 profile 菜单项起始 ID */
#define IDM_OPENRC       9000
#define IDM_RELOAD       9001
#define IDM_SETUP        9002
#define IDM_LINT         9003
#define IDM_STATUS       9004
#define IDM_ABOUT        9005
#define IDM_EXIT         9006

#define MAX_PROFILES     64
#define PROFILE_NAME_LEN 128
#define OUT_BUFSZ        4096

static const wchar_t *WC_TRAY = L"FwknopTrayHiddenWnd";

static HWND       g_hwnd = NULL;
static HINSTANCE  g_hinst = NULL;
static UINT       g_taskbar_created = 0;          /* explorer 重启后重建图标 */
static NOTIFYICONDATAW g_nid;
static HICON      g_icon_idle = NULL, g_icon_busy = NULL, g_icon_err = NULL;

static wchar_t    g_fwknop_exe[MAX_PATH] = {0};  /* 同目录 fwknop.exe */
static wchar_t    g_rc_path[MAX_PATH]    = {0};  /* %USERPROFILE%\.fwknoprc */
static wchar_t    g_profiles[MAX_PROFILES][PROFILE_NAME_LEN];
static int        g_profile_count = 0;
static wchar_t    g_last_status[512] = {0};      /* 最近一次状态摘要 */
static wchar_t    g_last_output[OUT_BUFSZ] = {0};/* 最近一次敲门输出 */
static int        g_busy = 0;                    /* 敲门进行中标志 */

/* 敲门线程参数 */
typedef struct {
    wchar_t profile[PROFILE_NAME_LEN];
} KnockArg;

/* ---------------------------------------------------------------- */
/* 运行时生成纯色圆形图标（避免携带 .ico 二进制资源）               */
/* mask 的圆形区域为黑色（opaque），其余白色（透明）                 */
/* ---------------------------------------------------------------- */
static HICON
make_icon(COLORREF c)
{
    int cx = GetSystemMetrics(SM_CXSMICON);
    int cy = GetSystemMetrics(SM_CYSMICON);
    if (cx < 16) cx = 16;
    if (cy < 16) cy = 16;

    HDC  sdc = GetDC(NULL);
    HDC  cdc = CreateCompatibleDC(sdc);
    HDC  mdc = CreateCompatibleDC(sdc);
    HBITMAP cbm = CreateCompatibleBitmap(sdc, cx, cy);
    HBITMAP mbm = CreateBitmap(cx, cy, 1, 1, NULL);

    HBITMAP oc = (HBITMAP)SelectObject(cdc, cbm);
    HBITMAP om = (HBITMAP)SelectObject(mdc, mbm);

    RECT r = {0, 0, cx, cy};

    /* color bitmap：整块填色 */
    HBRUSH br = CreateSolidBrush(c);
    FillRect(cdc, &r, br);
    DeleteObject(br);

    /* mask bitmap：白色=透明，黑色圆=不透明 */
    FillRect(mdc, &r, (HBRUSH)GetStockObject(WHITE_BRUSH));
    SelectObject(mdc, GetStockObject(BLACK_BRUSH));
    SelectObject(mdc, GetStockObject(NULL_PEN));
    Ellipse(mdc, 0, 0, cx, cy);

    SelectObject(cdc, oc);
    SelectObject(mdc, om);
    DeleteDC(cdc);
    DeleteDC(mdc);
    ReleaseDC(NULL, sdc);

    ICONINFO ii;
    ii.fIcon      = TRUE;
    ii.xHotspot   = 0;
    ii.yHotspot   = 0;
    ii.hbmMask    = mbm;
    ii.hbmColor   = cbm;
    HICON ic = CreateIconIndirect(&ii);

    DeleteObject(cbm);
    DeleteObject(mbm);
    return ic;
}

/* 0=idle 1=busy 2=err */
static void
set_icon_state(int state)
{
    g_nid.hIcon = (state == 0) ? g_icon_idle : (state == 1 ? g_icon_busy : g_icon_err);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void
show_notify(const wchar_t *title, const wchar_t *msg, DWORD flags)
{
    NOTIFYICONDATAW n;
    memset(&n, 0, sizeof(n));
    n.cbSize = sizeof(n);
    n.hWnd   = g_hwnd;
    n.uID    = 1;
    n.uFlags = NIF_INFO;
    n.dwInfoFlags = flags;
    n.uTimeout = 10000;
    lstrcpynW(n.szInfoTitle, title, sizeof(n.szInfoTitle) / sizeof(wchar_t));
    lstrcpynW(n.szInfo, msg, sizeof(n.szInfo) / sizeof(wchar_t));
    Shell_NotifyIconW(NIM_MODIFY, &n);

    /* 记录最近状态供「状态」菜单查看 */
    _snwprintf(g_last_status, 512, L"%s： %s", title, msg);
}

/* ---------------------------------------------------------------- */
/* 路径与 profile 解析                                              */
/* ---------------------------------------------------------------- */
static void
init_paths(void)
{
    wchar_t exe[MAX_PATH];
    wchar_t dir[MAX_PATH];

    GetModuleFileNameW(NULL, exe, MAX_PATH);
    lstrcpynW(dir, exe, MAX_PATH);
    PathRemoveFileSpecW(dir);
    _snwprintf(g_fwknop_exe, MAX_PATH, L"%s\\fwknop.exe", dir);

    const wchar_t *home = _wgetenv(L"USERPROFILE");
    if (home == NULL || home[0] == 0)
        home = _wgetenv(L"APPDATA");
    if (home == NULL || home[0] == 0)
        home = L".";
    _snwprintf(g_rc_path, MAX_PATH, L"%s\\.fwknoprc", home);
}

static void
reload_profiles(void)
{
    FILE *f;
    wchar_t line[512];

    g_profile_count = 0;

    f = _wfopen(g_rc_path, L"r");
    if (f == NULL)
        return;

    while (fgetws(line, 512, f) != NULL && g_profile_count < MAX_PROFILES)
    {
        wchar_t *p = line;
        wchar_t *e;
        int len;

        while (*p == L' ' || *p == L'\t')         /* 去前导空白 */
            p++;
        if (*p != L'[')
            continue;
        e = wcschr(p, L']');
        if (e == NULL)
            continue;
        len = (int)(e - p - 1);
        if (len <= 0 || len >= PROFILE_NAME_LEN)
            continue;
        wcsncpy(g_profiles[g_profile_count], p + 1, len);
        g_profiles[g_profile_count][len] = 0;
        g_profile_count++;
    }
    fclose(f);
}

static int
fwknop_exists(void)
{
    DWORD a = GetFileAttributesW(g_fwknop_exe);
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

/* ---------------------------------------------------------------- */
/* 在新控制台窗口中运行 fwknop 子命令（setup / lint），用户可见输出 */
/* ---------------------------------------------------------------- */
static void
run_console(const wchar_t *args)
{
    wchar_t cmd[1024];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    if (!fwknop_exists())
    {
        show_notify(L"错误", L"未找到同目录下的 fwknop.exe", NIIF_ERROR);
        set_icon_state(2);
        return;
    }

    _snwprintf(cmd, 1024, L"\"%s\" %s", g_fwknop_exe, args);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        show_notify(L"错误", L"无法启动 fwknop.exe", NIIF_ERROR);
        set_icon_state(2);
    }
}

/* ---------------------------------------------------------------- */
/* 后台线程：调用 fwknop -n <profile> -R 真实发送 SPA 包            */
/* 无窗口、捕获 stdout/stderr、回传退出码与输出给主线程             */
/* ---------------------------------------------------------------- */
static unsigned __stdcall
knock_thread(void *arg)
{
    KnockArg *ka = (KnockArg *)arg;
    wchar_t cmd[1024];
    char out[OUT_BUFSZ * 2];
    SECURITY_ATTRIBUTES sa;
    HANDLE rp = NULL, wp = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    char buf[1024];
    int total = 0;
    DWORD nread = 0;
    DWORD code = 0xFFFFFFFF;
    DWORD created_err = 0;

    _snwprintf(cmd, 1024, L"\"%s\" -n \"%s\" -R", g_fwknop_exe, ka->profile);
    free(ka);

    out[0] = '\0';

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rp, &wp, &sa, 0))
    {
        PostMessage(g_hwnd, WM_KNOCK_DONE, 0xFFFFFFFF, (LPARAM)1);
        return 1;
    }
    SetHandleInformation(rp, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = wp;
    si.hStdError  = wp;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.wShowWindow = SW_HIDE;
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        created_err = GetLastError();
        CloseHandle(rp);
        CloseHandle(wp);
        PostMessage(g_hwnd, WM_KNOCK_DONE, 0xFFFFFFFF, (LPARAM)created_err);
        return 1;
    }
    CloseHandle(wp);   /* 关闭本进程的写端，子进程结束后 ReadFile 才会返回 0 */

    /* 循环读取输出直到子进程关闭管道 */
    while (ReadFile(rp, buf, sizeof(buf) - 1, &nread, NULL) && nread > 0)
    {
        if (total + (int)nread < (int)sizeof(out) - 1)
        {
            memcpy(out + total, buf, nread);
            total += (int)nread;
            out[total] = '\0';
        }
    }
    CloseHandle(rp);

    /* 最多等 30s，防止 resolve 卡死 */
    if (WaitForSingleObject(pi.hProcess, 30000) == WAIT_TIMEOUT)
        TerminateProcess(pi.hProcess, 1);

    if (!GetExitCodeProcess(pi.hProcess, &code))
        code = 0xFFFFFFFF;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* 转 wide 存全局，供主线程通知与「状态」查看 */
    MultiByteToWideChar(CP_ACP, 0, out, -1, g_last_output, OUT_BUFSZ);

    PostMessage(g_hwnd, WM_KNOCK_DONE, (WPARAM)code, (LPARAM)0);
    return 0;
}

static void
start_knock(const wchar_t *profile)
{
    uintptr_t t;

    if (g_busy)
    {
        show_notify(L"忙碌", L"上一次敲门尚未完成，请稍候", NIIF_WARNING);
        return;
    }
    if (!fwknop_exists())
    {
        show_notify(L"错误", L"未找到同目录下的 fwknop.exe，请确认便携包完整", NIIF_ERROR);
        set_icon_state(2);
        return;
    }

    g_busy = 1;
    set_icon_state(1);
    show_notify(L"敲门中", profile, NIIF_INFO);

    {
        KnockArg *ka = (KnockArg *)malloc(sizeof(KnockArg));
        if (ka == NULL)
        {
            g_busy = 0;
            set_icon_state(2);
            show_notify(L"错误", L"内存不足", NIIF_ERROR);
            return;
        }
        wcsncpy(ka->profile, profile, PROFILE_NAME_LEN - 1);
        ka->profile[PROFILE_NAME_LEN - 1] = 0;
        t = _beginthreadex(NULL, 0, knock_thread, ka, 0, NULL);
        if (t == 0)
        {
            free(ka);
            g_busy = 0;
            set_icon_state(2);
            show_notify(L"错误", L"无法创建敲门线程", NIIF_ERROR);
            return;
        }
        CloseHandle((HANDLE)t);
    }
}

/* ---------------------------------------------------------------- */
/* 右键菜单                                                         */
/* ---------------------------------------------------------------- */
static void
show_menu(void)
{
    HMENU m = CreatePopupMenu();
    int i;
    POINT pt;

    if (g_profile_count == 0)
    {
        AppendMenuW(m, MF_STRING | MF_GRAYED, 0, L"(无 profile — 先运行 Setup)");
    }
    else
    {
        for (i = 0; i < g_profile_count; i++)
        {
            UINT f = MF_STRING | (g_busy ? MF_GRAYED : 0);
            AppendMenuW(m, f, IDM_PROFILE_BASE + i, g_profiles[i]);
        }
    }
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_SETUP,   L"Setup (配置向导)…");
    AppendMenuW(m, MF_STRING, IDM_LINT,    L"Lint (检查配置)");
    AppendMenuW(m, MF_STRING, IDM_OPENRC,  L"编辑 .fwknoprc");
    AppendMenuW(m, MF_STRING, IDM_RELOAD,  L"重新加载 profile");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_STATUS,  L"状态…");
    AppendMenuW(m, MF_STRING, IDM_ABOUT,   L"关于");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING, IDM_EXIT,    L"退出");

    /* 前台化，避免菜单不自动消失的已知问题 */
    SetForegroundWindow(g_hwnd);
    GetCursorPos(&pt);
    TrackPopupMenu(m, TPM_RIGHTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g_hwnd, NULL);
    PostMessage(g_hwnd, WM_NULL, 0, 0);
    DestroyMenu(m);
}

/* 弹出最近一次敲门输出 */
static void
show_status_dialog(void)
{
    wchar_t text[OUT_BUFSZ + 256];

    if (g_last_output[0] == 0 && g_last_status[0] == 0)
    {
        MessageBoxW(g_hwnd,
                    L"尚无敲门记录。\n右键托盘图标选择一个 profile 开始敲门。",
                    L"fwknop 状态", MB_OK | MB_ICONINFORMATION);
        return;
    }

    _snwprintf(text, sizeof(text) / sizeof(wchar_t),
               L"最近状态：\n%s\n\n最近一次敲门输出：\n%.3500s",
               (g_last_status[0] ? g_last_status : L"(无)"),
               (g_last_output[0] ? g_last_output : L"(无输出)"));

    MessageBoxW(g_hwnd, text, L"fwknop 状态",
                MB_OK | MB_ICONINFORMATION);
}

/* ---------------------------------------------------------------- */
/* 窗口过程                                                         */
/* ---------------------------------------------------------------- */
static LRESULT CALLBACK
WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == g_taskbar_created && g_taskbar_created != 0)
    {
        /* explorer 重启，重建托盘图标 */
        Shell_NotifyIconW(NIM_ADD, &g_nid);
        return 0;
    }

    switch (msg)
    {
    case WM_TRAYICON:
        switch (lp)
        {
        case WM_RBUTTONUP:
        case WM_LBUTTONUP:
        case WM_LBUTTONDBLCLK:
            show_menu();
            break;
        default:
            break;
        }
        return 0;

    case WM_KNOCK_DONE:
    {
        DWORD code = (DWORD)wp;
        LPARAM cerr = lp;
        g_busy = 0;
        if (code == 0xFFFFFFFF)
        {
            set_icon_state(2);
            if (cerr == 1)
                show_notify(L"敲门失败", L"管道创建失败", NIIF_ERROR);
            else if (cerr != 0)
            {
                wchar_t m[256];
                _snwprintf(m, 256, L"无法启动 fwknop.exe (错误 %lu)", (unsigned long)cerr);
                show_notify(L"敲门失败", m, NIIF_ERROR);
            }
            else
                show_notify(L"敲门失败", L"未知错误", NIIF_ERROR);
        }
        else if (code == 0)
        {
            set_icon_state(0);
            show_notify(L"敲门完成", L"SPA 包已发送，端口已开放（见状态查看详情）",
                         NIIF_INFO);
        }
        else
        {
            set_icon_state(2);
            show_notify(L"敲门失败", L"fwknop 返回错误，请查看状态中的输出",
                         NIIF_ERROR);
        }
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wp))
        {
        case IDM_EXIT:
            DestroyWindow(hwnd);
            return 0;
        case IDM_SETUP:
            run_console(L"setup");
            return 0;
        case IDM_LINT:
            run_console(L"lint");
            return 0;
        case IDM_RELOAD:
            reload_profiles();
            show_notify(L"已重新加载",
                        g_profile_count ? L"profile 列表已刷新" : L"仍无 profile",
                        NIIF_INFO);
            return 0;
        case IDM_OPENRC:
        {
            wchar_t c[1024];
            _snwprintf(c, 1024, L"notepad.exe \"%s\"", g_rc_path);
            {
                STARTUPINFOW si; PROCESS_INFORMATION pi;
                memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
                memset(&pi, 0, sizeof(pi));
                if (CreateProcessW(NULL, c, NULL, NULL, FALSE,
                                    0, NULL, NULL, &si, &pi))
                {
                    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                }
            }
            return 0;
        }
        case IDM_STATUS:
            show_status_dialog();
            return 0;
        case IDM_ABOUT:
            MessageBoxW(hwnd,
                L"fwknop SPA 便携版\r\n"
                L"托盘式 Windows 端口敲门客户端\r\n\r\n"
                L"基于 fwknop 单包授权（SPA）协议 v4.0.0：\r\n"
                L"  · TOTP 动态目的端口跳变\r\n"
                L"  · SPA v4 device_id 设备身份绑定\r\n\r\n"
                L"右键托盘图标选择 profile 即可敲门。\r\n"
                L"License: GPL v2 or later.",
                L"关于 fwknop-tray", MB_OK | MB_ICONINFORMATION);
            return 0;
        default:
            if (LOWORD(wp) >= IDM_PROFILE_BASE &&
                LOWORD(wp) <  IDM_PROFILE_BASE + MAX_PROFILES)
            {
                int idx = LOWORD(wp) - IDM_PROFILE_BASE;
                if (idx < g_profile_count)
                    start_knock(g_profiles[idx]);
            }
            return 0;
        }

    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        if (g_icon_idle) DestroyIcon(g_icon_idle);
        if (g_icon_busy) DestroyIcon(g_icon_busy);
        if (g_icon_err)  DestroyIcon(g_icon_err);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* ---------------------------------------------------------------- */
int WINAPI
wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow)
{
    WNDCLASSEXW wc;
    MSG msg;
    HANDLE mutex;

    (void)hPrev; (void)lpCmdLine; (void)nShow;

    /* 高 DPI 下让系统指标保持物理像素，图标清晰 */
    SetProcessDPIAware();

    /* 单实例 */
    mutex = CreateMutexW(NULL, TRUE, L"fwknop-tray-singleton");
    if (mutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS)
    {
        if (mutex) CloseHandle(mutex);
        return 0;
    }

    g_hinst = hInst;
    init_paths();
    reload_profiles();

    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = WC_TRAY;
    RegisterClassExW(&wc);

    g_taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");

    g_hwnd = CreateWindowExW(0, WC_TRAY, L"fwknop-tray", 0,
                             0, 0, 0, 0, HWND_MESSAGE, NULL, hInst, NULL);

    g_icon_idle = make_icon(RGB(46, 180, 90));
    g_icon_busy = make_icon(RGB(240, 170, 40));
    g_icon_err  = make_icon(RGB(220, 60, 60));

    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd   = g_hwnd;
    g_nid.uID    = 1;
    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon  = g_icon_idle;
    lstrcpynW(g_nid.szTip, L"fwknop SPA 便携版", sizeof(g_nid.szTip) / sizeof(wchar_t));
    Shell_NotifyIconW(NIM_ADD, &g_nid);

    show_notify(L"fwknop 已启动",
                g_profile_count
                    ? L"左键/右键托盘图标选择 profile 敲门"
                    : L"未找到 profile，请运行 Setup（右键菜单）",
                NIIF_INFO);

    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CloseHandle(mutex);
    return 0;
}

/***EOF***/
