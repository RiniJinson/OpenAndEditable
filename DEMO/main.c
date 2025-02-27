#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_IE 0x0600
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")

typedef struct {
    DWORD processID;
    char exePath[MAX_PATH];
    BOOL isSuspicious;
} PROCESS_INFO;

typedef struct {
    PROCESS_INFO* suspiciousList;
    int totalProcesses;
    int suspiciousCount;
    BOOL rootkitDetected;
} SCAN_RESULT;

// Add function prototype
SCAN_RESULT KaalBhairavaScan(BOOL deepScan);
void FreeScanResult(SCAN_RESULT* result);

// New GUI-related structures and globals
typedef struct {
    HWND hMainWindow;
    HWND hListView;
    HWND hStatusBar;
    HWND hScanButton;
    HWND hDeepScanCheck;
} GUI_CONTROLS;

GUI_CONTROLS g_gui;

// Add the implementation here
void FreeScanResult(SCAN_RESULT* result) {
    if (result && result->suspiciousList) {
        free(result->suspiciousList);
        result->suspiciousList = NULL;
    }
}

// GUI creation and handling functions
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            // Create controls
            g_gui.hScanButton = CreateWindow(
                "BUTTON", "Start Scan",
                WS_VISIBLE | WS_CHILD,
                10, 10, 100, 30,
                hwnd, (HMENU)1, NULL, NULL);

            g_gui.hDeepScanCheck = CreateWindow(
                "BUTTON", "Deep Scan",
                WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
                120, 15, 100, 20,
                hwnd, (HMENU)2, NULL, NULL);

            // Create ListView
            g_gui.hListView = CreateWindow(
                WC_LISTVIEW, "",
                WS_VISIBLE | WS_CHILD | LVS_REPORT,
                10, 50, 780, 400,
                hwnd, (HMENU)3, NULL, NULL);

            // Add ListView columns
            LVCOLUMN lvc = {0};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            
            lvc.pszText = "PID";
            lvc.cx = 70;
            ListView_InsertColumn(g_gui.hListView, 0, &lvc);
            
            lvc.pszText = "Path";
            lvc.cx = 500;
            ListView_InsertColumn(g_gui.hListView, 1, &lvc);
            
            lvc.pszText = "Status";
            lvc.cx = 100;
            ListView_InsertColumn(g_gui.hListView, 2, &lvc);

            // Create status bar
            g_gui.hStatusBar = CreateWindow(
                STATUSCLASSNAME, NULL,
                WS_CHILD | WS_VISIBLE,
                0, 0, 0, 0,
                hwnd, (HMENU)4, NULL, NULL);
            
            return 0;

        case WM_COMMAND:
            if (LOWORD(wParam) == 1) { // Scan button clicked
                // Clear existing items
                ListView_DeleteAllItems(g_gui.hListView);
                
                // Get deep scan status
                BOOL deepScan = (SendMessage(g_gui.hDeepScanCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
                
                // Perform scan
                SCAN_RESULT res = KaalBhairavaScan(deepScan);
                
                // Update ListView with results
                for (int i = 0; i < res.totalProcesses; i++) {
                    LVITEM lvi = {0};
                    char pidStr[32];
                    
                    lvi.mask = LVIF_TEXT;
                    lvi.iItem = i;
                    
                    // PID column
                    snprintf(pidStr, sizeof(pidStr), "%lu", res.suspiciousList[i].processID);
                    lvi.pszText = pidStr;
                    ListView_InsertItem(g_gui.hListView, &lvi);
                    
                    // Path column
                    ListView_SetItemText(g_gui.hListView, i, 1, res.suspiciousList[i].exePath);
                    
                    // Status column
                    ListView_SetItemText(g_gui.hListView, i, 2, 
                        res.suspiciousList[i].isSuspicious ? "Suspicious" : "Normal");
                }
                
                // Update status bar
                char statusText[256];
                snprintf(statusText, sizeof(statusText),
                    "Scan complete. Total: %d, Suspicious: %d, Rootkit: %s",
                    res.totalProcesses, res.suspiciousCount,
                    res.rootkitDetected ? "DETECTED" : "None");
                SetWindowText(g_gui.hStatusBar, statusText);
                
                FreeScanResult(&res);
            }
            return 0;

        case WM_SIZE:
            // Resize status bar
            SendMessage(g_gui.hStatusBar, WM_SIZE, 0, 0);
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Remove the duplicate implementation that appears before WinMain

// Replace the existing main() with this GUI version
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX icex = {0};
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    // Register window class
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "KaalBhairavaClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    RegisterClassEx(&wc);

    // Create main window
    g_gui.hMainWindow = CreateWindowEx(
        0, "KaalBhairavaClass",
        "Kaal Bhairava Memory Forensics",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, hInstance, NULL);

    if (!g_gui.hMainWindow) {
        return 1;
    }

    ShowWindow(g_gui.hMainWindow, nCmdShow);
    UpdateWindow(g_gui.hMainWindow);

    // Message loop
    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
} 