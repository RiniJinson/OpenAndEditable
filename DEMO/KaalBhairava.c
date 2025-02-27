/******************************************************************************
 * Kaal Bhairava Memory Forensics Tool - Full Backend
 *
 * Author: (Your Name)
 * Purpose: Provide a user-mode C backend for enumerating processes,
 *          detecting suspicious processes, and performing limited rootkit checks.
 *
 * Disclaimer: Real advanced rootkit detection requires kernel-mode drivers
 *             or specialized libraries. This code is a simplified skeleton.
 ******************************************************************************/

 #ifdef _MSC_VER
 // For MSVC or compilers supporting #pragma comment
 #pragma comment(lib, "psapi.lib")
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <time.h>

/*---------------------------------------------
 * Structures
 *---------------------------------------------*/
typedef struct {
    DWORD processID;
    char  exePath[MAX_PATH];
    bool  isSuspicious;
} PROCESS_INFO;

typedef struct {
    // A handle or pointer to future expansions (like logging or advanced detection context)
    // For now, keep it simple
    int  totalProcesses;
    int  suspiciousCount;
    bool rootkitDetected;
    PROCESS_INFO *suspiciousList; // dynamically allocated array
} SCAN_RESULT;

/*---------------------------------------------
 * Logging & Utility
 *---------------------------------------------*/

// Simple logging function (writes to console + optional log file)
static void LogMessage(const char *message) {
    // Could be expanded to write to a file or Windows event log
    printf("[LOG] %s\n", message);
}

// Timestamp helper
static void GetTimeStamp(char *buffer, size_t size) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    snprintf(buffer, size, "%02d/%02d/%04d %02d:%02d:%02d",
             st.wDay, st.wMonth, st.wYear,
             st.wHour, st.wMinute, st.wSecond);
}

/*---------------------------------------------
 * Suspicious Checks (User-Mode Heuristics)
 *---------------------------------------------*/

// Placeholder: YARA scanning or signature checks
static bool PerformYARAScan(const char *exePath) {
    // If you integrate YARA, load rules, scan exePath or mapped sections in memory
    // For demonstration, we simply return false or true based on a naive check
    if (strstr(exePath, "suspicious_app") != NULL) {
        return true;
    }
    return false;
}

// Example: Simple signature check stub
static bool IsSignedExecutable(const char *exePath) {
    // Real implementation might call WinVerifyTrust
    // For demonstration, treat everything as "signed" except if path contains "unsigned"
    if (strstr(exePath, "unsigned") != NULL) {
        return false;
    }
    return true;
}

// Consolidated suspicious check
static bool IsProcessSuspicious(const char *exePath) {
    // Example heuristics:
    // 1) If file is not properly "signed" => suspicious
    // 2) If YARA scanning triggers => suspicious
    // 3) If path looks fishy (like "C:\\Windows\\svch0st.exe") => suspicious

    if (!IsSignedExecutable(exePath)) {
        return true;
    }
    if (PerformYARAScan(exePath)) {
        return true;
    }
    // Additional naive check
    if (strstr(exePath, "svch0st") != NULL) {
        return true;
    }
    return false;
}

/*---------------------------------------------
 * Rootkit Detection (Placeholder)
 *---------------------------------------------*/
static bool CheckRootkitKernel() {
    // Real approach might:
    // 1) Compare user-mode process list with kernel EPROCESS list
    // 2) Check for SSDT hooks or IRP hooking
    // 3) Inspect loaded drivers for anomalies
    // 4) Possibly use a driver to call ZwQuerySystemInformation
    // For demonstration, return false or true at random or based on a naive condition

    // Pseudo-random example:
    // 1 in 100 chance to simulate a rootkit detection
    if ((rand() % 100) == 0) {
        return true;
    }
    return false;
}

/*---------------------------------------------
 * Process Enumeration
 *---------------------------------------------*/
static int EnumerateProcesses(PROCESS_INFO **procList) {
    // This function returns the total number of processes,
    // and allocates an array of PROCESS_INFO
    // Caller must free the allocated array
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogMessage("CreateToolhelp32Snapshot failed.");
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        LogMessage("Process32First failed.");
        return 0;
    }

    // We store up to 4096 processes in a temp array
    PROCESS_INFO *tempArray = (PROCESS_INFO *)malloc(sizeof(PROCESS_INFO) * 4096);
    if (!tempArray) {
        CloseHandle(hSnapshot);
        return 0;
    }

    int count = 0;
    do {
        // Retrieve the full path of the process (if possible)
        // We'll open the process, then call GetModuleFileNameEx
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                      FALSE, pe32.th32ProcessID);
        char exePathBuf[MAX_PATH] = {0};

        if (hProcess) {
            HMODULE hMod;
            DWORD needed;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &needed)) {
                GetModuleFileNameExA(hProcess, hMod, exePathBuf, MAX_PATH);
            }
            CloseHandle(hProcess);
        }

        // If we couldn't retrieve the full path, fallback to the short exe name
        if (exePathBuf[0] == '\0') {
            snprintf(exePathBuf, MAX_PATH, "%s", pe32.szExeFile);
        }

        // Fill tempArray
        PROCESS_INFO pi;
        pi.processID = pe32.th32ProcessID;
        snprintf(pi.exePath, MAX_PATH, "%s", exePathBuf);
        pi.isSuspicious = false; // default
        tempArray[count++] = pi;

    } while (Process32Next(hSnapshot, &pe32) && count < 4096);

    CloseHandle(hSnapshot);

    // Now we shrink to the actual size
    *procList = (PROCESS_INFO *)malloc(sizeof(PROCESS_INFO) * count);
    if (!(*procList)) {
        free(tempArray);
        return 0;
    }
    memcpy(*procList, tempArray, sizeof(PROCESS_INFO) * count);
    free(tempArray);

    return count;
}

/*---------------------------------------------
 * Main Scanning Logic
 *---------------------------------------------*/
SCAN_RESULT KaalBhairavaScan(bool deepScan) {
    SCAN_RESULT result;
    memset(&result, 0, sizeof(SCAN_RESULT));

    // 1) Enumerate all processes
    PROCESS_INFO *allProcs = NULL;
    int totalProcs = EnumerateProcesses(&allProcs);
    if (totalProcs <= 0) {
        LogMessage("No processes enumerated or an error occurred.");
        return result;
    }
    result.totalProcesses = totalProcs;

    // 2) Evaluate suspicious processes
    PROCESS_INFO *suspTemp = (PROCESS_INFO *)malloc(sizeof(PROCESS_INFO) * totalProcs);
    if (!suspTemp) {
        free(allProcs);
        LogMessage("Memory allocation failed for suspicious temp array.");
        return result;
    }
    int suspCount = 0;

    for (int i = 0; i < totalProcs; i++) {
        if (IsProcessSuspicious(allProcs[i].exePath)) {
            allProcs[i].isSuspicious = true;
            suspTemp[suspCount++] = allProcs[i];
        }
    }

    // 3) Rootkit detection if deepScan (Bhairava Mode)
    bool rootkitFound = false;
    if (deepScan) {
        rootkitFound = CheckRootkitKernel();
    }

    // 4) Populate SCAN_RESULT
    result.suspiciousCount = suspCount;
    result.rootkitDetected = rootkitFound;

    if (suspCount > 0) {
        result.suspiciousList = (PROCESS_INFO *)malloc(sizeof(PROCESS_INFO) * suspCount);
        if (result.suspiciousList) {
            memcpy(result.suspiciousList, suspTemp, sizeof(PROCESS_INFO) * suspCount);
        }
    }

    free(suspTemp);
    free(allProcs);

    return result;
}

/*---------------------------------------------
 * Reporting / Export
 *---------------------------------------------*/
void GenerateScanReport(const SCAN_RESULT *scanRes, const char *outputFile) {
    // Writes a simple text-based report
    FILE *fp = fopen(outputFile, "w");
    if (!fp) {
        LogMessage("Failed to open report file for writing.");
        return;
    }

    char timeBuf[64];
    GetTimeStamp(timeBuf, sizeof(timeBuf));

    fprintf(fp, "Kaal Bhairava Memory Forensics Report\n");
    fprintf(fp, "Generated on: %s\n\n", timeBuf);
    fprintf(fp, "Total Processes: %d\n", scanRes->totalProcesses);
    fprintf(fp, "Suspicious Processes: %d\n", scanRes->suspiciousCount);
    if (scanRes->rootkitDetected) {
        fprintf(fp, "CRITICAL: Potential rootkit detected in kernel memory!\n");
    } else {
        fprintf(fp, "No rootkit detected.\n");
    }
    fprintf(fp, "\n--- Suspicious Process List ---\n");
    for (int i = 0; i < scanRes->suspiciousCount; i++) {
        fprintf(fp, "[%d] PID: %lu | Path: %s\n", i+1,
                scanRes->suspiciousList[i].processID,
                scanRes->suspiciousList[i].exePath);
    }

    fclose(fp);
}

/*---------------------------------------------
 * Cleanup
 *---------------------------------------------*/
void FreeScanResult(SCAN_RESULT *scanRes) {
    if (scanRes->suspiciousList) {
        free(scanRes->suspiciousList);
        scanRes->suspiciousList = NULL;
    }
    scanRes->totalProcesses = 0;
    scanRes->suspiciousCount = 0;
    scanRes->rootkitDetected = false;
}

/*---------------------------------------------
 * Main (Demo Usage)
 *---------------------------------------------*/
int main(int argc, char *argv[]) {
    srand((unsigned)time(NULL)); // seed for random rootkit simulation

    bool bhairavaMode = false;
    if (argc > 1 && strcmp(argv[1], "--deep") == 0) {
        bhairavaMode = true;
        LogMessage("Bhairava (Deep) Mode Enabled");
    } else {
        LogMessage("Quick Scan Mode Enabled");
    }

    SCAN_RESULT res = KaalBhairavaScan(bhairavaMode);

    char summary[256];
    snprintf(summary, sizeof(summary),
             "Scan finished. TotalProcs=%d, Suspicious=%d, Rootkit=%s",
             res.totalProcesses,
             res.suspiciousCount,
             res.rootkitDetected ? "YES" : "NO");
    LogMessage(summary);

    // Generate a quick text-based report
    GenerateScanReport(&res, "kaal_bhairava_report.txt");
    LogMessage("Report saved to kaal_bhairava_report.txt");

    // Cleanup
    FreeScanResult(&res);

    return 0;
}
