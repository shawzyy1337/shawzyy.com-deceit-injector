#include <windows.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable: 4996)
#pragma comment(lib, "urlmon.lib")

const std::string URL_LIST_URL = "https://server.shawzyy.com/download/deceit.txt";
const std::string HWID_LIST_URL = "https://server.shawzyy.com/download/hwids.txt";
const std::string LOCAL_HWID_LIST_PATH = "hwids.txt";
const std::string LOCAL_URL_PATH = "download_url.txt";

std::vector<std::string> ALLOWED_HWIDs;

void clearDirectory(const std::string& path) {
    std::string command = "del /q /f \"" + path + "\\*\"";
    system(command.c_str());
    command = "for /d %d in (" + path + "\\*) do @rd /s /q \"%d\"";
    system(command.c_str());
}

std::string GetCacheBustedURL(const std::string& baseURL) {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << baseURL << "?t=" << now_c;
    return ss.str();
}

bool DownloadFile(const std::string& url, const std::string& savePath) {
    std::string cacheBustedURL = GetCacheBustedURL(url);
    HRESULT hr = URLDownloadToFileA(nullptr, cacheBustedURL.c_str(), savePath.c_str(), 0, nullptr);
    if (SUCCEEDED(hr)) {
        SetFileAttributesA(savePath.c_str(), FILE_ATTRIBUTE_HIDDEN);
        return true;
    }
    return false;
}


bool DeleteFileIfExists(const std::string& filePath) {
    if (DeleteFileA(filePath.c_str())) {
        return true;
    }
    return GetLastError() == ERROR_FILE_NOT_FOUND;
}

std::string TrimWhitespace(const std::string& str) {
    const auto start = str.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos)
        return "";

    const auto end = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(start, end - start + 1);
}

std::vector<std::string> LoadAllowedHWIDs(const std::string& filePath) {
    std::vector<std::string> hwids;
    std::ifstream file(filePath);

    if (!file.is_open()) {
        return hwids;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            std::string trimmedLine = TrimWhitespace(line);
            hwids.push_back(trimmedLine);
        }
    }

    file.close();
    return hwids;
}

#include <intrin.h>

std::string GetVolumeSerialNumber() {
    DWORD serialNumber = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serialNumber, NULL, NULL, NULL, 0);
    std::stringstream ss;
    ss << std::hex << serialNumber;
    return ss.str();
}

std::string GetCPUID() {
    int CPUInfo[4] = { -1 };
    __cpuid(CPUInfo, 0);
    std::stringstream ss;
    for (int i = 0; i < 4; ++i) {
        ss << std::hex << CPUInfo[i];
    }
    return ss.str();
}

std::string GetBIOSUUID() {
    char biosUUID[256] = { 0 };
    DWORD bufferSize = sizeof(biosUUID);
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "SystemProductUUID", NULL, NULL, (LPBYTE)&biosUUID, &bufferSize);
        RegCloseKey(hKey);
    }
    return std::string(biosUUID);
}

std::string GetHWID() {
    std::stringstream hwid;

    hwid << GetCPUID();
    hwid << GetVolumeSerialNumber();
    hwid << GetBIOSUUID();

    return hwid.str();
}

bool IsHWIDAllowed(const std::vector<std::string>& allowedHWIDs) {
    std::string currentHWID = GetHWID();

    for (const std::string& allowedHWID : allowedHWIDs) {
        if (currentHWID == allowedHWID) {
            return true;
        }
    }
    return false;
}

bool CopyTextToClipboard(const std::string& text) {
    if (!OpenClipboard(nullptr)) {
        return false;
    }

    EmptyClipboard();

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hMem) {
        CloseClipboard();
        return false;
    }

    memcpy(GlobalLock(hMem), text.c_str(), text.size() + 1);
    GlobalUnlock(hMem);

    if (!SetClipboardData(CF_TEXT, hMem)) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }

    CloseClipboard();
    return true;
}

bool FetchDLLURL(std::string& dllURL) {
    DeleteFileIfExists(LOCAL_URL_PATH);

    if (!DownloadFile(URL_LIST_URL, LOCAL_URL_PATH)) {
        std::cerr << "Failed to download URL list!" << std::endl;
        return false;
    }

    std::ifstream file(LOCAL_URL_PATH);
    if (!file.is_open()) {
        std::cerr << "Failed to open URL list file." << std::endl;
        return false;
    }

    std::getline(file, dllURL);
    dllURL = TrimWhitespace(dllURL);

    if (dllURL.empty()) {
        std::cerr << "URL list file is empty or URL is invalid." << std::endl;
        return false;
    }

    return true;
}

bool DownloadDLL(const std::string& dllURL, const std::string& savePath) {
    return DownloadFile(dllURL, savePath);
}

DWORD GetProcessIDByName(const std::wstring& processName) {
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    DWORD processID = 0;
    if (Process32FirstW(hProcessSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                processID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return processID;
}

bool InjectDLL(DWORD processID, const std::string& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == nullptr) {
        std::stringstream errorMsg;
        errorMsg << "Failed to open target process. Error: " << GetLastError();
        MessageBoxA(nullptr, errorMsg.str().c_str(), "Error", MB_OK | MB_ICONERROR);
        return false;
    }

    LPVOID allocMem = VirtualAllocEx(hProcess, nullptr, dllPath.length() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (allocMem == nullptr) {
        std::stringstream errorMsg;
        errorMsg << "Failed to allocate memory in target process. Error: " << GetLastError();
        MessageBoxA(nullptr, errorMsg.str().c_str(), "Error", MB_OK | MB_ICONERROR);
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, allocMem, dllPath.c_str(), dllPath.length() + 1, nullptr)) {
        std::stringstream errorMsg;
        errorMsg << "Failed to write memory in target process. Error: " << GetLastError();
        MessageBoxA(nullptr, errorMsg.str().c_str(), "Error", MB_OK | MB_ICONERROR);
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("Kernel32");
    if (hKernel32 == nullptr) {
        std::stringstream errorMsg;
        errorMsg << "Failed to get handle to Kernel32. Error: " << GetLastError();
        MessageBoxA(nullptr, errorMsg.str().c_str(), "Error", MB_OK | MB_ICONERROR);
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    if (loadLibraryAddr == nullptr) {
        std::stringstream errorMsg;
        errorMsg << "Failed to get address of LoadLibraryA. Error: " << GetLastError();
        MessageBoxA(nullptr, errorMsg.str().c_str(), "Error", MB_OK | MB_ICONERROR);
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocMem, 0, nullptr);
    if (hThread == nullptr) {
        std::stringstream errorMsg;
        errorMsg << "Failed to create remote thread. Error: " << GetLastError();
        MessageBoxA(nullptr, errorMsg.str().c_str(), "Error", MB_OK | MB_ICONERROR);
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}


void CleanUpFiles() {
    DeleteFileIfExists(LOCAL_HWID_LIST_PATH);
    DeleteFileIfExists(LOCAL_URL_PATH);
}
std::string generateUniqueDLLName() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y%m%d_%H%M%S");

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    int random_number = dis(gen);

    ss << "_" << random_number << ".dll";
    return ss.str();
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HWND hButtonInject;

    switch (uMsg) {
    case WM_CREATE:
        hButtonInject = CreateWindowA("BUTTON", "INJECT", WS_CHILD | WS_VISIBLE | WS_BORDER | BS_CENTER | BS_VCENTER,
            10, 10, 200, 50, hwnd, (HMENU)1, nullptr, nullptr);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            std::string currentHWID = GetHWID();

            if (!IsHWIDAllowed(ALLOWED_HWIDs)) {
                if (CopyTextToClipboard(currentHWID)) {
                    MessageBoxA(hwnd, "HWID not allowed! HWID has been copied to clipboard.", "Error", MB_OK | MB_ICONERROR);
                }
                else {
                    MessageBoxA(hwnd, "HWID not allowed! Failed to copy HWID to clipboard.", "Error", MB_OK | MB_ICONERROR);
                }
                break;
            }

            std::string dllURL;
            if (!FetchDLLURL(dllURL)) {
                MessageBoxA(hwnd, "Failed to fetch DLL URL!", "Error", MB_OK | MB_ICONERROR);
                break;
            }

            char tempPath[MAX_PATH];
            GetTempPathA(sizeof(tempPath), tempPath);
            std::string uniqueDLLName = generateUniqueDLLName();
            std::string dllPath = std::string(tempPath) + uniqueDLLName;

            if (DownloadDLL(dllURL, dllPath)) {
                DWORD processID = GetProcessIDByName(L"Deceit.exe");
                if (processID == 0) {
                    MessageBoxA(hwnd, "Deceit.exe process not found!", "Error", MB_OK | MB_ICONERROR);
                }
                else if (InjectDLL(processID, dllPath)) {
                    MessageBoxA(hwnd, "DLL successfully injected into Deceit.exe!", "Success", MB_OK | MB_ICONINFORMATION);
                }
                else {
                    MessageBoxA(hwnd, "DLL injection failed!", "Error", MB_OK | MB_ICONERROR);
                }
            }
            else {
                MessageBoxA(hwnd, "Failed to download DLL!", "Error", MB_OK | MB_ICONERROR);
            }
            CleanUpFiles();
        }
        break;

    case WM_DESTROY:
        CleanUpFiles();
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char CLASS_NAME[] = "DllInjectorWindowClass";

   /* const char* tempPath = std::getenv("TEMP");
    if (tempPath) {
        clearDirectory(tempPath);
    }
    const char* systemRoot = std::getenv("SystemRoot");
    if (systemRoot) {
        clearDirectory(std::string(systemRoot) + "\\Temp");
    }*/

    CleanUpFiles();

    if (!DownloadFile(HWID_LIST_URL, LOCAL_HWID_LIST_PATH)) {
        MessageBoxA(nullptr, "Failed to download HWID list!", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    ALLOWED_HWIDs = LoadAllowedHWIDs(LOCAL_HWID_LIST_PATH);

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(
        0,
        CLASS_NAME,
        "DLL Injector for Deceit",
        WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 230, 110,
        nullptr, nullptr, hInstance, nullptr
    );

    if (hwnd == nullptr) {
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessageA(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return 0;
}