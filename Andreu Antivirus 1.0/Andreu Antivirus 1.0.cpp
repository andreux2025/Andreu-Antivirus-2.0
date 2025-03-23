#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <thread>
#include <chrono>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <fstream>
#include <regex>
#include <mutex>

namespace fs = std::filesystem;

void setConsoleColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

std::string wcharToString(const WCHAR* wcharStr) {
    int size = WideCharToMultiByte(CP_UTF8, 0, wcharStr, -1, nullptr, 0, nullptr, nullptr);
    std::string str(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wcharStr, -1, &str[0], size, nullptr, nullptr);
    return str;
}

class Antivirus {
public:
    Antivirus() : stopFlag(false), realTimeProtectionThread(nullptr) {
        checkAdminPrivileges();
        threatPatterns = { "virus", "trojan", "malware", "hack", "keylogger" };
    }

    void checkAdminPrivileges() {
        BOOL isAdmin = FALSE;
        PSID adminGroup;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        if (!isAdmin) {
            setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << "[ERROR] Please run the program as Administrator.\n";
            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
            exit(1);
        }
    }

    void realTimeProtection() {
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[INFO] Real-time protection is active...\n";
        try {
            while (!stopFlag) {
                scanProcesses();
                scanSystem();
                std::this_thread::sleep_for(std::chrono::seconds(10));
            }
        }
        catch (const std::exception& e) {
            setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cerr << "[ERROR] Exception in real-time protection: " << e.what() << "\n";
            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
        }
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[INFO] Real-time protection stopped.\n";
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
    }

    void stopRealTimeProtection() {
        stopFlag = true;
    }

    void scanSystem() {
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[INFO] Scanning system for files...\n";
        setConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);

        // Recorremos las rutas comunes del sistema para detectar amenazas
        std::vector<std::string> directories = { "C:/", "C:/Program Files/", "C:/Users/", "C:/Windows/" };
        for (const auto& dir : directories) {
            scanDirectory(dir);
        }

        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[INFO] Scan complete.\n";
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
    }

    void scanDirectory(const std::string& dir) {
        try {
            for (const auto& file : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
                if (isThreat(file.path().string())) {
                    setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                    std::cout << "[ALERT] Threat detected: " << file.path() << "\n";
                    quarantineFile(file.path().string());
                }
            }
        }
        catch (const fs::filesystem_error& e) {
            setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cerr << "[ERROR] Access denied while scanning directory: " << e.what() << "\n";
            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
        }
    }

    void scanProcesses() {
        try {
            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "[INFO] Scanning running processes...\n";
            setConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);

            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            if (hProcessSnap == INVALID_HANDLE_VALUE) {
                setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::cerr << "[ERROR] Failed to create snapshot of processes\n";
                setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                return;
            }

            if (Process32First(hProcessSnap, &pe32)) {
                do {
                    std::string processName = wcharToString(pe32.szExeFile);
                    if (isThreat(processName)) {
                        setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                        std::cout << "[ALERT] Suspicious process detected: " << processName << "\n";
                        terminateProcess(pe32.th32ProcessID);
                    }
                } while (Process32Next(hProcessSnap, &pe32));
            }
            CloseHandle(hProcessSnap);

            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "[INFO] Process scan complete.\n";
            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
        }
        catch (const std::exception& e) {
            setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cerr << "[ERROR] Exception while scanning processes: " << e.what() << "\n";
            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
        }
    }

    void terminateProcess(DWORD processID) {
        try {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
            if (hProcess != NULL) {
                if (TerminateProcess(hProcess, 0)) {
                    setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::cout << "[INFO] Terminated suspicious process with ID: " << processID << "\n";
                }
                else {
                    setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                    std::cerr << "[ERROR] Failed to terminate process ID: " << processID << "\n";
                }
                CloseHandle(hProcess);
            }
        }
        catch (const std::exception& e) {
            setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cerr << "[ERROR] Exception while terminating process: " << e.what() << "\n";
            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
        }
    }

    void menu() {
        int choice;
        bool running = true;
        while (running) {
            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "\n===== Antivirus Menu =====\n";
            setConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << "1. Real-Time Protection\n";
            std::cout << "2. Scan System\n";
            std::cout << "3. View Quarantine\n";
            std::cout << "4. Exit\n";
            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
            std::cout << "Enter your choice: ";
            std::cin >> choice;

            switch (choice) {
            case 1:
                if (realTimeProtectionThread == nullptr) {
                    setConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                    std::cout << "Starting real-time protection...\n";
                    setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                    realTimeProtectionThread = new std::thread(&Antivirus::realTimeProtection, this);
                }
                break;
            case 2:
                scanSystem();
                break;
            case 3:
                viewQuarantine();
                break;
            case 4:
                stopFlag = true;
                if (realTimeProtectionThread != nullptr) {
                    realTimeProtectionThread->join();
                    delete realTimeProtectionThread;
                }
                running = false;
                break;
            default:
                setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::cout << "[ERROR] Invalid choice, try again.\n";
                setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                break;
            }
        }
    }

    void quarantineFile(const std::string& filePath) {
        setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[INFO] Quarantining file: " << filePath << "\n";
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
    }

    void viewQuarantine() {
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "[INFO] Viewing quarantined files...\n";
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
    }

    bool isThreat(const std::string& filePath) {
        for (const auto& pattern : threatPatterns) {
            if (filePath.find(pattern) != std::string::npos || std::regex_search(filePath, std::regex(pattern, std::regex_constants::icase))) {
                return true;
            }
        }
        return false;
    }

private:
    std::thread* realTimeProtectionThread;
    bool stopFlag;
    std::vector<std::string> threatPatterns;
};

int main() {
    Antivirus av;
    av.menu();
    return 0;
}
