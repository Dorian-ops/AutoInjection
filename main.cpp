#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <string>

DWORD getProcessID(const wchar_t *processName) {
    DWORD processes[1024], cbNeeded, processCount;

    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        return 0; // Ошибка, не удалось перечислить процессы
    }

    processCount = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < processCount; i++) {
        DWORD pid = processes[i];
        if (pid == 0) continue;

        // Открываем процесс с правами чтения информации о процессе
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess) {
            wchar_t exeName[MAX_PATH] = {0};
            // Получаем путь к исполняемому файлу процесса
            if (GetModuleFileNameExW(hProcess, NULL, exeName, MAX_PATH)) {
                // Сравниваем только имя файла, поэтому выделим из пути имя
                const wchar_t *pBaseName = wcsrchr(exeName, L'\\');
                if (pBaseName) pBaseName++;
                else pBaseName = exeName;

                if (wcscmp(pBaseName, processName) == 0) {
                    CloseHandle(hProcess);
                    return pid; // Процесс найден
                }
            }
            CloseHandle(hProcess);
        }
    }

    return 0; // Процесс не найден
}

int main(int argc, char *argv[]) {
    wchar_t processName[256];
    char dll[256];
    std::cout << "Launching the program...\n";

    wprintf(L"Write name DLL (for example, stalcraft.exe): ");
    fgetws(processName, 256, stdin);
    // Удаляем символ новой строки, если он есть
    size_t len = wcslen(processName);
    if (len > 0 && processName[len - 1] == L'\n') {
        processName[len - 1] = L'\0';
    }

    int pID = getProcessID(processName);

    if (pID == 0) {
        printf("The process was not found.\n");
        return 1;
    } else {
        printf("A process with a PID was found: %d\n", pID);
    }

    printf("Write name DLL (for example, dorian_client.dll): ");
    fgets(dll, sizeof(dll), stdin);
    len = strlen(dll);
    if (len > 0 && dll[len - 1] == '\n') {
        dll[len - 1] = '\0';
    }

    char dllPath[MAX_PATH] = {0};
    GetFullPathName(dll, MAX_PATH, dllPath, NULL);
    printf("%s\n", dllPath);

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pID);

    if (hProcess == NULL) {
        printf("Failed to open process. Error: %lu\n", GetLastError());
        return 1;
    }

    LPVOID pszLibFileRemote = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT,
                                             PAGE_READWRITE);
    if (pszLibFileRemote == NULL) {
        printf("VirtualAllocEx failed. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    WriteProcessMemory(hProcess, pszLibFileRemote, dllPath, strlen(dllPath) + 1, NULL);
    if (!WriteProcessMemory(hProcess, pszLibFileRemote, dllPath, strlen(dllPath) + 1, NULL)) {
        printf("WriteProcessMemory failed. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE handleThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) LoadLibraryA,
                                             pszLibFileRemote, 0, NULL);
    if (handleThread == NULL) {
        printf("Failed to create a remote stream. Error: %lu\n", GetLastError());
    }
    DWORD dwExitCode = 0;
    GetExitCodeThread(handleThread, &dwExitCode);

    if (dwExitCode == 0) {
        printf("Remote LoadLibraryA failed, invalid module handle returned.\n");
        // Ваша DLL могла не загрузиться
    }

    WaitForSingleObject(handleThread, INFINITE);
    CloseHandle(handleThread);
    VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "Completion.\n";
    std::cin.get(); // ждать нажатия Enter
    return 0;
}
