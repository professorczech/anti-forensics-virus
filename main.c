#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <time.h>
#ifdef _M_X64
#include <intrin.h>
#endif

// Function prototypes
void anti_disassembly();
void opaque_predicate_demo();
void anti_debugging();
void hardware_debug_check();
void runtime_decompression_demo();
void self_modifying_code();
void process_injection_demo();
void dll_injection_demo();
void obfuscation_demo();
void anti_forensic_demo();
void anti_vm_detection_demo();
void anti_analysis_delay_demo();
BOOL advanced_peb_debugger_check();

#ifdef _M_X64
// Minimal PEB structure for demonstration on x64.
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    // Other members omitted.
} PEB, *PPEB;

// NtCurrentPeb implementation for x64 using __readgsqword.
PPEB NTAPI NtCurrentPeb(void) {
    return (PPEB)__readgsqword(0x60);
}
#endif

// XOR key for obfuscation demonstration.
#define XOR_KEY 0xAA

//-----------------------------------------------------------------
// main()
// Calls all demonstration functions sequentially.
//-----------------------------------------------------------------
int main() {
    // Seed random for delay demo.
    srand((unsigned int)time(NULL));

    printf("Starting benign program simulation...\n");

    anti_disassembly();
    opaque_predicate_demo();
    anti_debugging();
    hardware_debug_check();
    runtime_decompression_demo();
    self_modifying_code();
    process_injection_demo();
    dll_injection_demo();
    obfuscation_demo();
    anti_forensic_demo();
    anti_vm_detection_demo();
    anti_analysis_delay_demo();

    printf("Program completed successfully.\n");
    return 0;
}

//-----------------------------------------------------------------
// anti_disassembly()
// Demonstrates misaligned disassembly by embedding data that may confuse linear disassemblers.
//-----------------------------------------------------------------
void anti_disassembly() {
    printf("Executing anti-disassembly technique...\n");
#ifdef _M_IX86
    __asm {
        jmp skip_data      // Jump over the data section.
        data_section:
            db 0x90, 0x90, 0x90, 0x90  // Four NOP bytes treated as data.
        skip_data:
            call data_section         // Call the data section address.
    }
#else
    printf("Inline assembly for anti-disassembly is not supported on x64. Skipping demonstration.\n");
#endif
    printf("Anti-disassembly technique executed.\n");
}

//-----------------------------------------------------------------
// opaque_predicate_demo()
// Demonstrates an opaque predicate that always evaluates to true but appears complex.
//-----------------------------------------------------------------
void opaque_predicate_demo() {
    printf("Executing opaque predicate demonstration...\n");
    int x = 10;
    // The expression below always evaluates to true, yet appears nontrivial.
    if (((x * x + x) ^ 0x1) % 2 == 0) {
        printf("Opaque predicate evaluated to true: printing 'Hello, World!'\n");
    } else {
        printf("Opaque predicate evaluated to false: this should never happen.\n");
    }
    printf("Opaque predicate demonstration executed.\n");
}

//-----------------------------------------------------------------
// anti_debugging()
// Uses API calls and PEB inspection to detect if a debugger is present.
//-----------------------------------------------------------------
void anti_debugging() {
    printf("Executing anti-debugging technique...\n");
    if (IsDebuggerPresent()) {
        printf("Debugger detected via IsDebuggerPresent()! Exiting program.\n");
        exit(1);
    }
    BOOL debuggerFlag = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerFlag);
    if (debuggerFlag) {
        printf("Debugger detected via CheckRemoteDebuggerPresent()! Exiting program.\n");
        exit(1);
    }
    if (advanced_peb_debugger_check()) {
        printf("Debugger detected via PEB check! Exiting program.\n");
        exit(1);
    }
    printf("No debugger detected. Anti-debugging technique executed.\n");
}

//-----------------------------------------------------------------
// hardware_debug_check()
// Demonstrates hardware-based debug checks by setting the Trap Flag on x86.
//-----------------------------------------------------------------
void hardware_debug_check() {
    printf("Executing hardware-based debug check...\n");
#ifdef _M_IX86
    __asm {
        pushfd            // Push EFLAGS.
        pop eax           // Pop into EAX.
        or eax, 0x100     // Set Trap Flag.
        push eax          // Push modified EAX.
        popfd             // Update EFLAGS.
        nop               // NOP to trigger single-step if debugging.
    }
    printf("Hardware-based debug check executed (x86 inline assembly).\n");
#elif defined(_M_X64)
    printf("Hardware-based debug check via inline assembly is not supported on x64. Skipping demonstration.\n");
#else
    printf("Unsupported architecture for hardware-based debug check.\n");
#endif
}

//-----------------------------------------------------------------
// decompress_payload()
// Simulated decompression: copies a fixed payload into the output buffer.
//-----------------------------------------------------------------
void decompress_payload(unsigned char *output, size_t out_size) {
    const char *payload = "Decompressed Payload Executed!";
    size_t len = strlen(payload) + 1;
    if (len > out_size) len = out_size;
    memcpy(output, payload, len);
}

//-----------------------------------------------------------------
// runtime_decompression_demo()
// Demonstrates runtime decompression by allocating memory, decompressing a payload, and printing it.
//-----------------------------------------------------------------
void runtime_decompression_demo() {
    printf("Executing runtime decompression demonstration...\n");
    size_t decompressed_size = 128;
    unsigned char *decompressed_code = (unsigned char *)VirtualAlloc(NULL, decompressed_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!decompressed_code) {
        printf("Memory allocation for decompression failed.\n");
        return;
    }
    decompress_payload(decompressed_code, decompressed_size);
    printf("%s\n", (char *)decompressed_code);
    VirtualFree(decompressed_code, 0, MEM_RELEASE);
    printf("Runtime decompression demonstration executed.\n");
}

//-----------------------------------------------------------------
// self_modifying_code()
// Demonstrates self-modifying code by allocating memory, executing a routine, modifying it, and re-executing.
//-----------------------------------------------------------------
void self_modifying_code() {
    printf("Executing self-modifying code technique...\n");
    unsigned char *code = (unsigned char *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!code) {
        printf("Memory allocation failed.\n");
        exit(1);
    }
    unsigned char original_code[] = {
        0x6A, 0x00,                   // push 0 (MB_OK)
        0x68, 0, 0, 0, 0,             // push offset for "Hello, World!"
        0x68, 0, 0, 0, 0,             // push offset for "Message"
        0x6A, 0x00,                   // push 0 (NULL hWnd)
        0xE8, 0, 0, 0, 0,             // call MessageBoxA (relative offset)
        0xC3                          // ret
    };
    char *hello_world = "Hello, World!";
    char *message = "Message";
    *(char **)(original_code + 3) = hello_world;
    *(char **)(original_code + 8) = message;
#ifdef _WIN64
    DWORD_PTR callOffset = (DWORD_PTR)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA") - ((DWORD_PTR)code + 14);
#else
    DWORD callOffset = (DWORD)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA") - ((DWORD)code + 14);
#endif
    *(DWORD_PTR *)(original_code + 11) = callOffset;
    memcpy(code, original_code, sizeof(original_code));
    ((void(*)())code)();  // Display "Hello, World!"
    char *goodbye = "Goodbye!";
    *(char **)(code + 3) = goodbye;
    ((void(*)())code)();  // Now displays "Goodbye!"
    VirtualFree(code, 0, MEM_RELEASE);
    printf("Self-modifying code technique executed.\n");
}

//-----------------------------------------------------------------
// process_injection_demo()
// Demonstrates process injection by launching Notepad, injecting a payload, and creating a remote thread.
//-----------------------------------------------------------------
void process_injection_demo() {
    printf("Executing process injection demonstration...\n");
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcess(NULL, "notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to create process for injection.\n");
        return;
    }
    Sleep(1000);
    char payload[] =
        "\x6A\x00"                       // push 0 (MB_OK)
        "\x68\x00\x00\x00\x00"             // push offset for text (to be set)
        "\x68\x00\x00\x00\x00"             // push offset for caption (to be set)
        "\x6A\x00"                       // push 0 (hWnd)
        "\xE8\x00\x00\x00\x00"             // call MessageBoxA (relative, to be set)
        "\xC3";                          // ret
    char *text = "Injected Payload!";
    char *caption = "Process Injection";
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (!hProcess) {
        printf("Failed to open target process.\n");
        TerminateProcess(pi.hProcess, 0);
        return;
    }
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, sizeof(payload) + 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        printf("Failed to allocate memory in remote process.\n");
        TerminateProcess(pi.hProcess, 0);
        return;
    }
    unsigned char localPayload[sizeof(payload)];
    memcpy(localPayload, payload, sizeof(payload));
    *(DWORD_PTR *)(localPayload + 2) = (DWORD_PTR)remoteMemory + sizeof(payload);  // text address
    *(DWORD_PTR *)(localPayload + 7) = (DWORD_PTR)remoteMemory + sizeof(payload) + strlen(text) + 1; // caption address
    FARPROC msgBoxAddr = GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
    *(DWORD_PTR *)(localPayload + 12) = (DWORD_PTR)msgBoxAddr - ((DWORD_PTR)remoteMemory + 17);
    if (!WriteProcessMemory(hProcess, remoteMemory, localPayload, sizeof(localPayload), NULL)) {
        printf("Failed to write payload to remote process.\n");
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        return;
    }
    LPVOID remoteTextAddr = (LPVOID)((DWORD_PTR)remoteMemory + sizeof(localPayload));
    WriteProcessMemory(hProcess, remoteTextAddr, text, strlen(text) + 1, NULL);
    LPVOID remoteCaptionAddr = (LPVOID)((DWORD_PTR)remoteTextAddr + strlen(text) + 1);
    WriteProcessMemory(hProcess, remoteCaptionAddr, caption, strlen(caption) + 1, NULL);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (!hThread) {
        printf("Failed to create remote thread.\n");
    } else {
        printf("Remote thread created successfully. Payload executed in target process.\n");
        CloseHandle(hThread);
    }
    CloseHandle(hProcess);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("Process injection demonstration executed.\n");
}

//-----------------------------------------------------------------
// dll_injection_demo()
// Demonstrates DLL injection by writing a DLL path into a remote process and calling LoadLibraryA.
//-----------------------------------------------------------------
void dll_injection_demo() {
    printf("Executing DLL injection demonstration...\n");
    const char *dllPath = "C:\\Temp\\BenignDemo.dll";  // Ensure this DLL exists.
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcess(NULL, "notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("Failed to create process for DLL injection.\n");
        return;
    }
    Sleep(1000);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (!hProcess) {
        printf("Failed to open target process.\n");
        TerminateProcess(pi.hProcess, 0);
        return;
    }
    size_t dllPathLen = strlen(dllPath) + 1;
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMemory) {
        printf("Failed to allocate memory in remote process for DLL path.\n");
        TerminateProcess(pi.hProcess, 0);
        return;
    }
    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, dllPathLen, NULL)) {
        printf("Failed to write DLL path to remote process.\n");
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        return;
    }
    FARPROC loadLibAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, remoteMemory, 0, NULL);
    if (!hThread) {
        printf("Failed to create remote thread for DLL injection.\n");
    } else {
        printf("DLL injection successful: BenignDemo.dll loaded in target process.\n");
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("DLL injection demonstration executed.\n");
}

//-----------------------------------------------------------------
// obfuscation_demo()
// Demonstrates simple XOR obfuscation of a sensitive string.
//-----------------------------------------------------------------
void obfuscation_demo() {
    printf("Executing obfuscation demonstration...\n");
    const char *original = "Sensitive Data: Do Not Analyze!";
    size_t len = strlen(original) + 1;
    char *encrypted = (char *)malloc(len);
    char *decrypted = (char *)malloc(len);
    if (!encrypted || !decrypted) {
        printf("Memory allocation failed for obfuscation demo.\n");
        return;
    }
    for (size_t i = 0; i < len; i++) {
        encrypted[i] = original[i] ^ XOR_KEY;
    }
    printf("Encrypted string: ");
    for (size_t i = 0; i < len - 1; i++) {
        printf("%02X ", (unsigned char)encrypted[i]);
    }
    printf("\n");
    for (size_t i = 0; i < len; i++) {
        decrypted[i] = encrypted[i] ^ XOR_KEY;
    }
    printf("Decrypted string: %s\n", decrypted);
    free(encrypted);
    free(decrypted);
    printf("Obfuscation demonstration executed.\n");
}

//-----------------------------------------------------------------
// anti_forensic_demo()
// Simulates anti-forensic techniques like log cleanup and artifact removal.
//-----------------------------------------------------------------
void anti_forensic_demo() {
    printf("Executing anti-forensic demonstration...\n");
    printf("Deleting temporary files...\n");
    printf("Clearing event logs...\n");
    printf("Erasing forensic artifacts from memory...\n");
    printf("Anti-forensic demonstration executed.\n");
}

//-----------------------------------------------------------------
// anti_vm_detection_demo()
// Uses CPUID to detect if the program is running under a hypervisor (VM).
//-----------------------------------------------------------------
void anti_vm_detection_demo() {
    printf("Executing anti-VM detection demonstration...\n");
#ifdef _MSC_VER
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    // Bit 31 of ECX indicates hypervisor presence.
    if (cpuInfo[2] & (1 << 31)) {
        printf("Virtual machine detected (hypervisor present).\n");
    } else {
        printf("No virtual machine detected.\n");
    }
#else
    printf("CPUID instruction not supported on this compiler.\n");
#endif
    printf("Anti-VM detection demonstration executed.\n");
}

//-----------------------------------------------------------------
// anti_analysis_delay_demo()
// Introduces a random delay if a debugger is detected to hinder analysis.
//-----------------------------------------------------------------
void anti_analysis_delay_demo() {
    printf("Executing anti-analysis delay demonstration...\n");
    if (IsDebuggerPresent()) {
        // Introduce a random delay between 1 and 5 seconds.
        int delay = (rand() % 5000) + 1000;
        printf("Debugger detected, delaying execution for %d milliseconds.\n", delay);
        Sleep(delay);
    } else {
        printf("No debugger detected; no delay introduced.\n");
    }
    printf("Anti-analysis delay demonstration executed.\n");
}

//-----------------------------------------------------------------
// advanced_peb_debugger_check()
// Reads the BeingDebugged flag from the PEB using inline assembly (x86) or NtCurrentPeb (x64).
//-----------------------------------------------------------------
BOOL advanced_peb_debugger_check() {
#ifdef _M_IX86
    BOOL beingDebugged = FALSE;
    __asm {
        mov eax, fs:[30h]
        mov al, byte ptr [eax+2]
        mov beingDebugged, al
    }
    return beingDebugged;
#elif defined(_M_X64)
    PPEB peb = NtCurrentPeb();
    return peb->BeingDebugged;
#else
    return FALSE;
#endif
}
