#include <Windows.h>
#include <stdio.h>

#pragma pack(push)
#pragma pack(1)
// single interception point definition
typedef struct _HOOK_DEFINE {
    ULONG dwSize;              
    USHORT modNameSize;       
    BYTE modName[1];         
    ULONG moduleOffset;        
    USHORT nopSize;                 
    USHORT trampStartOpcodesSize;   
    BYTE trampStartOpcodes[1];      
    USHORT trampEndOpcodesSize;      
    BYTE trampEndOpcodes[1];        
    USHORT relocsCount;
    ULONG relocs[1];
}HOOK_DEFINE, *PHOOK_DEFINE;
// full config
typedef struct _param {
    ULONG entryCount;
    HOOK_DEFINE entries[1];
} param;
#pragma pack(pop)
#define MUTATE_BUFFER_MSGID             0x01
#define START_MONITORING                0x02
#define MUTATE_BUFFER_MSGID_RESPONSE    0x03
#define MUTATE_BUFFER_MSGID_RESP_MOD    0x04
#define SMEM_AREA_OPCODE_OFFSET 0x0
#define SMEM_AREA_BUFLEN_OFFSET 0x4
#define SMEM_AREA_BUFFER_OFFSET 0x8
#define TIMEOUTSECONDS 2
#define SHAREDMEMSIZE 0x20000
#define SHAREDMEMNAME "Local\\SuperMem_"
#define SHAREDMEMEVENTNAME_R "Local\\SuperMemEvent_REPLY_"
#define SHAREDMEMEVENTNAME_S "Local\\SuperMemEvent_SEND_"
VOID __fastcall genericHookFunction(
    __inout PUCHAR buffer,
    __inout SIZE_T bufferLen,
    __in ULONG hijackID);

SIZE_T currentTampId = 0;
BOOL installHook(
    __in PHOOK_DEFINE definition) {
    PVOID t1 = NULL;
    PVOID t2 = NULL;
    PVOID functionAddress = NULL;
    ULONG dwOld = 0;
    ULONG i = 0;
    PVOID modStart = NULL;
    PUCHAR sPtr = NULL;
    USHORT nopsSize = 0;
    PULONG relocsPtr;
    PUCHAR t1opcodes;
    PUCHAR t2opcodes;
    USHORT t1opcodesSize;
    USHORT t2opcodesSize;
    USHORT relocsCount;
    char buff[2048];

    // so:
    //      (fonction) -> CALL T1 -> (T1) -> CALL fct -> (fct) -> CALL T2 -> (T2) -> POP -> RET -> (function)

    // allocate areas
    t1 = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    t2 = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (t1 == NULL || t2 == NULL)
        return FALSE;


    sprintf_s(buff, 2048, "Module target: %s\n", definition->modName);
    OutputDebugStringA(buff);

    modStart = GetModuleHandleA(definition->modName);
    if (modStart == NULL)
        return FALSE;

    sPtr = (PUCHAR)definition + sizeof(ULONG) + sizeof(USHORT) + definition->modNameSize;
    functionAddress = (PVOID)((SIZE_T)GetModuleHandleA(definition->modName) + *(PULONG)sPtr);
    sprintf_s(buff, 2048, "Function address: %p\n", functionAddress);
    OutputDebugStringA(buff);

    sprintf_s(buff, 2048, "T1 address: %p\n", t1);
    OutputDebugStringA(buff);
    sprintf_s(buff, 2048, "T2 address: %p\n", t2);
    OutputDebugStringA(buff);

    sPtr += sizeof(ULONG);

    nopsSize = *(PUSHORT)sPtr;
    sPtr += sizeof(USHORT);
    sprintf_s(buff, 2048, "NOPS size: %x\n", nopsSize);
    OutputDebugStringA(buff);

    t1opcodesSize = *(PUSHORT)sPtr;
    sPtr += sizeof(USHORT);
    sprintf_s(buff, 2048, "t1opcodesSize: %x\n", t1opcodesSize);
    OutputDebugStringA(buff);


    t1opcodes = sPtr;
    sPtr += t1opcodesSize;

    t2opcodesSize = *(PUSHORT)sPtr;
    sPtr += sizeof(USHORT);
    sprintf_s(buff, 2048, "t2opcodesSize: %x\n", t2opcodesSize);
    OutputDebugStringA(buff);

    t2opcodes = sPtr;
    sPtr += t2opcodesSize;

    relocsCount = *(PUSHORT)sPtr;
    sPtr += sizeof(USHORT);
    sprintf_s(buff, 2048, "relocsCount: %x\n", relocsCount);
    OutputDebugStringA(buff);
    relocsPtr = (PULONG)sPtr;
    sPtr += relocsCount * sizeof(ULONG);


    // let's patch T1 :
    //      - pushad
    //      - pushfd
    //      - push 0xFAD0FAD0           // or mov r8, 0xFAD0FAD0FAD0FAD0  -> replaced by trampoline ID
    //      - mov ecx le buffer
    //      - mov edx la size
    //      - mov eax, 0xDEADBEEF         // or mov rax, 0xBAD0BAD0BAD0BAD0     -> replaced by genericHookFunction address
    //      - call eax
    //      - push 0xF00DF00D           // or mov rax, 0xF0D0F0D0F0D0F0D0    -> replaced by T2 address
    //      - ret
    OutputDebugStringA("Patching T1\n");
    for (i = 0; i < t1opcodesSize; i++) {
#ifdef _WIN64
        if (*(PULONGLONG)(t1opcodes + i) == 0xBAD0BAD0BAD0BAD0)
            *(PULONGLONG)(t1opcodes + i) = (ULONGLONG)genericHookFunction;
        if (*(PULONGLONG)(t1opcodes + i) == 0xF0D0F0D0F0D0F0D0)
            *(PULONGLONG)(t1opcodes + i) = (ULONGLONG)t2;
        if (*(PULONGLONG)(t1opcodes + i) == 0xFAD0FAD0FAD0FAD0)
            *(PULONGLONG)(t1opcodes + i) = (ULONGLONG)currentTampId;
#else
        if (*(PULONG)(t1opcodes + i) == 0xFAD0FAD0)
            *(PULONG)(t1opcodes + i) = (ULONG)currentTampId;
        if (*(PULONG)(t1opcodes + i) == 0xDEADBEEF)
            *(PULONG)(t1opcodes + i) = (ULONG)&genericHookFunction;
        if (*(PULONG)(t1opcodes + i) == 0xF00DF00D)
            *(PULONG)(t1opcodes + i) = (ULONG)&t2;
#endif
    }

    currentTampId++;

    OutputDebugStringA("Writing T1\n");
    memcpy(t1, t1opcodes, t1opcodesSize);


    OutputDebugStringA("Patching T2 relocs\n");
    // relative address => absolute!
#ifndef _WIN64
    for (i = 0; i < relocsCount; i++) {

        *(PULONG)((SIZE_T)t2opcodes + relocsPtr[i]) = *(PULONG)((SIZE_T)t2opcodes + relocsPtr[i]) + (ULONG)modStart;
    }
#else
    for (i = 0; i < relocsCount; i++) {
        *(PULONGLONG)((SIZE_T)t2opcodes + relocsPtr[i]) = *(PULONGLONG)((SIZE_T)t2opcodes + relocsPtr[i]) + (ULONGLONG)modStart;
    }
#endif

    OutputDebugStringA("Patching T2 return address\n");
    for (i = 0; i < t2opcodesSize; i++) {
#ifdef _WIN64
        if (*(PULONGLONG)(t2opcodes + i) == 0xF0F0F0F0F0F0F0F0)
            *(PULONGLONG)(t2opcodes + i) = (ULONGLONG)functionAddress + 13;
#else
        if (*(PULONG)(t2opcodes + i) == 0xF0F0F0F0)
            *(PULONG)(t2opcodes + i) = (ULONG)&functionAddress + 5;
#endif
    }
    OutputDebugStringA("Writing T2\n");
    // écrit le trampoline de fin
    //  il doit :
    //      - pop eax       
    //      - popfd             
    //      - popad
    //      <saved instructions>
    //      - ret
    memcpy(t2, t2opcodes, t2opcodesSize);


    OutputDebugStringA("Writing hook\n");
    // JMP <t1>
    VirtualProtect(functionAddress, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
    // did not want to suspend all the threads in order to avoid race conditions errors, so
    // first, let's write an infinite loop (~almost) atomically
    *((PWORD)functionAddress) = 0xFEEB;
    // write nops
    memset((PVOID)((SIZE_T)functionAddress + 2), 0x90, nopsSize - 2);

    // and writes the JMP bottom->start
#ifdef _WIN64
    *(PUCHAR)((SIZE_T)functionAddress + 2) = 0xB8;
    *(PULONGLONG)((SIZE_T)functionAddress + 3) = (ULONGLONG)t1;
    *(PUCHAR)((SIZE_T)functionAddress + 3 + sizeof(ULONGLONG)) = 0xFF;
    *(PUCHAR)((SIZE_T)functionAddress + 3 + sizeof(ULONGLONG) + 1) = 0xE0;
    *((PWORD)functionAddress) = 0x4850;
#else
    *(PUCHAR)((SIZE_T)functionAddress + 1 + sizeof(ULONG)) = 0xFF;
    *(PUCHAR)((SIZE_T)functionAddress + 1 + sizeof(ULONG) + 1) = 0xE0;
    // equivalent to
    //*(PUCHAR)functionAddress = 0xB8;
    //*(PULONG)((SIZE_T)functionAddress + 1) = (ULONG)t2;
    *(PUCHAR)((SIZE_T)functionAddress + 4) = (((ULONG)t1 >> 24) & 0xFF);
    *(PULONG)functionAddress = ((ULONG)t1 << 8) | 0xB8;
#endif

    OutputDebugStringA("Finished!\n");
    return TRUE;
}



PVOID sharedMemoryArea = NULL;
HANDLE hSharedMapping = NULL;
HANDLE hEventSend = NULL;
HANDLE hEventReply = NULL;
CRITICAL_SECTION sharedMemCS;
// IPC through sharedmemory
VOID sendReceiveMessage(
    __inout PUCHAR Buffer,
    __in ULONG bufferLength,
    __in ULONG messageID,
    __in ULONG hijackID) {
    DWORD retCode;

    if (sharedMemoryArea == NULL || 
        Buffer == NULL ||
        bufferLength + 1 + 4 > SHAREDMEMSIZE ||
        bufferLength == 0)
        return;
    
    // lock
    EnterCriticalSection(&sharedMemCS);

    // update the message ID
    hijackID = hijackID << 16;
    messageID |= hijackID;

    // write!
    *(PULONG)((PUCHAR)sharedMemoryArea + SMEM_AREA_OPCODE_OFFSET) = messageID;
    *(PULONG)((PUCHAR)sharedMemoryArea + SMEM_AREA_BUFLEN_OFFSET) = bufferLength;

    // copy the buffer
    // we are not sure the buffer is really OK (bugs, mem free...) => try/except
    __try {
        memcpy((PUCHAR)sharedMemoryArea + SMEM_AREA_BUFFER_OFFSET, Buffer, bufferLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        goto releaseLockAndReturn;
    }

    // set the event
    if (SetEvent(hEventSend) == 0)
        goto releaseLockAndReturn;

    // wait for the answer
    retCode = WaitForSingleObject(hEventReply, TIMEOUTSECONDS * 1000);

    if (retCode == WAIT_OBJECT_0) {

        // update?
        if (*(PULONG)((PUCHAR)sharedMemoryArea + SMEM_AREA_OPCODE_OFFSET) == MUTATE_BUFFER_MSGID_RESP_MOD) {

            // update!
            __try {
                memcpy(Buffer, (PUCHAR)sharedMemoryArea + SMEM_AREA_BUFFER_OFFSET, bufferLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                goto releaseLockAndReturn;
            }
        }
    }

    releaseLockAndReturn:
    LeaveCriticalSection(&sharedMemCS);
    return;
}

// hooks land here :)
VOID __fastcall genericHookFunction(
    __inout PUCHAR buffer,
    __inout SIZE_T bufferLen,
    __in ULONG hijackID) {

    if (sharedMemoryArea == NULL)
        return;

    sendReceiveMessage(
        buffer, 
        (ULONG)bufferLen, 
        MUTATE_BUFFER_MSGID,
        hijackID);

    return;
}

// init
BOOL initiateSharedMemory() {

    BOOL status = FALSE;
    UCHAR s_area[MAX_PATH];
    UCHAR r_event[MAX_PATH];
    UCHAR s_event[MAX_PATH];

    if (sprintf_s(s_area, MAX_PATH, "%s%x", SHAREDMEMNAME, GetCurrentProcessId()) == -1)
        return FALSE;
    if (sprintf_s(r_event, MAX_PATH, "%s%x", SHAREDMEMEVENTNAME_R, GetCurrentProcessId()) == -1)
        return FALSE;
    if (sprintf_s(s_event, MAX_PATH, "%s%x", SHAREDMEMEVENTNAME_S, GetCurrentProcessId()) == -1)
        return FALSE;

    InitializeCriticalSection(&sharedMemCS);
    hSharedMapping = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,  
        SHAREDMEMSIZE,
        s_area);
    if (hSharedMapping == NULL)
        return FALSE;

    sharedMemoryArea = MapViewOfFile(
        hSharedMapping,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        SHAREDMEMSIZE);
    if (sharedMemoryArea == NULL)
        goto end;

    hEventSend = CreateEventA(
        NULL,               // default security attributes
        FALSE,              
        FALSE,              // initial state is nonsignaled
        s_event             // object name
        );
    hEventReply = CreateEventA(
        NULL,               // default security attributes
        FALSE,              
        FALSE,              // initial state is nonsignaled
        r_event             // object name
        );

    if (hEventReply == NULL || hEventSend == NULL)
        goto end;
    status = TRUE;

end:
    if (status == FALSE) {
        if (sharedMemoryArea)
            UnmapViewOfFile(sharedMemoryArea);
        if (hSharedMapping)
            CloseHandle(hSharedMapping);
        if (hEventReply)
            CloseHandle(hEventReply);
        if (hEventSend)
            CloseHandle(hEventSend);
        hEventSend = NULL;
        hEventReply = NULL;
        hSharedMapping = NULL;
        sharedMemoryArea = NULL;
    }
    return status;
}

BOOL initialized = FALSE;
VOID cleanup() {

    if (sharedMemoryArea)
        UnmapViewOfFile(sharedMemoryArea);
    if (hSharedMapping)
        CloseHandle(hSharedMapping);
    if (hEventReply)
        CloseHandle(hEventReply);
    if (hEventSend)
        CloseHandle(hEventSend);
    hEventSend = NULL;
    hEventReply = NULL;
    hSharedMapping = NULL;
    sharedMemoryArea = NULL;
    initialized = FALSE;
}

DWORD WINAPI init(_In_ LPVOID lpParameter) {
    UNREFERENCED_PARAMETER(lpParameter);
    PHOOK_DEFINE ptr = NULL, ptrEnd = NULL;

    if (initialized)
        return FALSE;

    if (initiateSharedMemory() == FALSE)
        return FALSE;
    initialized = TRUE;

    // waits for the first message
    WaitForSingleObject(hEventReply, INFINITE);

    // install the hooks
    if (*(PULONG)((PUCHAR)sharedMemoryArea + SMEM_AREA_OPCODE_OFFSET) == START_MONITORING) {

        // loop
        ptrEnd = (PHOOK_DEFINE)(((PUCHAR)sharedMemoryArea + SMEM_AREA_BUFFER_OFFSET) + *(PULONG)((PUCHAR)sharedMemoryArea + SMEM_AREA_BUFLEN_OFFSET));
        ptr = (PHOOK_DEFINE)((PUCHAR)sharedMemoryArea + SMEM_AREA_BUFFER_OFFSET);
        do {
            installHook(ptr);
            ptr = (PHOOK_DEFINE)((SIZE_T)ptr + ptr->dwSize);
        } while (ptr < ptrEnd && ptr->dwSize != 0);

    }

    return 0;
}

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
    ) {

    if (fdwReason == DLL_PROCESS_ATTACH || fdwReason == DLL_THREAD_ATTACH) {
        if (!initialized)
            CreateThread(NULL, 0, init, NULL, 0, NULL);
    }
    return TRUE;
}