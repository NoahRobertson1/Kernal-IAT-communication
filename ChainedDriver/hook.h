#pragma once
#include "includes.h"


class Hook
{
    PVOID g_ModuleBase = NULL;
    ULONG g_ModuleSize = NULL;
    char* g_FunctionName;

public:
    inline static __int64 (__fastcall* OrigFunc)();

    NTSTATUS setup(const char* functionName, const char* processName)
    {   
        g_FunctionName = (char*)functionName;
        NTSTATUS status;

        ULONG bytes;
        status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

        if (status != STATUS_SUCCESS)
        {
            DbgPrintEx(0, 0, "ZwQuerySystemInformation: first call failed");
            return status;
        }

        PSYSTEM_MODULE_INFORMATION pMods;
        pMods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, bytes, 'tag');
        RtlZeroMemory(pMods, bytes);

        status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);
        if (status != STATUS_SUCCESS)
        {
            DbgPrintEx(0, 0, "ZwQuerySystemInformation: second call failed");
            return status;
        }

        PSYSTEM_MODULE_ENTRY pMod = (PSYSTEM_MODULE_ENTRY)pMods->Modules;
        STRING targetModuleName = RTL_CONSTANT_STRING("\\systemroot\\system32\\win32k.sys");
        STRING current;
        for (ULONG i = 0; i < pMods->NumberOfModules; i++)
        {
            RtlInitAnsiString(&current, (PCSZ)pMod[i].FullPathName);
            if (0 == RtlCompareString(&targetModuleName, &current, TRUE))
            {
                g_ModuleBase = pMod[i].ImageBase;
                g_ModuleSize = pMod[i].ImageSize;
                break;
            }
        }

        if (g_ModuleBase == NULL || g_ModuleSize == NULL)
        {
            DbgPrintEx(0, 0, "Couldnt get base");
            return STATUS_UNSUCCESSFUL;
        }

        OrigFunc = PsIsWin32KFilterEnabled;
        if (OrigFunc == nullptr)
        {
            DbgPrintEx(0, 0, "Failed to import function");
            return STATUS_UNSUCCESSFUL;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS apply(uintptr_t HookFunc)
    {
        LPVOID imageBase = g_ModuleBase;
        PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
        IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
        PIMAGE_IMPORT_BY_NAME functionName = NULL;

        while (importDescriptor->Name != NULL)
        {
            PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
            originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
            firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

            while (originalFirstThunk->u1.AddressOfData != NULL)
            {
                functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);

                // find address of function 
                if (!strcmp(functionName->Name, g_FunctionName))
                {
                    SIZE_T bytesWritten = 0;
                    DWORD oldProtect = 0;

                    // swap import address with new function address
                    firstThunk->u1.Function = (DWORD_PTR)HookFunc;
                    return STATUS_SUCCESS;
                }
                ++originalFirstThunk;
                ++firstThunk;
            }
            importDescriptor++;
        }
        return STATUS_UNSUCCESSFUL;
    }

    Hook()
    {
    }
};