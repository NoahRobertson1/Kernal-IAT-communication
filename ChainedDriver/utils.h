#pragma once
#include "includes.h"
#include "memory.h"

class Pattern
{
private:
	static PIMAGE_NT_HEADERS GetHeader(PVOID module)
	{
		return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
	}

	static PBYTE Find(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask)
	{
		auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
		{
			for (auto x = buffer; *mask; pattern++, mask++, x++)
			{
				auto addr = *(BYTE*)(pattern);
				if (addr != *x && *mask != '?')
					return FALSE;
			}

			return TRUE;
		};

		for (auto x = 0; x < size - strlen(mask); x++)
		{
			auto addr = (PBYTE)module + x;
			if (checkMask(addr, pattern, mask))
				return addr;
		}

		return NULL;
	}
public:
	static PBYTE Find(PVOID base, LPCSTR pattern, LPCSTR mask)
	{
		auto Header = GetHeader(base);
		auto Section = IMAGE_FIRST_SECTION(Header);

		for (auto x = 0; x < Header->FileHeader.NumberOfSections; x++, Section++)
		{
			if (!memcmp(Section->Name, ".text", 5) || !memcmp(Section->Name, "PAGE", 4))
			{
				auto Address = Find((PBYTE)base + Section->VirtualAddress, Section->Misc.VirtualSize, pattern, mask);

				return Address ? Address : NULL;
			}
		}

		return NULL;
	}
};



namespace helpers
{
#define SYSCALL_MAGIC 130321
	static const auto initialize_shellcode = [](void* target, void* origHook) -> void* {
        /*
         *     ; check for our id mask
         *     movabs r10, 0x0
         *     cmp    r9, r10
         *
         *     ; jump to normal if it's our call
         *     je     normal
         *
         *     ; tail call original
         *     movabs r10, 0x0
         *     jmp    r10
         *
         * normal:
         *     ; disable NMIs
         *     ; KeEnterGuardedRegion
         *     movabs r10, 0x0
         *     call   r10
         *
         *     ; allocate shadow space
         *     sub    rsp, 0x48
         *
         *     ; call target
         *     movabs r10, 0x0
         *     call   r10
         *
         *     ; store return result
         *     mov    QWORD PTR [rsp+0x30],rax
         *
         *     ; push gadget as return address
         *     movabs r10, 0x0
         *     push   r10
         *
         *     ; enable NMIs
         *     ; KeLeaveGuarded region
         *     movabs r10, 0x0
         *     jmp    r10
        */

        uint8_t shellcode[] = "\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00\x4D\x39\xD1\x74\x0D\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00\x41\xFF\xE2\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00\x41\xFF\xD2\x48\x83\xEC\x48\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00\x41\xFF\xD2\x48\x89\x44\x24\x30\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00\x41\x52\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00\x41\xFF\xE2";
        const uint64_t ntoskrnl = (uint64_t)SDK::Kernel::Module::Image("\\SystemRoot\\System32\\ntoskrnl.exe");
        if (ntoskrnl == 0)
            return nullptr;
#define sig1 "\x48\x8B\x44\x24\x30\x48\x83\xC4\x48\xC3", "xxxxxxxxxx"
        // ntoskrnl!KeSetSystemAffinityThreadEx + 0x3B 48 8B 44 24 30 48 83 C4 48 C3
        uint64_t address = (uint64_t)Pattern::Find((void*)ntoskrnl, sig1);
        if (address == 0)
            return nullptr;

        auto code = (uint8_t*)ExAllocatePool(NonPagedPool, sizeof(shellcode));
        if (code == nullptr)
            return nullptr;

        memcpy(code, shellcode, sizeof(shellcode));

        *(void**)(&code[0x02]) = (void*)SYSCALL_MAGIC;
        *(void**)(&code[0x11]) = (void*)origHook;
        *(void**)(&code[0x1e]) = (void*)KeEnterGuardedRegion;
        *(void**)(&code[0x2f]) = (void*)target;
        *(void**)(&code[0x41]) = (void*)address;
        *(void**)(&code[0x4d]) = (void*)KeLeaveGuardedRegion;

        return code;
    };
}