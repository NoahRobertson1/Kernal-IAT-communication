#pragma once
#include "includes.h"
#include "hook.h"
#include "memory.h"

namespace handler
{
	namespace communication
	{
		enum Status : int
		{
			pause,
			ready,
			operationSuccess,
			operationFailed,
			abort
		};
		enum Instruction : int
		{
			getBase,
			readMemory,
			writeMemory,
			copyMemory
		};

		struct Call
		{
			// driver handler
			Status status;
			Instruction instruction;
			int key;

			// r/w params
			int pid;
			PVOID dst;
			PVOID src;
			int size;

			// mod params
			PVOID base;
			wchar_t* moduleName;
		};
	}

	struct parentProcess
	{
		int pid;
		uint64_t base;
		uint64_t callAddress;
	};

	using namespace communication;

	Call g_call;
	parentProcess parent;


	NTSTATUS initiate()
	{
		parent.pid = (int)SDK::Usermode::Memory::GetPidByName(L"Surgent.exe");
		if (!parent.pid) return STATUS_UNSUCCESSFUL;
		parent.base = (uintptr_t)SDK::Usermode::Memory::GetModuleBase(parent.pid, L"Surgent.exe");
		if (!parent.base) return STATUS_UNSUCCESSFUL;

		// GET POINTER TO CALL OBJECT
		
		ULONG callOff = 0x56C0; // this is just for the current um procees and will be needed to be updated often
		parent.callAddress = uint64_t(parent.base + callOff);
		SDK::Usermode::Memory::ReadProcessMemory(parent.pid, (PVOID)(parent.callAddress), &g_call, sizeof(Call));
		if (g_call.key != 130321)
			return STATUS_UNSUCCESSFUL;

		return STATUS_SUCCESS;
	}

	void writeBack(Call* c, NTSTATUS status)
	{
		if (status == STATUS_SUCCESS)
			c->status = operationSuccess;
		else
			c->status = operationFailed;

		SDK::Usermode::Memory::WriteProcessMemory(parent.pid, (PVOID)parent.callAddress, c, sizeof(Call));
	}

	__int64 handler()
	{
		NTSTATUS status;

		if (g_call.status != pause)
		{
			if (g_call.status == ready)
			{
				if (g_call.instruction == getBase)
				{
					g_call.base = SDK::Usermode::Memory::GetModuleBase(g_call.pid, g_call.moduleName);
					writeBack(&g_call, STATUS_SUCCESS);
				}
				else if (g_call.instruction == readMemory)
				{
					status = SDK::Usermode::Memory::ReadProcessMemory(g_call.pid, g_call.src, g_call.dst, g_call.size);
					writeBack(&g_call, status);
				}
				else if (g_call.instruction == writeMemory)
				{
					status = SDK::Usermode::Memory::WriteProcessMemory(g_call.pid, g_call.dst, g_call.src, g_call.size);
					writeBack(&g_call, status);
				}
				if (g_call.instruction == copyMemory)
				{
					status = SDK::Usermode::Memory::ReadProcessMemory(g_call.pid, g_call.src, g_call.dst, g_call.size);
					writeBack(&g_call, status);
				}
			}
		}

		return Hook::OrigFunc();
	}
}