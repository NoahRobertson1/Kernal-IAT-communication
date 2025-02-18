#pragma once
#include <ntifs.h>
#include <classpnp.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <windef.h>
#include <ntimage.h>
#include <intrin.h>
#include <wdm.h>
#include "structs.h"


extern "C"
{
	NTKERNELAPI __int64 NTAPI PsIsWin32KFilterEnabled();
	NTSYSCALLAPI NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID OPTIONAL, PVOID*);
	NTSYSCALLAPI POBJECT_TYPE* IoDriverObjectType;

	NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
	NTSYSCALLAPI NTSTATUS NTAPI ZwFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
	NTSYSCALLAPI NTSTATUS NTAPI ZwLockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG LockOption);
	NTSYSCALLAPI NTSTATUS NTAPI ZwUnlockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG LockOption);
	NTSYSCALLAPI NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection);
	NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
	NTSYSCALLAPI NTSTATUS NTAPI ZwQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
	NTSYSCALLAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

	NTKERNELAPI NTSTATUS NTAPI PsSuspendProcess(HANDLE ProcessId);
	NTKERNELAPI NTSTATUS NTAPI PsResumeProcess(HANDLE ProcessId);
	NTKERNELAPI NTSTATUS NTAPI PsLookupProcessThreadByCid(PCLIENT_ID ClientId, PEPROCESS* Process, PETHREAD* Thread);
	NTKERNELAPI HANDLE NTAPI PsGetProcessInheritedFromUniqueProcessId(PEPROCESS Process);
	NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);
	NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	NTKERNELAPI NTSTATUS NTAPI PsGetContextThread(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);
	NTKERNELAPI NTSTATUS NTAPI PsSetContextThread(PETHREAD Thread, PCONTEXT ThreadContext, KPROCESSOR_MODE Mode);
	NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(PVOID ImageBase, PCCH RoutineName);
	NTKERNELAPI PVOID NTAPI PsRegisterPicoProvider(PVOID, PVOID);
	NTKERNELAPI PVOID NTAPI PsGetThreadTeb(PETHREAD Thread);
	//NTKERNELAPI PLIST_ENTRY NTAPI PsLoadedModuleList;

	NTSYSAPI NTSTATUS ZwQueryVirtualMemory(
		HANDLE                   ProcessHandle,
		PVOID                    BaseAddress,
		MEMORY_INFORMATION_CLASS MemoryInformationClass,
		PVOID                    MemoryInformation,
		SIZE_T                   MemoryInformationLength,
		PSIZE_T                  ReturnLength
	);

	NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
	NTKERNELAPI NTSTATUS WINAPI ZwQueryInformationProcess(
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength
	);

	NTSYSAPI VOID RtlInitAnsiString(
		_Out_          PANSI_STRING          DestinationString,
		_Out_opt_  __drv_aliasesMem PCSZ SourceString
	);
}
