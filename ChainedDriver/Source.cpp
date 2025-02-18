#include "includes.h"
#include "hook.h"
#include "handler.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);

	NTSTATUS status;
	Hook hook;
	
	status = hook.setup("PsIsWin32KFilterEnabled", "win32k.sys");
	if (status != STATUS_SUCCESS) return status;
	DbgPrintEx(0, 0, "Setup hook");

	status = handler::initiate();
	if (status != STATUS_SUCCESS) return status;
	DbgPrintEx(0, 0, "Initiated handler");

	status = hook.apply((uintptr_t)&handler::handler);
	if (status != STATUS_SUCCESS) return status;
	DbgPrintEx(0, 0, "Applied hook");

	return status;
}