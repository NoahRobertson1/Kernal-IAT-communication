#pragma once
#include "includes.h"

#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

#define PAGE_OFFSET_SIZE 12
#define FUNC_MARKER_END { volatile unsigned int _ = 0xAEDCF489; }
static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

#define ImageFileName 0x5A8 // EPROCESS::ImageFileName
#define ActiveThreads 0x5F0 // EPROCESS::ActiveThreads
#define ThreadListHead 0x5E0 // EPROCESS::ThreadListHead
#define ActiveProcessLinks 0x448 // EPROCESS::ActiveProcessLinks



namespace SDK
{
	namespace Usermode
	{
		class Memory
		{
		private:
			static bool valid_memory(uintptr_t address)
			{
				return address < 0x7FFFFFFFFFFF && address > 0;
			}

			static DWORD get_user_directory_table_base_offset()
			{
				RTL_OSVERSIONINFOW ver = { 0 };
				RtlGetVersion(&ver);

				switch (ver.dwBuildNumber)
				{
				case WINDOWS_1803:
					return 0x0278;
					break;
				case WINDOWS_1809:
					return 0x0278;
					break;
				case WINDOWS_1903:
					return 0x0280;
					break;
				case WINDOWS_1909:
					return 0x0280;
					break;
				case WINDOWS_2004:
					return 0x0388;
					break;
				case WINDOWS_20H2:
					return 0x0388;
					break;
				case WINDOWS_21H1:
					return 0x0388;
					break;
				default:
					return 0x0388;
				}
			}

			template <typename str_type, typename str_type_2>
			static __forceinline bool crt_strcmp(str_type str, str_type_2 in_str, bool two)
			{
				if (!str || !in_str)
					return false;

				wchar_t c1, c2;
#define to_lower(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)

				do
				{
					c1 = *str++; c2 = *in_str++;
					c1 = to_lower(c1); c2 = to_lower(c2);

					if (!c1 && (two ? !c2 : 1))
						return true;

				} while (c1 == c2);

				return false;
			}

			//check normal dirbase if 0 then get from UserDirectoryTableBas
			static ULONG_PTR get_process_cr3(PEPROCESS peprocess)
			{
				PUCHAR process = (PUCHAR)peprocess;
				ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
				if (process_dirbase == 0)
				{
					DWORD user_directory_offset = get_user_directory_table_base_offset();
					ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + user_directory_offset);
					return process_userdirbase;
				}
				return process_dirbase;
			}

			static ULONG_PTR get_kernel_dir_base()
			{
				PUCHAR process = (PUCHAR)PsGetCurrentProcess();
				ULONG_PTR cr3 = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
				return cr3;
			}

			static NTSTATUS read_physical_address(long long target_address, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
			{
				MM_COPY_ADDRESS address_to_read = { 0 };
				address_to_read.PhysicalAddress.QuadPart = target_address;
				return MmCopyMemory(lpBuffer, address_to_read, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
			}

			static uint64_t translate_linear_address(uint64_t directory_table_base, uint64_t virtual_address)
			{
				directory_table_base &= ~0xf;

				uint64_t page_offset = virtual_address & ~(~0ul << PAGE_OFFSET_SIZE);
				uint64_t pte = ((virtual_address >> 12) & (0x1ffll));
				uint64_t pt = ((virtual_address >> 21) & (0x1ffll));
				uint64_t pd = ((virtual_address >> 30) & (0x1ffll));
				uint64_t pdp = ((virtual_address >> 39) & (0x1ffll));

				SIZE_T readsize = 0;
				uint64_t pdpe = 0;
				read_physical_address(directory_table_base + 8 * pdp, &pdpe, sizeof(pdpe), &readsize);
				if (~pdpe & 1)
					return 0;

				uint64_t pde = 0;
				read_physical_address((pdpe & PMASK) + 8 * pd, &pde, sizeof(pde), &readsize);
				if (~pde & 1)
					return 0;

				// 1GB large page, use pde's 12-34 bits 
				if (pde & 0x80)
					return (pde & (~0ull << 42 >> 12)) + (virtual_address & ~(~0ull << 30));

				uint64_t ptr_address = 0;
				read_physical_address((pde & PMASK) + 8 * pt, &ptr_address, sizeof(ptr_address), &readsize);
				if (~ptr_address & 1)
					return 0;

				// 2MB large page 
				if (ptr_address & 0x80)
					return (ptr_address & PMASK) + (virtual_address & ~(~0ull << 21));

				virtual_address = 0;
				read_physical_address((ptr_address & PMASK) + 8 * pte, &virtual_address, sizeof(virtual_address), &readsize);
				virtual_address &= PMASK;

				if (!virtual_address)
					return 0;

				return virtual_address + page_offset;
			}

			static NTSTATUS read_virtual_memory(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read)
			{
				uint64_t translated_address = translate_linear_address(dirbase, address);
				return read_physical_address(translated_address, buffer, size, read);
			}

			static NTSTATUS write_physical_address(long long target_address, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
			{
				if (!target_address || Size > 4096)
					return STATUS_UNSUCCESSFUL;

				PHYSICAL_ADDRESS address_to_write = { 0 };
				address_to_write.QuadPart = target_address;

				PVOID mapped_memory = MmMapIoSpaceEx(address_to_write, Size, PAGE_READWRITE);

				if (!mapped_memory)
					return STATUS_UNSUCCESSFUL;

				memcpy(mapped_memory, lpBuffer, Size);

				*BytesWritten = Size;
				MmUnmapIoSpace(mapped_memory, Size);
				return STATUS_SUCCESS;
			}

			static NTSTATUS write_virtual_memory(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written)
			{
				uint64_t translated_address = translate_linear_address(dirbase, address);
				return write_physical_address(translated_address, buffer, size, written);
			}
		public:
			static NTSTATUS ReadProcessMemory(int pid, PVOID address, PVOID allocated_buffer, SIZE_T size)
			{
				PEPROCESS pProcess = NULL;
				if (pid == 0)
					return STATUS_UNSUCCESSFUL;

				NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
				if (NtRet != STATUS_SUCCESS) return NtRet;

				if (!valid_memory(reinterpret_cast<uintptr_t>(address))) {
					return STATUS_UNSUCCESSFUL;
				}

				ULONG_PTR process_dirbase = get_process_cr3(pProcess);
				ObDereferenceObject(pProcess);

				SIZE_T CurOffset = 0;
				SIZE_T TotalSize = size;
				while (TotalSize)
				{
					uint64_t cur_physical_address = translate_linear_address(process_dirbase, (ULONG64)address + CurOffset);
					if (!cur_physical_address) return STATUS_UNSUCCESSFUL;

					ULONG64 ReadSize = min(PAGE_SIZE - (cur_physical_address & 0xFFF), TotalSize);
					SIZE_T BytesRead = 0;
					NtRet = read_physical_address(cur_physical_address, (PVOID)((ULONG64)allocated_buffer + CurOffset), ReadSize, &BytesRead);
					TotalSize -= BytesRead;
					CurOffset += BytesRead;
					if (NtRet != STATUS_SUCCESS) break;
					if (BytesRead == 0) break;
				}

				SIZE_T read_bytes;
				read_bytes = CurOffset;

				return NtRet;
			}

			static NTSTATUS WriteProcessMemory(int pid, PVOID address, PVOID allocated_buffer, SIZE_T size)
			{
				PEPROCESS pProcess = NULL;
				if (pid == 0)
					return STATUS_UNSUCCESSFUL;

				NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
				if (status != STATUS_SUCCESS)
					return status;

				if (!valid_memory(reinterpret_cast<uintptr_t>(address))) {
					return STATUS_UNSUCCESSFUL;
				}

				ULONG_PTR process_dirbase = get_process_cr3(pProcess);
				ObDereferenceObject(pProcess);

				SIZE_T current_offset = 0;
				SIZE_T total_size = size;
				while (total_size)
				{
					uint64_t current_phyisical_address = translate_linear_address(process_dirbase, (ULONG64)address + current_offset);
					if (!current_phyisical_address) return STATUS_UNSUCCESSFUL;

					ULONG64 write_size = min(PAGE_SIZE - (current_phyisical_address & 0xFFF), total_size);
					SIZE_T bytes_written = 0;
					status = write_physical_address(current_phyisical_address, (PVOID)((ULONG64)allocated_buffer + current_offset), write_size, &bytes_written);
					total_size -= bytes_written;
					current_offset += bytes_written;
					if (status != STATUS_SUCCESS) break;
					if (bytes_written == 0) break;
				}

				SIZE_T written;
				written = current_offset;

				return status;

				FUNC_MARKER_END;
			}

			static PVOID GetModuleBase(int processpid, const wchar_t* module_name)
			{
				PEPROCESS peprocess;
				PsLookupProcessByProcessId((HANDLE)processpid, &peprocess);

				NTSTATUS status;
				PROCESS_BASIC_INFORMATION proc_info;
				ULONG length = 0;

				HANDLE proc;
				status = ObOpenObjectByPointer(peprocess, 0, NULL, 0, 0, KernelMode, &proc);
				if (!NT_SUCCESS(status))
					return NULL;

				if (!NT_SUCCESS(ZwQueryInformationProcess(
					proc,
					ProcessBasicInformation,
					&proc_info,
					sizeof(PROCESS_BASIC_INFORMATION),
					&length)))
				{
					return NULL;
				}
				ZwClose(proc);

				PEB process_peb = { 0 };
				status = ReadProcessMemory(processpid, (PVOID)proc_info.PebBaseAddress, &process_peb, sizeof(PEB));
				if (!NT_SUCCESS(status))
					return NULL;

				PEB_LDR_DATA peb_ldr_data = { 0 };
				status = ReadProcessMemory(processpid, (PVOID)process_peb.LoaderData, &peb_ldr_data, sizeof(PEB_LDR_DATA));
				if (!NT_SUCCESS(status))
					return NULL;

				LIST_ENTRY* ldr_list_head = (LIST_ENTRY*)peb_ldr_data.InLoadOrderModuleList.Flink;
				LIST_ENTRY* ldr_current_node = peb_ldr_data.InLoadOrderModuleList.Flink;
				do
				{
					LDR_DATA_TABLE_ENTRY list_entry = { 0 };
					status = ReadProcessMemory(processpid, (PVOID)ldr_current_node, &list_entry, sizeof(LDR_DATA_TABLE_ENTRY));
					if (!NT_SUCCESS(status))
						return NULL;

					ldr_current_node = list_entry.InLoadOrderLinks.Flink;

					if (list_entry.BaseDllName.Length > 0)
					{
						wchar_t base_name[MAX_PATH] = { 0 };
						status = ReadProcessMemory(processpid, (PVOID)list_entry.BaseDllName.Buffer, &base_name, list_entry.BaseDllName.Length);
						if (NT_SUCCESS(status))
						{
							if (!wcscmp(module_name, base_name))
							{
								if (list_entry.DllBase != nullptr && list_entry.SizeOfImage != 0)
								{
									return list_entry.DllBase;
								}
							}
						}
					}

				} while (ldr_list_head != ldr_current_node);

				return NULL;
			}
			static HANDLE GetPidByName(const wchar_t* process_name)
			{
				CHAR image_name[15];
				PEPROCESS sys_process = PsInitialSystemProcess;
				PEPROCESS cur_entry = sys_process;

				do
				{
					RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + ImageFileName), sizeof(image_name));

					if (crt_strcmp(image_name, process_name, true))
					{
						DWORD active_threads;
						RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)cur_entry + ActiveThreads), sizeof(active_threads));

						if (active_threads)
							return PsGetProcessId(cur_entry);
					}

					PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry)+ActiveProcessLinks);
					cur_entry = (PEPROCESS)((uintptr_t)list->Flink - ActiveProcessLinks);

				} while (cur_entry != sys_process);

				return 0;
			}
		};
	}
	namespace Kernel
	{
		class Module
		{
		private:
		public:
			static uintptr_t GetKernelBase()
			{
				auto entry = __readmsr(0xC0000082) & ~0xfff;

				do {

					auto addr = *(USHORT*)entry;

					if (addr == IMAGE_DOS_SIGNATURE) {

						for (auto x = entry; x < entry + 0x400; x += 8) {

							if (*(ULONG64*)x == 0x4B4C45474150) {
								return (uintptr_t)entry;
							}

						}
					}

					entry -= 0x1000;

				} while (TRUE);

				return 0;
			}

			static void ListModules()
			{
				ULONG bytes = 0;
				NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

				if (!bytes)
					return;

				PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);

				status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

				if (!NT_SUCCESS(status))
					return;

				PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
				PVOID module_base = 0, module_size = 0;

				for (ULONG i = 0; i < modules->NumberOfModules; i++)
				{
					DbgPrintEx(0, 0, "%s\n", (char*)module[i].FullPathName);
				}

				ExFreePoolWithTag(modules, 0);
			}

			static void* Image(const char* ModuleName)
			{
				ULONG bytes = 0;
				NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

				if (!bytes) return 0;

				PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);

				status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

				if (!NT_SUCCESS(status))
					return 0;

				PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
				PVOID module_base = 0, module_size = 0;

				for (ULONG i = 0; i < modules->NumberOfModules; i++)
				{
					//DbgPrintEx(0,0,"%s\n",(char*)module[i].FullPathName);

					if (strcmp((char*)module[i].FullPathName, ModuleName) == 0)
					{
						module_base = module[i].ImageBase;
						module_size = (PVOID)module[i].ImageSize;
						break;
					}
				}

				if (modules) ExFreePoolWithTag(modules, 0);
				if (module_base <= 0) return 0;
				return module_base;
			}
		};
	}
}