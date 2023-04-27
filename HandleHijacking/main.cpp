#include <Windows.h>
#include <iostream>
#include <string>
#include <Psapi.h>
#include <vector>

#include "nt.h"

DWORD GetSvcPidByName(const char* SvcName)
{
	// Shoutout to MarkHC from UC.
	
	DWORD SvcPid = 0;

	SC_HANDLE SvcManagerHandle = 0;
	SC_HANDLE SvcHandle = 0;
	do
	{
		// Getting an handle to the service manager.
		SvcManagerHandle = OpenSCManagerA(NULL, SERVICES_ACTIVE_DATABASEA, SC_MANAGER_CONNECT);
		if (!SvcManagerHandle)
		{
			printf("[-] OpenSCManagerA failed, err: 0x%X\n", GetLastError());
			break;
		}

		// Opening the service with the name SvcName from the service manager.
		SvcHandle = OpenServiceA(SvcManagerHandle, SvcName, GENERIC_READ);
		if (!SvcHandle)
		{
			printf("[-] OpenServiceA failed, err: 0x%X\n", GetLastError());
			break;
		}

		// Querying the returned service so we can get it's PID.
		SERVICE_STATUS_PROCESS SvcStatus = {};
		DWORD BytesNeeded = 0;
		if (!QueryServiceStatusEx(SvcHandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&SvcStatus, sizeof(SERVICE_STATUS_PROCESS), &BytesNeeded))
		{
			printf("[-] QueryServiceStatusEx failed, err: 0x%X\n", GetLastError());
			break;
		}

		SvcPid = SvcStatus.dwProcessId;
	} while (FALSE);

	if (SvcHandle && !CloseServiceHandle(SvcHandle))
		printf("[-] CloseServiceHandle for SvcHandle failed, err: 0x%X\n", GetLastError());

	if (SvcManagerHandle && !CloseServiceHandle(SvcManagerHandle))
		printf("[-] CloseServiceHandle for SvcManagerHandle failed, err: 0x%X\n", GetLastError());
	
	return SvcPid;
}

HANDLE HandleHijack(DWORD Pid)
{
	// Getting a handle to NTDLL module so we can access it's functions.
	static const HMODULE hNtdll = GetModuleHandleA("NTDLL.DLL");
	if (!hNtdll)
	{
		printf("[-] NTDLL.DLL module couldn't be found.\n");
		return 0;
	}

	// Getting NtQuerySystemInformation address that will be used on getting the handles.
	static const tNtQuerySystemInformation NtQuerySystemInformation = (tNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (!NtQuerySystemInformation)
	{
		printf("[-] NTDLL!NtQuerySystemInformation couldn't be found.\n");
		return 0;
	}

	// Getting NtQueryObject which will be used on getting a specific handle's details.
	static const tNtQueryObject NtQueryObject = (tNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
	if (!NtQueryObject)
	{
		printf("[-] NTDLL!NtQueryObject couldn't be found.\n");
		return 0;
	}

	// Getting NtDuplicateObject which will be used on copying the handle.
	static const tNtDuplicateObject NtDuplicateObject = (tNtDuplicateObject)GetProcAddress(hNtdll, "ZwDuplicateObject");
	if (!NtQueryObject)
	{
		printf("[-] NTDLL!NtDuplicateObject couldn't be found.\n");
		return 0;
	}

	// PcaSvc is the service which's process (svchost.exe) has a HANDLE with PROCESS_ALL_ACCESS permission to almost every process in the system.
	const DWORD SvcPid = GetSvcPidByName("PcaSvc");
	printf("[*] Svc Pid: 0x%X\n", SvcPid);


	// Starting off with a little size, will be increased over failed attempts.
	// Using std::vector for memory safety.
	ULONG ReturnLength = 16;
	std::vector<BYTE> HandleMemory(ReturnLength, 0);

	NTSTATUS Status = STATUS_SUCCESS;
	while (Status = NtQuerySystemInformation(SystemHandleInformation, &HandleMemory[0], ReturnLength, &ReturnLength), !NT_SUCCESS(Status))
	{
		HandleMemory.resize(ReturnLength);

		if (Status = NtQuerySystemInformation(SystemHandleInformation, &HandleMemory[0], ReturnLength, &ReturnLength), NT_SUCCESS(Status))
			break;

		// If it still couldn't get the handle in the 100th time then we just quit to prevent deadlock.
		static SIZE_T IterateTimes = 0;
		if (++IterateTimes >= 100)
		{
			printf("[-] NTDLL!NtQuerySystemInformation couldn't retrieve handle information.\n");
			return 0;
		}
	}

	// Storing the pointer at a different variable so we don't have to keep doing ' (PSYSTEM_HANDLE_INFORMATION)&HandleMemory[0] '.
	PSYSTEM_HANDLE_INFORMATION SysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)&HandleMemory[0];
	
	// Opening an handle to the service.
	HANDLE SvcHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, SvcPid);
	if (!SvcHandle)
	{
		printf("[-] OpenProcess failed, err: 0x%X.\n", GetLastError());
		return 0;
	}

	// Iterating through all the handles.
	for (int i = 0; i < SysHandleInfo->HandleCount; i++)
	{
		const SYSTEM_HANDLE& IdxHandleEntry = SysHandleInfo->Handles[i];

		// ProcessId is the process who opened this handle, in our case since we are iterating through EVERY handle we must guarantee it was opened by our service process.
		// GrantedAccess is the accesses the handle have, if it doesn't have PROCESS_ALL_ACCESS it's unusable.
		// ObjectTypeNumber is a number indicating the handle type (yes) so we are checking if it's a process handle since we are hijack the handle of a process.
		if (IdxHandleEntry.ProcessId != SvcPid ||
			IdxHandleEntry.GrantedAccess != PROCESS_ALL_ACCESS ||
			IdxHandleEntry.ObjectTypeNumber != HANDLE_TYPE_PROCESS)
			continue;

		// Duplicating the handle so we can query it and use it later on.
		HANDLE DupHandle = 0;
		if (Status = NtDuplicateObject(SvcHandle, (HANDLE)IdxHandleEntry.Handle, GetCurrentProcess(), &DupHandle, NULL, NULL, DUPLICATE_SAME_ACCESS), !NT_SUCCESS(Status))
		{
			printf("[-] NTDLL!NtDuplicateObject failed, ntstatus: 0x%X.\n", Status);
			return 0;
		}

		// Validating that the process this handle was opened for is our target process, if it is we return the handle.
		if (GetProcessId(DupHandle) == Pid)
			return DupHandle;

		// Otherwise we close this handle and continue iterating through the other handles.
		if (!CloseHandle(DupHandle))
			printf("[-] CloseHandle for DupHandle failed, err: 0x%X\n", GetLastError());
	}

	printf("[-] An open handle against the target process couldn't be found.\n");
	return 0;
}

int main(int argc, const char* argv[])
{
	// The program must be run from administrator-powershell in order to get an handle from svchost with PROCESS_DUP_HANDLE access.

	printf("Handle Hijacker\n\n");

	if (argc != 2)
	{
		const std::string Filename = argv[0];
		printf("[-] Invalid arguments\n[-] Usage: %s PID\n", Filename.substr(Filename.find_last_of("/\\") + 1).c_str());
		return 0;
	}

	const DWORD Pid = atoi(argv[1]);
	if (!Pid)
	{
		printf("Invalid PID.\n");
		return 0;
	}

	printf("[*] Attempting to handle hijack [PID: %lu]\n", Pid);
	const HANDLE hHijacked = HandleHijack(Pid);
	if (!hHijacked)
	{
		printf("[-] Handle hijacking attempt failed.\n");
		return 0;
	}

	printf("[*] Hijacked Handle from [PID: %lu] - 0x%X\n", Pid, HandleToULong(hHijacked));

	if (!CloseHandle(hHijacked))
		printf("[-] CloseHandle for hHijacked failed, err: 0x%X\n", GetLastError());

	system("pause");
}