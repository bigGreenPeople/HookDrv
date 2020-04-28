#include "precomp.h"

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]
#define SDT     SYSTEMSERVICE
#define KSDT KeServiceDescriptorTable

NTKERNELAPI NTSTATUS ZwTerminateProcess(
	IN HANDLE              ProcessHandle OPTIONAL,
	IN NTSTATUS            ExitStatus);

NTSTATUS Hook_ZwTerminateProcess(
	IN HANDLE              ProcessHandle OPTIONAL,
	IN NTSTATUS            ExitStatus);

typedef NTSTATUS(*ZWTERMINATEPROCESS)(
	IN HANDLE              ProcessHandle OPTIONAL,
	IN NTSTATUS            ExitStatus);

static ZWTERMINATEPROCESS        OldZwTerminateProcess;


NTSTATUS Hook_ZwTerminateProcess(
	__in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus
)
{
	ULONG 			uPID = 0;
	NTSTATUS 		ntStatus = 0;
	PEPROCESS 		pEProcess = NULL;
	WCHAR	szCopiedStr[1024] = L"";
	WCHAR	ieName[1024] = L"iexplore.exe";


	ntStatus = ObReferenceObjectByHandle(ProcessHandle, FILE_READ_DATA, NULL, KernelMode, &pEProcess, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	UNICODE_STRING closeFileName = { 0 };
	UNICODE_STRING ieProcessName = { 0 };
	//初始化ieprlorer名称
	RtlInitUnicodeString(&ieProcessName, ieName);
	ieProcessName.MaximumLength = sizeof(ieName);
	ieProcessName.Length = ieProcessName.MaximumLength;


	uPID = (ULONG)PsGetProcessId(pEProcess);

	RtlInitUnicodeString(&closeFileName, szCopiedStr);
	closeFileName.MaximumLength = sizeof(szCopiedStr);
	closeFileName.Length = closeFileName.MaximumLength;


	//得到closeFileName
	GetProcessFullNameByPid((HANDLE)uPID, &closeFileName);
	GetNameByFullName(&closeFileName);
	closeFileName.Length = closeFileName.MaximumLength;
	
	if (wcscmp(closeFileName.Buffer, ieProcessName.Buffer)==0)
	{
		// 判断不是自己
		if (uPID != (ULONG)PsGetProcessId(PsGetCurrentProcess()))
		{
			return STATUS_ACCESS_DENIED;
		}
	}
	ntStatus = OldZwTerminateProcess(ProcessHandle, ExitStatus);

	return ntStatus;
}


NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED *Dst, IN CONST VOID UNALIGNED *Src, IN ULONG Length)
{
	PMDL pmdl = IoAllocateMdl(Dst, Length, 0, 0, NULL);
	if (pmdl == NULL)
		return STATUS_UNSUCCESSFUL;
	MmBuildMdlForNonPagedPool(pmdl);
	unsigned int *Mapped = (unsigned int *)MmMapLockedPages(pmdl, KernelMode);
	if (!Mapped)
	{
		IoFreeMdl(pmdl);
		return STATUS_UNSUCCESSFUL;
	}

	KIRQL kirql = KeRaiseIrqlToDpcLevel();

	RtlCopyMemory(Mapped, Src, Length);

	KeLowerIrql(kirql);

	MmUnmapLockedPages((PVOID)Mapped, pmdl);
	IoFreeMdl(pmdl);

	return STATUS_SUCCESS;

}

void StartHook(void)
{
#if DBG
	_asm int 3
#endif // DBG

	DbgPrint("StartHook \n");

	OldZwTerminateProcess = SDT(ZwTerminateProcess);
	ULONG hookAddr = (ULONG)Hook_ZwTerminateProcess;
	RtlSuperCopyMemory(&SDT(ZwTerminateProcess), &hookAddr, 4);   //关闭

	return;
}

void RemoveHook(void)
{
	DbgPrint("RemoveHook \n");

	ULONG hookAddr = (ULONG)OldZwTerminateProcess;
	RtlSuperCopyMemory(&SDT(ZwTerminateProcess), &hookAddr, 4);    //关闭
}


