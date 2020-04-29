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

NTSTATUS Hook_NtSetValueKey(
	IN HANDLE  KeyHandle,
	IN PUNICODE_STRING  ValueName,
	IN ULONG  TitleIndex  OPTIONAL,
	IN ULONG  Type,
	IN PVOID  Data,
	IN ULONG  DataSize);

typedef NTSTATUS(*ZWSETVALUEKEY)(
	IN HANDLE  KeyHandle,
	IN PUNICODE_STRING  ValueName,
	IN ULONG  TitleIndex  OPTIONAL,
	IN ULONG  Type,
	IN PVOID  Data,
	IN ULONG  DataSize
	);

NTSTATUS Hook_ZwTerminateProcess(
	IN HANDLE              ProcessHandle OPTIONAL,
	IN NTSTATUS            ExitStatus);

typedef NTSTATUS(*ZWTERMINATEPROCESS)(
	IN HANDLE              ProcessHandle OPTIONAL,
	IN NTSTATUS            ExitStatus);

static ZWTERMINATEPROCESS        OldZwTerminateProcess;
static ZWSETVALUEKEY            OldZwSetValueKey;

NTSTATUS Hook_NtSetValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex OPTIONAL,
	IN ULONG Type,
	IN PVOID Data,
	IN ULONG DataSize
)
{
	NTSTATUS status = STATUS_SUCCESS;
	BOOL skipOriginal = FALSE;
	UNICODE_STRING CapturedName;
	WCHAR wszPath[MAX_PATH] = { 0 };
	R3_RESULT CallBackResult = R3Result_Pass;
	WCHAR	ieName[MAX_PATH] = L"\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page";

	__try
	{
		UNICODE_STRING keyName;
		UNICODE_STRING uTarget;

		RtlZeroMemory(&keyName, sizeof(UNICODE_STRING));
		RtlZeroMemory(&uTarget, sizeof(UNICODE_STRING));

		//内核放行
		if ((ExGetPreviousMode() == KernelMode) ||
			(ValueName == NULL))
		{
			skipOriginal = TRUE;
			status = OldZwSetValueKey(KeyHandle,
				ValueName,
				TitleIndex,
				Type,
				Data,
				DataSize);

			return status;
		}

		//只要存在KeyHandle对象的Object 减少引用计数?
		if (MyProbeKeyHandle(KeyHandle, KEY_SET_VALUE) == FALSE)
		{

			skipOriginal = TRUE;
			status = OldZwSetValueKey(KeyHandle,
				ValueName,
				TitleIndex,
				Type,
				Data,
				DataSize);
			return status;
		}
		//查询到对象名称
		if (MyObQueryObjectName(KeyHandle, &keyName, TRUE) == FALSE)
		{
			skipOriginal = TRUE;
			status = OldZwSetValueKey(KeyHandle,
				ValueName,
				TitleIndex,
				Type,
				Data,
				DataSize);
			return status;
		}


		uTarget.Buffer = wszPath;
		uTarget.MaximumLength = MAX_PATH * sizeof(WCHAR);

		RtlCopyUnicodeString(&uTarget, &keyName);
		RtlFreeUnicodeString(&keyName);
		//添加最后的\
		if (L'\\' != uTarget.Buffer[uTarget.Length / sizeof(WCHAR) - 1])
			RtlAppendUnicodeToString(&uTarget, L"\\");

		CapturedName = ProbeAndReadUnicodeString(ValueName);

		ProbeForRead(CapturedName.Buffer,
			CapturedName.Length,
			sizeof(WCHAR));
		//组成注册表全名称
		RtlAppendUnicodeStringToString(&uTarget, &CapturedName);
		DbgPrint("Key:%wZ\n", &uTarget);
		
		if (GetRegLastInexByFullName(&uTarget, 5)) {
			//判断是否是IE
			if (wcscmp(uTarget.Buffer, ieName) == 0)
			{
				return STATUS_ACCESS_DENIED;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	if (skipOriginal)
		return status;

	return OldZwSetValueKey(KeyHandle,
		ValueName,
		TitleIndex,
		Type,
		Data,
		DataSize);
}

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


