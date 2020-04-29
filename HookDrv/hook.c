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



NTSTATUS Hook_ZwTerminateProcess(
	IN HANDLE              ProcessHandle OPTIONAL,
	IN NTSTATUS            ExitStatus);

NTSTATUS Hook_ZwSetInformationFile(
	_In_ HANDLE FileHandle,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_reads_bytes_(Length) PVOID FileInformation,
	_In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS(*ZWSETINFORMATIONFILE)(
	_In_ HANDLE FileHandle,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_reads_bytes_(Length) PVOID FileInformation,
	_In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS(*ZWTERMINATEPROCESS)(
	IN HANDLE              ProcessHandle OPTIONAL,
	IN NTSTATUS            ExitStatus);
typedef NTSTATUS(*ZWSETVALUEKEY)(
	IN HANDLE  KeyHandle,
	IN PUNICODE_STRING  ValueName,
	IN ULONG  TitleIndex  OPTIONAL,
	IN ULONG  Type,
	IN PVOID  Data,
	IN ULONG  DataSize
	);

static ZWTERMINATEPROCESS        OldZwTerminateProcess;
static ZWSETVALUEKEY            OldZwSetValueKey;
static ZWSETINFORMATIONFILE        OldZwSetInformationFile;



NTSTATUS Hook_ZwSetInformationFile(
	_In_ HANDLE FileHandle,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_reads_bytes_(Length) PVOID FileInformation,
	_In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass
) {
	NTSTATUS ntStatus = -1;
	IO_STATUS_BLOCK IoStatus = { 0 };
	size_t allocSize = 0;
	WCHAR	proName[MAX_PATH] = L"\\2.txt";
	FILE_NAME_INFORMATION  fni;


	PWCHAR pName = (PWCHAR)ExAllocatePool(PagedPool, MAX_PATH);

	RtlZeroMemory(pName, MAX_PATH);

	PFILE_NAME_INFORMATION pfni = (PFILE_NAME_INFORMATION)pName;

	pfni->FileNameLength = MAX_PATH;

	ntStatus = ZwQueryInformationFile(FileHandle, &IoStatus, pfni, sizeof(FILE_NAME_INFORMATION) + MAX_PATH, FileNameInformation);


	if (NT_SUCCESS(ntStatus))
	{
		if (wcscmp(pfni->FileName, proName) == 0)
		{
			return STATUS_ACCESS_DENIED;
		}
	}

	ExFreePool(pfni);
	ntStatus = OldZwSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

	return ntStatus;
}

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

		//�ں˷���
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

		//ֻҪ����KeyHandle�����Object �������ü���?
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
		//��ѯ����������
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
		//�������\
		if (L'\\' != uTarget.Buffer[uTarget.Length / sizeof(WCHAR) - 1])
		RtlAppendUnicodeToString(&uTarget, L"\\");

		CapturedName = ProbeAndReadUnicodeString(ValueName);

		ProbeForRead(CapturedName.Buffer,
			CapturedName.Length,
			sizeof(WCHAR));
		//���ע���ȫ����
		RtlAppendUnicodeStringToString(&uTarget, &CapturedName);
		DbgPrint("Key:%wZ\n", &uTarget);

		if (GetRegLastInexByFullName(&uTarget, 5)) {
			//�ж��Ƿ���IE
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
	//��ʼ��ieprlorer����
	RtlInitUnicodeString(&ieProcessName, ieName);
	ieProcessName.MaximumLength = sizeof(ieName);
	ieProcessName.Length = ieProcessName.MaximumLength;


	uPID = (ULONG)PsGetProcessId(pEProcess);

	RtlInitUnicodeString(&closeFileName, szCopiedStr);
	closeFileName.MaximumLength = sizeof(szCopiedStr);
	closeFileName.Length = closeFileName.MaximumLength;


	//�õ�closeFileName
	GetProcessFullNameByPid((HANDLE)uPID, &closeFileName);
	GetNameByFullName(&closeFileName);
	closeFileName.Length = closeFileName.MaximumLength;

	if (wcscmp(closeFileName.Buffer, ieProcessName.Buffer) == 0)
	{
		// �жϲ����Լ�
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

	//OldZwTerminateProcess = SDT(ZwTerminateProcess);
	//ULONG hookAddr = (ULONG)Hook_ZwTerminateProcess;
	//RtlSuperCopyMemory(&SDT(ZwTerminateProcess), &hookAddr, 4);   //�ر�

	OldZwSetValueKey = SDT(ZwSetValueKey);
	ULONG hookAddr2 = (ULONG)Hook_NtSetValueKey;
	RtlSuperCopyMemory(&SDT(ZwSetValueKey), &hookAddr2, 4);

	OldZwSetInformationFile = SDT(ZwSetInformationFile);
	ULONG hookAddr3 = (ULONG)Hook_ZwSetInformationFile;
	RtlSuperCopyMemory(&SDT(ZwSetInformationFile), &hookAddr3, 4);
	return;
}

void RemoveHook(void)
{
	DbgPrint("RemoveHook \n");

	//ULONG hookAddr = (ULONG)OldZwTerminateProcess;
	//RtlSuperCopyMemory(&SDT(ZwTerminateProcess), &hookAddr, 4);

	ULONG hookAddr2 = (ULONG)OldZwSetValueKey;
	RtlSuperCopyMemory(&SDT(ZwSetValueKey), &hookAddr2, 4);    //�ر�

	ULONG hookAddr3 = (ULONG)OldZwSetInformationFile;
	RtlSuperCopyMemory(&SDT(ZwSetInformationFile), &hookAddr3, 4);
}


