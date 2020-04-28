#include "precomp.h"

#define		DEVICE_NAME		L"\\device\\HookDrv"
#define		LINK_NAME		L"\\dosDevices\\HookDrv"

//�������ͺ�list
//����
LIST_ENTRY g_OperList;
ERESOURCE  g_OperListLock;
//�ȴ�
LIST_ENTRY g_WaitList;
ERESOURCE  g_WaitListLock;
//����
LIST_ENTRY g_PendingIrpList;
ERESOURCE  g_PendingIrpListLock;
//�ȴ���ID ���ڱ�ʶ
ULONG g_ulWaitID = 0;


/*        ���Ͳ���list�ĺ���         */
VOID __stdcall LockWrite(ERESOURCE *lpLock)
{
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(lpLock, TRUE);
}


VOID __stdcall UnLockWrite(ERESOURCE *lpLock)
{
	ExReleaseResourceLite(lpLock);
	KeLeaveCriticalRegion();
}


VOID __stdcall LockRead(ERESOURCE *lpLock)
{
	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(lpLock, TRUE);
}


VOID __stdcall LockReadStarveWriter(ERESOURCE *lpLock)
{
	KeEnterCriticalRegion();
	ExAcquireSharedStarveExclusive(lpLock, TRUE);
}


VOID __stdcall UnLockRead(ERESOURCE *lpLock)
{
	ExReleaseResourceLite(lpLock);
	KeLeaveCriticalRegion();
}


VOID __stdcall InitLock(ERESOURCE *lpLock)
{
	ExInitializeResourceLite(lpLock);
}

VOID __stdcall DeleteLock(ERESOURCE *lpLock)
{
	ExDeleteResourceLite(lpLock);
}

VOID __stdcall InitList(LIST_ENTRY *list)
{
	InitializeListHead(list);
}
/*        ���Ͳ���list�ĺ���end         */


//����Irp
VOID IrpCancel(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	KIRQL				CancelOldIrql = Irp->CancelIrql;

	IoReleaseCancelSpinLock(DISPATCH_LEVEL);
	KeLowerIrql(CancelOldIrql);

	LockWrite(&g_PendingIrpListLock);
	RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
	UnLockWrite(&g_PendingIrpListLock);

	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

//����irp
VOID PendingIrpToList(PIRP lpIrp, PLIST_ENTRY lpIrpList, PDRIVER_CANCEL lpfnCancelRoutine)
{
	InsertTailList(lpIrpList, &lpIrp->Tail.Overlay.ListEntry);
	IoMarkIrpPending(lpIrp);
	IoSetCancelRoutine(lpIrp, lpfnCancelRoutine);
}


//����Ӧ�ò��read()����
NTSTATUS DispatchRead(IN PDEVICE_OBJECT	pDevObj, IN PIRP	lpIrp)
{
	NTSTATUS			ntStatus = STATUS_SUCCESS;
	ULONG				ulLength = 0;
	PIO_STACK_LOCATION	lpIrpStack = IoGetCurrentIrpStackLocation(lpIrp);
	OP_INFO				*lpOpInfoEntry = NULL;
	LIST_ENTRY			*lpOpInfoList = NULL;

	//�ж϶��Ĵ�С�Ƿ���RING3_OP_INFO
	if (lpIrpStack->Parameters.Read.Length < sizeof(RING3_OP_INFO))
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		ulLength = 0;
		goto Completed;
	}
	//����g_OperList
	LockWrite(&g_OperListLock);

	//����ɲ�����g_OperListΪ�վ͹���irp����
	if (IsListEmpty(&g_OperList) == TRUE)
	{
		UnLockWrite(&g_OperListLock);

		LockWrite(&g_PendingIrpListLock);
		PendingIrpToList(lpIrp, &g_PendingIrpList, IrpCancel);
		UnLockWrite(&g_PendingIrpListLock);

		goto Pended;
	}

	lpOpInfoList = g_OperList.Flink;
	//�õ�lpOpInfoEntry
	lpOpInfoEntry = CONTAINING_RECORD(lpOpInfoList, OP_INFO, m_List);
	//�Ƴ�lpOpInfoEntry
	RemoveEntryList(lpOpInfoList);
	UnLockWrite(&g_OperListLock);
	//д��lpOpInfoEntry����Ϣ
	RtlCopyMemory(lpIrp->AssociatedIrp.SystemBuffer, lpOpInfoEntry, sizeof(RING3_OP_INFO));
	ntStatus = STATUS_SUCCESS;
	ulLength = sizeof(RING3_OP_INFO);

	ExFreePool(lpOpInfoEntry);

Completed:

	lpIrp->IoStatus.Status = ntStatus;
	lpIrp->IoStatus.Information = ulLength;
	IoCompleteRequest(lpIrp, IO_NO_INCREMENT);
	return ntStatus;

Pended:
	return STATUS_PENDING;
}

//ͨ��ulWaitID��ѯ��Entry
WAIT_LIST_ENTRY* FindWaitEntryByID(PLIST_ENTRY ListHead, ULONG ulWaitID)
{
	PLIST_ENTRY			pList = NULL;
	WAIT_LIST_ENTRY		*pEntry = NULL;
	//ѭ������
	for (pList = ListHead->Flink; pList != ListHead; pList = pList->Flink)
	{
		pEntry = CONTAINING_RECORD(pList, WAIT_LIST_ENTRY, m_List);
		if (pEntry->m_ulWaitID == ulWaitID)
		{
			return pEntry;
		}
	}
	return NULL;
}

//�����ȴ�id
ULONG MakeWaitID()
{
	InterlockedIncrement(&g_ulWaitID);
	return g_ulWaitID;
}

//��ɹ���Irp
BOOLEAN CompletePendingIrp(LIST_ENTRY* pIrpListHead, OP_INFO* lpOpInfo)
{
	LIST_ENTRY			*pIrpList = NULL;
	PIRP				pIrp = NULL;
	BOOLEAN				bFound = FALSE;
	BOOLEAN				bRet = FALSE;

	if (IsListEmpty(pIrpListHead) == TRUE)
	{
		return bRet;
	}

	for (pIrpList = pIrpListHead->Flink; pIrpList != pIrpListHead; pIrpList = pIrpList->Flink)
	{
		pIrp = CONTAINING_RECORD(pIrpList, IRP, Tail.Overlay.ListEntry);
		//��ȡ����������ΪNULL
		if (IoSetCancelRoutine(pIrp, NULL))
		{
			//ɾ��
			RemoveEntryList(pIrpList);
			bFound = TRUE;
			break;
		}
	}

	if (bFound == FALSE)
	{
		return bRet;
	}

	RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, lpOpInfo, sizeof(RING3_OP_INFO));

	pIrp->IoStatus.Information = sizeof(RING3_OP_INFO);
	pIrp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	bRet = TRUE;

	return bRet;
}

R3_RESULT __stdcall GetResultFromUser(PWCH processName)
{
	R3_RESULT			NotifyResult = R3Result_Pass;
	BOOLEAN				bSuccess = FALSE;
	NTSTATUS			Status = STATUS_SUCCESS;
	LARGE_INTEGER		WaitTimeOut = { 0 };
	OP_INFO				*lpNewOpInfo = NULL;
	WAIT_LIST_ENTRY		*lpNewWaitEntry = NULL;
	ULONG_PTR ulPtr = 0;
	UNICODE_STRING pPath = { 0 };
	WCHAR	szCopiedStr[1024] = L"";
	HANDLE ProcessHandle = NULL;

	
	lpNewOpInfo = (OP_INFO*)ExAllocatePool(PagedPool, sizeof(OP_INFO));

	if (lpNewOpInfo == NULL)
	{
		return NotifyResult;
	}
	RtlInitUnicodeString(&pPath, szCopiedStr);
	pPath.MaximumLength = sizeof(szCopiedStr);

	ProcessHandle = PsGetCurrentProcessId();

	//�����¼���ص����ݣ����͸�R3���������ID�����֣�·�����Լ�����������������޸ģ�ɾ�����ȵ�
	//��Ȼ���������ֻ�Ǽ򵥵Ĳ�׽�˽��̵�ID�������ֵ�
	ulPtr = (ULONG_PTR)ProcessHandle;
	

	lpNewOpInfo->m_ulProcessID = (ULONG_PTR)ulPtr;
	//���������Ľ���
	if (processName != NULL){
		RtlCopyMemory(lpNewOpInfo->m_ProcessName, processName, MAX_PATH);
	}
	else
	{
		GetProcessFullNameByPid(ProcessHandle, &pPath);
		RtlCopyMemory(lpNewOpInfo->m_ProcessName, pPath.Buffer, pPath.Length);
	}

	lpNewOpInfo->m_ulWaitID = MakeWaitID();//����ͬ�¼���ID


	lpNewWaitEntry = (WAIT_LIST_ENTRY*)ExAllocatePool(NonPagedPool, sizeof(WAIT_LIST_ENTRY));
	if (lpNewWaitEntry == NULL)
	{
		goto End;
	}

	lpNewWaitEntry->m_ulWaitID = lpNewOpInfo->m_ulWaitID;
	// ��ʼ��ͬ�� �¼�
	KeInitializeEvent(&lpNewWaitEntry->m_ulWaitEvent, SynchronizationEvent, FALSE);

	// ����ȴ����У��ȴ�R3�·����
	LockWrite(&g_WaitListLock);
	InsertTailList(&g_WaitList, &lpNewWaitEntry->m_List);
	UnLockWrite(&g_WaitListLock);

	// ��40�룬��3��30�볬ʱ
	WaitTimeOut.QuadPart = -40 * 10000000;

	LockWrite(&g_PendingIrpListLock);
	bSuccess = CompletePendingIrp(&g_PendingIrpList, lpNewOpInfo);//�鿴�Ƿ���δ��ɵ�pendingIRP��ֱ�ӽ���OperInfo����R3
	UnLockWrite(&g_PendingIrpListLock);

	//�ж�g_PendingIrpList�������ΪNull
	if (bSuccess == FALSE)	//���pending irpʧ�ܣ���lpNewOpInfo����operlist
	{
		LockWrite(&g_OperListLock);
		InsertTailList(&g_OperList, &lpNewOpInfo->m_List); //����OperList,�ȴ�R3����ȡ
		UnLockWrite(&g_OperListLock);

		lpNewOpInfo = NULL;
	}

	Status = KeWaitForSingleObject(&lpNewWaitEntry->m_ulWaitEvent,
		Executive, KernelMode, FALSE, &WaitTimeOut);//�ȴ�R3�·��������ֹ����
	//R3����˲���
	LockWrite(&g_WaitListLock);
	RemoveEntryList(&lpNewWaitEntry->m_List);
	UnLockWrite(&g_WaitListLock);

	if (Status != STATUS_TIMEOUT)
	{
		if (lpNewWaitEntry->m_bBlocked == TRUE)
		{
			NotifyResult = R3Result_Block;
		}
		else
		{
			NotifyResult = R3Result_Pass;
		}
	}
	else
	{
		NotifyResult = R3Result_DefaultNon;
	}

End:
	if (lpNewWaitEntry != NULL)
	{
		ExFreePool(lpNewWaitEntry);
	}
	if (lpNewOpInfo != NULL)
	{
		ExFreePool(lpNewOpInfo);
	}
	return NotifyResult;
}


//����Ӧ�ò��DeviceIoControl()
NTSTATUS DispatchControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION      	lpIrpStack = NULL;
	PVOID                   	inputBuffer = NULL;
	PVOID                   	outputBuffer = NULL;
	ULONG                   	inputBufferLength = 0;
	ULONG                   	outputBufferLength = 0;
	ULONG                   	ioControlCode = 0;
	NTSTATUS		     		ntStatus = STATUS_SUCCESS;

	ntStatus = Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	//��ȡ��ǰIRP��ջλ��
	lpIrpStack = IoGetCurrentIrpStackLocation(Irp);
	//������뻺��ͳ���
	inputBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = lpIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//����������ͳ���
	outputBuffer = Irp->AssociatedIrp.SystemBuffer;
	outputBufferLength = lpIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	//��ȡ������
	ioControlCode = lpIrpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (ioControlCode)
	{
	case IOCTL_SEND_RESULT_TO_R0://R3���ں˴��ݵ������������Ӧ��WaitID�¼������û�ѡ����
	{
		RING3_REPLY			*lpReply = NULL;
		WAIT_LIST_ENTRY		*lpWaitEntry = NULL;

		if (lpIrpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(RING3_REPLY))
		{
			Irp->IoStatus.Information = 0;
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			break;
		}
		lpReply = (RING3_REPLY*)Irp->AssociatedIrp.SystemBuffer;

		LockWrite(&g_WaitListLock);
		lpWaitEntry = FindWaitEntryByID(&g_WaitList, lpReply->m_ulWaitID);//����WaitID���ҵ���Ӧ�������¼�

		if (lpWaitEntry != NULL)
		{
			lpWaitEntry->m_bBlocked = lpReply->m_ulBlocked;
			KeSetEvent(&lpWaitEntry->m_ulWaitEvent, 0, FALSE);//����EVENT�¼�������GetResultFromUser()��ĵȴ��¼�
		}

		UnLockWrite(&g_WaitListLock);

		Irp->IoStatus.Information = 0;
		ntStatus = Irp->IoStatus.Status = STATUS_SUCCESS;
	}
	break;

	case IOCTL_XXX_ATTACK://��������ģ��
	{
		R3_RESULT notifyResult = R3Result_DefaultNon;


		notifyResult = GetResultFromUser(NULL);//��R3��õ�����������ֹ���ǷŹ�
		if (notifyResult == R3Result_Block)
		{
			DbgPrint("��ֹ\n");
			*(ULONG *)outputBuffer = 0;
			ntStatus = STATUS_SUCCESS;
		}
		else if (notifyResult == R3Result_Pass)
		{
			DbgPrint("����\n");
			*(ULONG *)outputBuffer = 1;
			ntStatus = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("��ʱ����\n");
			*(ULONG *)outputBuffer = 1;
			ntStatus = STATUS_SUCCESS;
		}

	}
	Irp->IoStatus.Information = sizeof(ULONG);
	Irp->IoStatus.Status = ntStatus;
	break;

	default:
		break;
	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
}

//����Unload��������
VOID DriverUnload(
	IN PDRIVER_OBJECT	pDriverObject)
{
	UNICODE_STRING         deviceLink = { 0 };

	RemoveHook();

	DeleteLock(&g_OperListLock);
	DeleteLock(&g_WaitListLock);
	DeleteLock(&g_PendingIrpListLock);

	RtlInitUnicodeString(&deviceLink, LINK_NAME);
	IoDeleteSymbolicLink(&deviceLink);
	IoDeleteDevice(pDriverObject->DeviceObject);


	return;
}

//����Ӧ�ò��create()����
NTSTATUS DispatchCreate(
	IN PDEVICE_OBJECT	pDevObj,
	IN PIRP	pIrp)
{
	//����IO״̬��Ϣ
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	//���IRP�����������²���������
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//����Ӧ�ò��close()����
NTSTATUS DispatchClose(
	IN PDEVICE_OBJECT	pDevObj,
	IN PIRP	pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//����������ڣ���ɸ��ֳ�ʼ�������������豸����
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS 		status = STATUS_SUCCESS;
	PDEVICE_OBJECT 	pDevObj = NULL;
	UNICODE_STRING 	uDevName = { 0 };
	UNICODE_STRING 	uLinkName = { 0 };
	DbgPrint("Driver Load begin!\n");

	InitLock(&g_OperListLock);
	InitLock(&g_WaitListLock);
	InitLock(&g_PendingIrpListLock);

	InitList(&g_OperList);
	InitList(&g_WaitList);
	InitList(&g_PendingIrpList);


	//��ʼ����������

	pDriverObject->MajorFunction[IRP_MJ_CREATE] =
		DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
		DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_READ] =
		DispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
		DispatchControl;
	pDriverObject->DriverUnload =
		DriverUnload;

	RtlInitUnicodeString(&uDevName, DEVICE_NAME);
	//���������豸
	status = IoCreateDevice(pDriverObject,
		0,//sizeof(DEVICE_EXTENSION)
		&uDevName,
		FILE_DEVICE_UNKNOWN,
		0, FALSE,
		&pDevObj);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateDevice Failed:%x\n", status);
		return status;
	}

	pDevObj->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&uLinkName, LINK_NAME);
	//������������
	status = IoCreateSymbolicLink(&uLinkName, &uDevName);
	if (!NT_SUCCESS(status))
	{
		//STATUS_INSUFFICIENT_RESOURCES 	��Դ����
		//STATUS_OBJECT_NAME_EXISTS 		ָ������������
		//STATUS_OBJECT_NAME_COLLISION 	�������г�ͻ
		DbgPrint("IoCreateSymbolicLink Failed:%x\n", status);
		IoDeleteDevice(pDevObj);
		return status;
	}
	StartHook();

	DbgPrint("Driver Load success!\n");
	return status;
}
