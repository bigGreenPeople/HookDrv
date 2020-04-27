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


NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED *Dst,IN CONST VOID UNALIGNED *Src,IN ULONG Length)
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

	/*OldZwLoadDriver = SDT(ZwLoadDriver);
	ULONG hookAddr = (ULONG)Hook_ZwLoadDriver;
	RtlSuperCopyMemory(&SDT(ZwLoadDriver), &hookAddr, 4);  */  //¹Ø±Õ

	return;
}

void RemoveHook(void)
{
	DbgPrint("RemoveHook \n");

/*	ULONG hookAddr3 = (ULONG)OldZwSetSystemInformation;
	RtlSuperCopyMemory(&SDT(ZwSetSystemInformation), &hookAddr3, 4); */   //¹Ø±Õ
}


