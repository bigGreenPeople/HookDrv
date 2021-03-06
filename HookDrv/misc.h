#define ProbeAndReadUnicodeString(Source)  \
    (((Source) >= (UNICODE_STRING * const)MM_USER_PROBE_ADDRESS) ? \
        (*(volatile UNICODE_STRING * const)MM_USER_PROBE_ADDRESS) : (*(volatile UNICODE_STRING *)(Source)))

#define ProbeAndReadObjectAttributes(Source)  \
					(((Source) >= (OBJECT_ATTRIBUTES * const)MM_USER_PROBE_ADDRESS) ? \
						(*( volatile OBJECT_ATTRIBUTES * const)MM_USER_PROBE_ADDRESS) : (*( volatile OBJECT_ATTRIBUTES *)(Source)))

BOOL obQueryObjectName(PVOID pObject, PUNICODE_STRING objName, BOOL allocateName);

BOOL ntGetNameFromObjectAttributes(POBJECT_ATTRIBUTES ObjectAttributes,
	WCHAR * NameBuffer,
	DWORD NameBufferSize);
NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath);
NTSTATUS  GetNameByFullName(PUNICODE_STRING  FullPath);
BOOL  GetRegLastInexByFullName(PUNICODE_STRING  FullPath, int Index);

BOOL ntGetDriverImagePath(PUNICODE_STRING uReg, WCHAR * filepath);
BOOL NTAPI ntGetNtDeviceName(WCHAR * filename, WCHAR * ntname);
BOOL ntIsDosDeviceName(WCHAR * filename);


typedef enum _OBJECT_INFO_CLASS {
	ObjectBasicInfo,
	ObjectNameInfo,
	ObjectTypeInfo,
	ObjectAllTypesInfo,
	ObjectProtectionInfo
} OBJECT_INFO_CLASS;

BOOL MyObQueryObjectName(PVOID pObject, PUNICODE_STRING objName, BOOL allocateName);
BOOL MyProbeKeyHandle(HANDLE KeyHandle, DWORD Access);
