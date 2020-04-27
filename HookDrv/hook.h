void StartHook(void);
void RemoveHook(void);

NTSTATUS
NTAPI HOOK_NtCreateSection(
	OUT PHANDLE             SectionHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER       MaximumSize OPTIONAL,
	IN ULONG                SectionPageProtection,
	IN ULONG                AllocationAttributes,
	IN HANDLE               FileHandle OPTIONAL
);

typedef struct LpcMessage {

	USHORT     DataLength;
	USHORT     Length;
	USHORT     MessageType;
	USHORT     DataInfoOffset;
	CLIENT_ID  ClientId;
	ULONG      MessageId;
	ULONG      CallbackId;
	BYTE       MessageData[150];
} LPCMESSAGE, *PLPCMESSAGE;
//messgetype ∫Í∂®“Â
#define UNUSED_MSG_TYPE                 0
#define LPC_REQUEST                     1
#define LPC_REPLY                       2
#define LPC_DATAGRAM                    3
#define LPC_LOST_REPLY                  4
#define LPC_PORT_CLOSED                 5
#define LPC_CLIENT_DIED                 6
#define LPC_EXCEPTION                   7
#define LPC_DEBUG_EVENT                 8
#define LPC_ERROR_EVENT                 9
#define LPC_CONNECTION_REQUEST         10