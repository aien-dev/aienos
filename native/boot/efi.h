/* efi.h -- the few UEFI definitions the AIENOS boot stub needs, written from
 * the UEFI 2.10 specification (sections 4.2, 4.3, 4.4, 7.2, 12.4). Only the
 * members we call are typed; the rest are placeholders that keep the layout.
 * AArch64 UEFI uses the normal AAPCS64 calling convention. */
#ifndef AIENOS_EFI_H
#define AIENOS_EFI_H

#include <stddef.h>
#include <stdint.h>

typedef uint16_t CHAR16;
typedef uint64_t EFI_STATUS;
typedef void *EFI_HANDLE;

#define EFI_SUCCESS 0ull
#define EFI_ERR(n) (0x8000000000000000ull | (n))
#define EFI_INVALID_PARAMETER EFI_ERR(2)
#define EFI_BUFFER_TOO_SMALL EFI_ERR(5)

typedef struct {
    uint32_t d1;
    uint16_t d2, d3;
    uint8_t d4[8];
} EFI_GUID;

typedef struct {
    uint64_t Signature;
    uint32_t Revision, HeaderSize, CRC32, Reserved;
} EFI_TABLE_HEADER;

typedef struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    EFI_STATUS (*Reset)(struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, uint8_t);
    EFI_STATUS (*OutputString)(struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, CHAR16 *);
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

/* Memory types (UEFI 2.10 table 7.10). */
enum {
    EfiReservedMemoryType, EfiLoaderCode, EfiLoaderData, EfiBootServicesCode,
    EfiBootServicesData, EfiRuntimeServicesCode, EfiRuntimeServicesData,
    EfiConventionalMemory, EfiUnusableMemory, EfiACPIReclaimMemory,
    EfiACPIMemoryNVS, EfiMemoryMappedIO, EfiMemoryMappedIOPortSpace,
    EfiPalCode, EfiPersistentMemory, EfiUnacceptedMemoryType
};
#define EFI_MEMORY_WB 0x8ull

typedef struct {
    uint32_t Type;
    uint32_t Pad;
    uint64_t PhysicalStart;
    uint64_t VirtualStart;
    uint64_t NumberOfPages;
    uint64_t Attribute;
} EFI_MEMORY_DESCRIPTOR;

typedef struct {
    EFI_TABLE_HEADER Hdr;
    void *RaiseTPL, *RestoreTPL;
    void *AllocatePages, *FreePages;
    EFI_STATUS (*GetMemoryMap)(uint64_t *MapSize, EFI_MEMORY_DESCRIPTOR *Map,
                               uint64_t *MapKey, uint64_t *DescriptorSize,
                               uint32_t *DescriptorVersion);
    void *AllocatePool, *FreePool;
    void *CreateEvent, *SetTimer, *WaitForEvent, *SignalEvent, *CloseEvent, *CheckEvent;
    void *InstallProtocolInterface, *ReinstallProtocolInterface;
    void *UninstallProtocolInterface, *HandleProtocol, *Reserved;
    void *RegisterProtocolNotify, *LocateHandle, *LocateDevicePath;
    void *InstallConfigurationTable;
    void *LoadImage, *StartImage, *Exit, *UnloadImage;
    EFI_STATUS (*ExitBootServices)(EFI_HANDLE ImageHandle, uint64_t MapKey);
    void *GetNextMonotonicCount, *Stall;
    EFI_STATUS (*SetWatchdogTimer)(uint64_t Timeout, uint64_t WatchdogCode,
                                   uint64_t DataSize, CHAR16 *WatchdogData);
} EFI_BOOT_SERVICES;

typedef struct {
    EFI_GUID VendorGuid;
    void *VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef struct {
    EFI_TABLE_HEADER Hdr;
    CHAR16 *FirmwareVendor;
    uint32_t FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    void *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
    EFI_HANDLE StandardErrorHandle;
    void *StdErr;
    void *RuntimeServices;
    EFI_BOOT_SERVICES *BootServices;
    uint64_t NumberOfTableEntries;
    EFI_CONFIGURATION_TABLE *ConfigurationTable;
} EFI_SYSTEM_TABLE;

/* Offsets fixed by the specification (LP64). */
_Static_assert(offsetof(EFI_BOOT_SERVICES, GetMemoryMap) == 0x38, "GetMemoryMap");
_Static_assert(offsetof(EFI_BOOT_SERVICES, ExitBootServices) == 0xe8, "ExitBootServices");
_Static_assert(offsetof(EFI_BOOT_SERVICES, SetWatchdogTimer) == 0x100, "SetWatchdogTimer");
_Static_assert(offsetof(EFI_SYSTEM_TABLE, ConOut) == 0x40, "ConOut");
_Static_assert(offsetof(EFI_SYSTEM_TABLE, BootServices) == 0x60, "BootServices");
_Static_assert(offsetof(EFI_SYSTEM_TABLE, ConfigurationTable) == 0x70, "ConfigurationTable");
_Static_assert(sizeof(EFI_MEMORY_DESCRIPTOR) == 40, "descriptor");

/* EFI_ACPI_20_TABLE_GUID */
#define EFI_ACPI_20_TABLE_GUID_INIT \
    { 0x8868e871, 0xe4f1, 0x11d3, { 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 } }

#endif
