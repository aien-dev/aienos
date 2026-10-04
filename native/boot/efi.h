/* efi.h -- the slice of UEFI the AIENOS C boot stub uses: system table,
 * boot services it calls (GetMemoryMap, ExitBootServices, SetWatchdogTimer,
 * AllocatePages, FreePages, FreePool, HandleProtocol, LocateHandleBuffer),
 * the Loaded Image, Simple File System and Block I/O protocols (model ingest,
 * efi_model.c). Field orders and offsets follow UEFI 2.10 (edk2
 * MdePkg/Include/Uefi/UefiSpec.h, Protocol/BlockIo.h, SimpleFileSystem.h,
 * LoadedImage.h); _Static_asserts below pin the offsets this stub relies on.
 * Everything not used is a void pointer placeholder of the right size. */
#ifndef AIENOS_CK_EFI_H
#define AIENOS_CK_EFI_H
#include <stdint.h>
#include <stddef.h>

typedef uint16_t CHAR16;
typedef uint64_t EFI_STATUS;
typedef void *EFI_HANDLE;

#define EFI_SUCCESS 0ull
#define EFI_ERR(n) (0x8000000000000000ull | (n))
#define EFI_INVALID_PARAMETER EFI_ERR(2)
#define EFI_BUFFER_TOO_SMALL EFI_ERR(5)
#define EFI_DEVICE_ERROR EFI_ERR(7)
#define EFI_OUT_OF_RESOURCES EFI_ERR(9)
#define EFI_NOT_FOUND EFI_ERR(14)

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

/* EFI_ALLOCATE_TYPE and EFI_LOCATE_SEARCH_TYPE (UefiSpec.h). */
typedef enum { AllocateAnyPages, AllocateMaxAddress, AllocateAddress, MaxAllocateType } EFI_ALLOCATE_TYPE;
typedef enum { AllHandles, ByRegisterNotify, ByProtocol } EFI_LOCATE_SEARCH_TYPE;

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
    EFI_STATUS (*AllocatePages)(EFI_ALLOCATE_TYPE Type, uint32_t MemoryType, uint64_t Pages,
                                uint64_t *Memory);
    EFI_STATUS (*FreePages)(uint64_t Memory, uint64_t Pages);
    EFI_STATUS (*GetMemoryMap)(uint64_t *MapSize, EFI_MEMORY_DESCRIPTOR *Map,
                               uint64_t *MapKey, uint64_t *DescriptorSize,
                               uint32_t *DescriptorVersion);
    void *AllocatePool;
    EFI_STATUS (*FreePool)(void *Buffer);
    void *CreateEvent, *SetTimer, *WaitForEvent, *SignalEvent, *CloseEvent, *CheckEvent;
    void *InstallProtocolInterface, *ReinstallProtocolInterface;
    void *UninstallProtocolInterface;
    EFI_STATUS (*HandleProtocol)(EFI_HANDLE Handle, const EFI_GUID *Protocol, void **Interface);
    void *Reserved;
    void *RegisterProtocolNotify, *LocateHandle, *LocateDevicePath;
    void *InstallConfigurationTable;
    void *LoadImage, *StartImage, *Exit, *UnloadImage;
    EFI_STATUS (*ExitBootServices)(EFI_HANDLE ImageHandle, uint64_t MapKey);
    void *GetNextMonotonicCount, *Stall;
    EFI_STATUS (*SetWatchdogTimer)(uint64_t Timeout, uint64_t WatchdogCode,
                                   uint64_t DataSize, CHAR16 *WatchdogData);
    void *ConnectController, *DisconnectController;
    void *OpenProtocol, *CloseProtocol, *OpenProtocolInformation, *ProtocolsPerHandle;
    EFI_STATUS (*LocateHandleBuffer)(EFI_LOCATE_SEARCH_TYPE SearchType, const EFI_GUID *Protocol,
                                     void *SearchKey, uint64_t *NoHandles, EFI_HANDLE **Buffer);
    void *LocateProtocol;
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
_Static_assert(offsetof(EFI_BOOT_SERVICES, AllocatePages) == 0x28, "AllocatePages");
_Static_assert(offsetof(EFI_BOOT_SERVICES, GetMemoryMap) == 0x38, "GetMemoryMap");
_Static_assert(offsetof(EFI_BOOT_SERVICES, FreePool) == 0x48, "FreePool");
_Static_assert(offsetof(EFI_BOOT_SERVICES, HandleProtocol) == 0x98, "HandleProtocol");
_Static_assert(offsetof(EFI_BOOT_SERVICES, ExitBootServices) == 0xe8, "ExitBootServices");
_Static_assert(offsetof(EFI_BOOT_SERVICES, SetWatchdogTimer) == 0x100, "SetWatchdogTimer");
_Static_assert(offsetof(EFI_BOOT_SERVICES, LocateHandleBuffer) == 0x138, "LocateHandleBuffer");
_Static_assert(offsetof(EFI_SYSTEM_TABLE, ConOut) == 0x40, "ConOut");
_Static_assert(offsetof(EFI_SYSTEM_TABLE, BootServices) == 0x60, "BootServices");
_Static_assert(offsetof(EFI_SYSTEM_TABLE, ConfigurationTable) == 0x70, "ConfigurationTable");
_Static_assert(sizeof(EFI_MEMORY_DESCRIPTOR) == 40, "descriptor");

/* EFI_ACPI_20_TABLE_GUID */
#define EFI_ACPI_20_TABLE_GUID_INIT \
    { 0x8868e871, 0xe4f1, 0x11d3, { 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 } }

/* --- Loaded Image (UEFI 2.10 section 9.1) --- */
#define EFI_LOADED_IMAGE_PROTOCOL_GUID_INIT \
    { 0x5B1B31A1, 0x9562, 0x11d2, { 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } }
typedef struct {
    uint32_t Revision;
    EFI_HANDLE ParentHandle;
    EFI_SYSTEM_TABLE *SystemTable;
    EFI_HANDLE DeviceHandle; /* the device handle that the EFI Image was loaded from */
    void *FilePath;
    void *Reserved;
    uint32_t LoadOptionsSize;
    void *LoadOptions;
    void *ImageBase;
    uint64_t ImageSize;
    uint32_t ImageCodeType, ImageDataType;
    void *Unload;
} EFI_LOADED_IMAGE_PROTOCOL;
_Static_assert(offsetof(EFI_LOADED_IMAGE_PROTOCOL, DeviceHandle) == 0x18, "DeviceHandle");

/* --- Simple File System + File (UEFI 2.10 section 13.4, 13.5) --- */
#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID_INIT \
    { 0x964e5b22, 0x6459, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } }
#define EFI_FILE_MODE_READ 0x0000000000000001ull
typedef struct EFI_FILE_PROTOCOL {
    uint64_t Revision;
    EFI_STATUS (*Open)(struct EFI_FILE_PROTOCOL *This, struct EFI_FILE_PROTOCOL **NewHandle,
                       CHAR16 *FileName, uint64_t OpenMode, uint64_t Attributes);
    EFI_STATUS (*Close)(struct EFI_FILE_PROTOCOL *This);
    void *Delete;
    EFI_STATUS (*Read)(struct EFI_FILE_PROTOCOL *This, uint64_t *BufferSize, void *Buffer);
    void *Write, *GetPosition, *SetPosition, *GetInfo, *SetInfo, *Flush;
    void *OpenEx, *ReadEx, *WriteEx, *FlushEx;
} EFI_FILE_PROTOCOL;
typedef struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
    uint64_t Revision;
    EFI_STATUS (*OpenVolume)(struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *This, EFI_FILE_PROTOCOL **Root);
} EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;
_Static_assert(offsetof(EFI_FILE_PROTOCOL, Read) == 0x20, "File.Read");

/* --- Block I/O (UEFI 2.10 section 13.9) --- */
#define EFI_BLOCK_IO_PROTOCOL_GUID_INIT \
    { 0x964e5b21, 0x6459, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } }
typedef struct {
    uint32_t MediaId;
    uint8_t RemovableMedia;
    uint8_t MediaPresent;
    uint8_t LogicalPartition; /* TRUE if LBA 0 is the first block of a partition */
    uint8_t ReadOnly;
    uint8_t WriteCaching;
    uint32_t BlockSize;       /* ReadBlocks BufferSize must be a multiple of this */
    uint32_t IoAlign;         /* alignment requirement for any buffer to read or write */
    uint64_t LastBlock;
    uint64_t LowestAlignedLba;                 /* Revision 2 */
    uint32_t LogicalBlocksPerPhysicalBlock;    /* Revision 2 */
    uint32_t OptimalTransferLengthGranularity; /* Revision 3 */
} EFI_BLOCK_IO_MEDIA;
typedef struct EFI_BLOCK_IO_PROTOCOL {
    uint64_t Revision;
    EFI_BLOCK_IO_MEDIA *Media;
    void *Reset;
    EFI_STATUS (*ReadBlocks)(struct EFI_BLOCK_IO_PROTOCOL *This, uint32_t MediaId, uint64_t Lba,
                             uint64_t BufferSize, void *Buffer);
    void *WriteBlocks, *FlushBlocks;
} EFI_BLOCK_IO_PROTOCOL;
_Static_assert(offsetof(EFI_BLOCK_IO_MEDIA, BlockSize) == 12, "Media.BlockSize");
_Static_assert(offsetof(EFI_BLOCK_IO_MEDIA, LastBlock) == 24, "Media.LastBlock");
_Static_assert(offsetof(EFI_BLOCK_IO_PROTOCOL, ReadBlocks) == 0x18, "BlockIo.ReadBlocks");

#endif
