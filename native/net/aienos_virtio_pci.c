/* See aienos_virtio_pci.h. */
#include "aienos_virtio_pci.h"

#include <string.h>

static uint16_t le16(const uint8_t *b) { return (uint16_t)(b[0] | (uint16_t)b[1] << 8); }
static uint32_t le32(const uint8_t *b)
{
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

#define VIRTIO_PCI_MAX_STEPS 48

static virtio_pci_err set_region(virtio_pci_region *slot, virtio_pci_region r)
{
    int dup = slot->present;
    *slot = r; /* Rust Option::replace stores before reporting the duplicate */
    return dup ? VIRTIO_PCI_DUPLICATE_CAPABILITY : VIRTIO_PCI_OK;
}

const char *virtio_pci_err_name(virtio_pci_err e)
{
    switch (e) {
    case VIRTIO_PCI_OK: return "Ok";
    case VIRTIO_PCI_INVALID_CONFIG_LENGTH: return "InvalidConfigLength";
    case VIRTIO_PCI_CAPABILITIES_NOT_PRESENT: return "CapabilitiesNotPresent";
    case VIRTIO_PCI_INVALID_POINTER: return "InvalidPointer";
    case VIRTIO_PCI_CAPABILITY_LOOP: return "CapabilityLoop";
    case VIRTIO_PCI_SHORT_CAPABILITY: return "ShortCapability";
    case VIRTIO_PCI_INVALID_REGION: return "InvalidRegion";
    case VIRTIO_PCI_DUPLICATE_CAPABILITY: return "DuplicateCapability";
    }
    return "Unknown";
}

virtio_pci_err virtio_pci_parse_caps(const uint8_t *config, size_t len, virtio_pci_caps *out)
{
    if (!out) return VIRTIO_PCI_INVALID_CONFIG_LENGTH;
    memset(out, 0, sizeof *out);
    if (!config || (len != 256 && len != 4096)) return VIRTIO_PCI_INVALID_CONFIG_LENGTH;
    if ((le16(config + 0x06) & (1u << 4)) == 0) return VIRTIO_PCI_CAPABILITIES_NOT_PRESENT;

    uint8_t visited[256];
    memset(visited, 0, sizeof visited);
    unsigned steps = 0;
    uint8_t pointer = config[0x34] & (uint8_t)~0x03u;
    while (pointer != 0) {
        size_t index = pointer; /* <= 252, so every bound below is in range of size_t */
        if (index < 0x40 || index + 2 > len) return VIRTIO_PCI_INVALID_POINTER;
        if (visited[index] || steps >= VIRTIO_PCI_MAX_STEPS) return VIRTIO_PCI_CAPABILITY_LOOP;
        visited[index] = 1;
        steps++;

        uint8_t next = config[index + 1] & (uint8_t)~0x03u;
        if (config[index] == 0x09) {
            if (index + 16 > len) return VIRTIO_PCI_SHORT_CAPABILITY;
            size_t cap_len = config[index + 2];
            uint8_t kind = config[index + 3];
            size_t minimum = kind == 2 ? 20 : 16;
            if (cap_len < minimum || index + cap_len > len) return VIRTIO_PCI_SHORT_CAPABILITY;
            virtio_pci_region r = {1, config[index + 4], le32(config + index + 8),
                                   le32(config + index + 12)};
            /* Region checks apply only to the structures this driver maps
             * (cfg_type 1..4). VIRTIO_PCI_CAP_PCI_CFG (5) legally carries
             * bar 0 / offset 0 / length 0 (real QEMU virtio-net-pci does), and
             * the spec tells drivers to ignore cfg types they do not use. The
             * Rust reference checked every vendor cap and so refused real
             * QEMU; AIENOS_VIRTIO_PCI_REFERENCE_COMPAT restores that order for
             * the pinned Rust differential only (tests/net_diff.c). */
#ifdef AIENOS_VIRTIO_PCI_REFERENCE_COMPAT
            int mapped = 1;
#else
            int mapped = kind >= 1 && kind <= 4;
#endif
            if (mapped && (r.bar > 5 || r.length == 0 || r.offset > UINT32_MAX - r.length))
                return VIRTIO_PCI_INVALID_REGION;
            virtio_pci_err e = VIRTIO_PCI_OK;
            switch (kind) {
            case 1: e = set_region(&out->common_cfg, r); break;
            case 2:
                e = set_region(&out->notify_cfg, r);
                if (e) break;
                if (out->has_notify_off_multiplier) { e = VIRTIO_PCI_DUPLICATE_CAPABILITY; break; }
                out->has_notify_off_multiplier = 1;
                out->notify_off_multiplier = le32(config + index + 16);
                break;
            case 3: e = set_region(&out->isr_cfg, r); break;
            case 4: e = set_region(&out->device_cfg, r); break;
            default: break;
            }
            if (e) return e;
        }
        pointer = next;
    }
    return VIRTIO_PCI_OK;
}
