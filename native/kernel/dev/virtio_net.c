/* virtio_net.c -- virtio-net discovery (see virtio_net.h). Freestanding. */
#include "virtio_net.h"
#include "ck.h"

static uint8_t cfg_image[4096];

int ck_virtio_net_probe(const pci_system *pci, virtio_pci_caps *caps, const pci_func **func_out)
{
    if (func_out) *func_out = 0;
    const pci_func *f = pci_find_id(pci, 0x1af4u, 0x1041u);
    if (!f) {
        f = pci_find_id(pci, 0x1af4u, 0x1000u); /* transitional: subsystem 1 = net */
        if (f && f->subsys_id != 1u) f = 0;
    }
    if (!f) {
        ck_printf("virtio_net: not bound (no virtio-net function)\n");
        return 0;
    }
    for (uint32_t off = 0; off < sizeof cfg_image; off += 4) {
        uint32_t v = pci_r32(f->cfg, off);
        cfg_image[off] = (uint8_t)v;
        cfg_image[off + 1] = (uint8_t)(v >> 8);
        cfg_image[off + 2] = (uint8_t)(v >> 16);
        cfg_image[off + 3] = (uint8_t)(v >> 24);
    }
    virtio_pci_err e = virtio_pci_parse_caps(cfg_image, sizeof cfg_image, caps);
    if (e != VIRTIO_PCI_OK) {
        ck_printf("virtio_net: %02x:%02x.%u caps refused (%s)\n", f->bus, f->dev, f->fn, virtio_pci_err_name(e));
        ck_printf("virtio_net: not bound (capability parse failed)\n");
        return (int)e;
    }
    ck_printf("virtio_net: %02x:%02x.%u caps ok common=bar%u+0x%x notify=bar%u+0x%x mult=%u isr=bar%u+0x%x device=bar%u+0x%x\n",
              f->bus, f->dev, f->fn, caps->common_cfg.bar, caps->common_cfg.offset, caps->notify_cfg.bar,
              caps->notify_cfg.offset, caps->notify_off_multiplier, caps->isr_cfg.bar, caps->isr_cfg.offset,
              caps->device_cfg.bar, caps->device_cfg.offset);
    if (func_out) *func_out = f;
    return 0;
}
