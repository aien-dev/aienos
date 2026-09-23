//! Physical page pool managing accelerator memory allocation and reference counting.

use crate::page::{PageId, PhysicalKvPage, PAGE_KV_BYTES};
use std::collections::HashMap;

/// Pool managing physical KV pages with atomic reference tracking.
#[derive(Default)]
pub struct PhysicalPagePool {
    pages: HashMap<PageId, PhysicalKvPage>,
    next_id: u64,
}

impl PhysicalPagePool {
    /// Initialize an empty physical page pool.
    pub fn new() -> Self {
        Self {
            pages: HashMap::new(),
            next_id: 1,
        }
    }

    /// Allocate a new physical KV page.
    pub fn allocate(&mut self) -> PageId {
        let id = PageId(self.next_id);
        self.next_id += 1;
        self.pages.insert(id, PhysicalKvPage::new(id));
        id
    }

    /// Reference an existing page by ID.
    pub fn get(&self, id: PageId) -> Option<&PhysicalKvPage> {
        self.pages.get(&id)
    }

    /// Mutable reference to an existing page by ID.
    pub fn get_mut(&mut self, id: PageId) -> Option<&mut PhysicalKvPage> {
        self.pages.get_mut(&id)
    }

    /// Increment reference count when sharing a page across branches.
    pub fn retain(&mut self, id: PageId) {
        if let Some(p) = self.pages.get_mut(&id) {
            p.ref_count += 1;
        }
    }

    /// Decrement reference count. If count reaches 0, free page frame immediately.
    pub fn release(&mut self, id: PageId) {
        if let Some(p) = self.pages.get_mut(&id) {
            p.ref_count = p.ref_count.saturating_sub(1);
            if p.ref_count == 0 {
                self.pages.remove(&id);
            }
        }
    }

    /// Perform Copy-On-Write: clone page contents into a new private frame,
    /// decrementing the shared parent's ref_count.
    pub fn clone_on_write(&mut self, source_id: PageId) -> PageId {
        let new_id = PageId(self.next_id);
        self.next_id += 1;

        let mut new_page = PhysicalKvPage::new(new_id);
        if let Some(source) = self.pages.get(&source_id) {
            new_page.tokens = source.tokens;
            new_page.len = source.len;
            new_page.kv_cache = source.kv_cache.clone();
            new_page.recompute_checksum();
        }

        self.release(source_id);
        self.pages.insert(new_id, new_page);
        new_id
    }

    /// Total active physical pages currently residing in accelerator memory.
    pub fn allocated_page_count(&self) -> usize {
        self.pages.len()
    }

    /// Total physical bytes occupied by active KV pages.
    pub fn physical_memory_bytes(&self) -> usize {
        self.pages.len() * PAGE_KV_BYTES
    }
}
