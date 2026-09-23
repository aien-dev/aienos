//! J-Space Worlds: Transactional sandboxes with copy-on-write semantics (§12).

use std::collections::{HashMap, HashSet};

/// State of a J-Space World transactional sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorldStatus {
    Active,
    RolledBack,
    Promoted,
}

/// J-Space World sandbox providing reversible copy-on-write environment.
pub struct JSpaceWorld {
    pub world_id: [u8; 16],
    pub parent_world_id: Option<[u8; 16]>,
    pub delta_fs: HashMap<String, Vec<u8>>,
    pub deleted_files: HashSet<String>,
    pub status: WorldStatus,
}

impl JSpaceWorld {
    /// Instantiate a new isolated World sandbox.
    pub fn new(world_id: [u8; 16], parent_world_id: Option<[u8; 16]>) -> Self {
        Self {
            world_id,
            parent_world_id,
            delta_fs: HashMap::new(),
            deleted_files: HashSet::new(),
            status: WorldStatus::Active,
        }
    }

    /// Read file content, checking delta layer first, falling back to base reader.
    pub fn read_file<F>(&self, path: &str, base_reader: F) -> Option<Vec<u8>>
    where
        F: FnOnce(&str) -> Option<Vec<u8>>,
    {
        if self.deleted_files.contains(path) {
            return None;
        }
        if let Some(content) = self.delta_fs.get(path) {
            return Some(content.clone());
        }
        base_reader(path)
    }

    /// Write file to isolated copy-on-write delta layer.
    pub fn write_file(&mut self, path: impl Into<String>, data: Vec<u8>) {
        if self.status != WorldStatus::Active {
            return;
        }
        let p = path.into();
        self.deleted_files.remove(&p);
        self.delta_fs.insert(p, data);
    }

    /// Mark a file deleted inside this world.
    pub fn delete_file(&mut self, path: &str) {
        if self.status != WorldStatus::Active {
            return;
        }
        self.delta_fs.remove(path);
        self.deleted_files.insert(path.to_string());
    }

    /// Instantaneous rollback via dropping all deltas.
    pub fn rollback(&mut self) {
        self.delta_fs.clear();
        self.deleted_files.clear();
        self.status = WorldStatus::RolledBack;
    }

    /// Mark world as promoted.
    pub fn mark_promoted(&mut self) {
        self.status = WorldStatus::Promoted;
    }
}
