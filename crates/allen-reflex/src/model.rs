//! Label scorers. All three read the same feature list.
//!
//! - [`HvModel`]: hypervector exemplar memory + ternary class prototypes (the REFLEX core).
//! - [`NearestModel`]: nearest exemplar over the sparse feature sets, no hypervectors (ablation).
//! - [`PerceptronModel`]: averaged multiclass perceptron over the sparse features (baseline).

use crate::action::{Action, N_LABELS};
use crate::features::Feat;
use crate::hv;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// What a scorer says about one request.
#[derive(Clone, Debug)]
pub struct Scores {
    /// per-label score (higher is better); labels without any training example get -9
    pub s: [f32; N_LABELS],
    /// similarity of the single nearest exemplar (1.0 for the perceptron, which has none)
    pub best_sim: f32,
    /// index of the nearest exemplar
    pub nearest: Option<usize>,
    /// share of the top-k neighbours that carry the top label (1.0 for the perceptron)
    pub agree: f32,
}

impl Scores {
    fn empty() -> Scores {
        Scores {
            s: [-9.0; N_LABELS],
            best_sim: 0.0,
            nearest: None,
            agree: 1.0,
        }
    }
}

/// Memory is full: the caller should run `sleep()` (which merges near duplicates).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryFull;

/// A pair of exemplars with different labels that look alike.
#[derive(Clone, Debug)]
pub struct Conflict {
    /// first exemplar index (after consolidation)
    pub a: usize,
    /// second exemplar index
    pub b: usize,
    /// their similarity
    pub sim: f32,
}

/// Result of `sleep()`.
#[derive(Clone, Debug, Default)]
pub struct SleepReport {
    /// exemplars removed as near duplicates of an earlier one with the same label
    pub merged: usize,
    /// exemplars kept
    pub kept: usize,
    /// label conflicts, most similar first, at most [`MAX_CONFLICTS`]
    pub conflicts: Vec<Conflict>,
    /// retraining passes run
    pub passes: u32,
}

/// Bound on conflicts reported by one sleep.
pub const MAX_CONFLICTS: usize = 32;
/// Bound on the explanation note kept per exemplar (bytes).
pub const NOTE_BYTES: usize = 96;

fn short(note: &str) -> String {
    let mut n = NOTE_BYTES.min(note.len());
    while !note.is_char_boundary(n) {
        n -= 1;
    }
    String::from(&note[..n])
}

/// Hypervector settings.
#[derive(Clone, Copy, Debug)]
pub struct HvConfig {
    /// u64 words per vector (128 = 8192 bits)
    pub words: usize,
    /// exemplars per label averaged for the k-NN part
    pub k: usize,
    /// weight of the k-NN part (the prototype part gets 1 - alpha)
    pub alpha: f32,
    /// ternary zero band, in standard deviations of a class's counters
    pub zero_band: f32,
    /// retraining passes (at most)
    pub epochs: u32,
    /// retraining rate
    pub eta: f32,
    /// exemplar capacity
    pub max_exemplars: usize,
}

/// Counter scale of one exemplar in a prototype.
const SCALE: f32 = 64.0;

/// Hypervector exemplar memory with ternary prototypes.
#[derive(Clone)]
pub struct HvModel {
    /// settings
    pub cfg: HvConfig,
    hvs: Vec<u64>,
    labels: Vec<u8>,
    notes: Vec<String>,
    counts: Vec<i32>,
    sign: Vec<u64>,
    mask: Vec<u64>,
    nnz: [u32; N_LABELS],
    n_label: [u32; N_LABELS],
}

impl HvModel {
    /// Empty memory.
    pub fn new(cfg: HvConfig) -> HvModel {
        let d = cfg.words * 64;
        HvModel {
            cfg,
            hvs: Vec::with_capacity(cfg.max_exemplars * cfg.words),
            labels: Vec::with_capacity(cfg.max_exemplars),
            notes: Vec::with_capacity(cfg.max_exemplars),
            counts: vec![0; N_LABELS * d],
            sign: vec![0; N_LABELS * cfg.words],
            mask: vec![0; N_LABELS * cfg.words],
            nnz: [0; N_LABELS],
            n_label: [0; N_LABELS],
        }
    }

    /// Number of exemplars.
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// True when no exemplar is stored.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Exemplar label and note.
    pub fn exemplar(&self, i: usize) -> (Action, &str) {
        (Action::from_idx(self.labels[i] as usize), &self.notes[i])
    }

    /// Encode features into a fresh vector.
    pub fn encode(&self, feats: &[Feat]) -> Vec<u64> {
        let w = self.cfg.words;
        let mut out = vec![0u64; w];
        let mut cnt = vec![0i32; w * 64];
        let mut acc = vec![0u64; w];
        let mut tmp = vec![0u64; w];
        hv::encode(feats, &mut out, &mut cnt, &mut acc, &mut tmp);
        out
    }

    fn hv(&self, i: usize) -> &[u64] {
        &self.hvs[i * self.cfg.words..(i + 1) * self.cfg.words]
    }

    /// Bytes held (vectors, counters, prototypes, notes; capacity-based).
    pub fn bytes(&self) -> usize {
        self.hvs.capacity() * 8
            + self.labels.capacity()
            + self.notes.iter().map(|n| n.capacity() + 24).sum::<usize>()
            + self.counts.len() * 4
            + (self.sign.len() + self.mask.len()) * 8
    }

    /// Store one exemplar (vector already encoded). Prototypes are not touched.
    pub fn push(&mut self, q: &[u64], label: Action, note: &str) -> Result<usize, MemoryFull> {
        if self.labels.len() >= self.cfg.max_exemplars {
            return Err(MemoryFull);
        }
        self.hvs.extend_from_slice(q);
        self.labels.push(label.idx() as u8);
        self.notes.push(short(note));
        self.n_label[label.idx()] += 1;
        Ok(self.labels.len() - 1)
    }

    fn add_counts(&mut self, l: usize, q: &[u64], wt: i32) {
        let d = self.cfg.words * 64;
        let c = &mut self.counts[l * d..(l + 1) * d];
        for (x, &v) in q.iter().enumerate() {
            for b in 0..64 {
                let bit = ((v >> b) & 1) as i32;
                c[x * 64 + b] += (2 * bit - 1) * wt;
            }
        }
    }

    fn quantize(&mut self, l: usize) {
        let w = self.cfg.words;
        let d = w * 64;
        let c = &self.counts[l * d..(l + 1) * d];
        let mean = c.iter().map(|&x| x as f32).sum::<f32>() / d as f32;
        let var = c
            .iter()
            .map(|&x| {
                let t = x as f32 - mean;
                t * t
            })
            .sum::<f32>()
            / d as f32;
        let band = self.cfg.zero_band * hv::sqrtf(var);
        let mut nnz = 0u32;
        for x in 0..w {
            let mut s = 0u64;
            let mut m = 0u64;
            for b in 0..64 {
                let v = c[x * 64 + b] as f32;
                if v > 0.0 {
                    s |= 1 << b;
                }
                if v > band || -v > band {
                    m |= 1 << b;
                }
            }
            self.sign[l * w + x] = s;
            self.mask[l * w + x] = m;
            nnz += m.count_ones();
        }
        self.nnz[l] = nnz;
    }

    /// Cosine-like similarity of a binary query with the ternary prototype of `l`.
    pub fn proto_sim(&self, q: &[u64], l: usize) -> f32 {
        if self.n_label[l] == 0 || self.nnz[l] == 0 {
            return -1.0;
        }
        let w = self.cfg.words;
        let mut agree = 0i64;
        let mut dis = 0i64;
        for x in 0..w {
            let m = self.mask[l * w + x];
            let diff = q[x] ^ self.sign[l * w + x];
            dis += (diff & m).count_ones() as i64;
            agree += (!diff & m).count_ones() as i64;
        }
        let d = (w * 64) as f32;
        (agree - dis) as f32 / hv::sqrtf(self.nnz[l] as f32 * d)
    }

    fn proto_argmax(&self, q: &[u64]) -> (usize, [f32; N_LABELS]) {
        let mut s = [-9.0f32; N_LABELS];
        for (l, sl) in s.iter_mut().enumerate() {
            if self.n_label[l] > 0 {
                *sl = self.proto_sim(q, l);
            }
        }
        (argmax(&s), s)
    }

    /// Rebuild prototypes from all exemplars: one bundling pass, then retraining passes with
    /// the ternary model in the loop (OnlineHD-style weights). Returns passes run.
    pub fn rebuild(&mut self) -> u32 {
        for c in self.counts.iter_mut() {
            *c = 0;
        }
        let w = self.cfg.words;
        for i in 0..self.len() {
            let l = self.labels[i] as usize;
            let q: Vec<u64> = self.hvs[i * w..(i + 1) * w].to_vec();
            self.add_counts(l, &q, SCALE as i32);
        }
        for l in 0..N_LABELS {
            self.quantize(l);
        }
        let mut passes = 0;
        for _ in 0..self.cfg.epochs {
            passes += 1;
            let mut errors = 0;
            for i in 0..self.len() {
                let y = self.labels[i] as usize;
                let q: Vec<u64> = self.hvs[i * w..(i + 1) * w].to_vec();
                let (p, s) = self.proto_argmax(&q);
                if p != y {
                    errors += 1;
                    let wy = (self.cfg.eta * (1.0 - s[y]) * SCALE) as i32;
                    let wp = (self.cfg.eta * (1.0 - s[p]) * SCALE) as i32;
                    self.add_counts(y, &q, wy.max(1));
                    self.add_counts(p, &q, -wp.max(1));
                    self.quantize(y);
                    self.quantize(p);
                }
            }
            if errors == 0 {
                break;
            }
        }
        passes
    }

    /// One-shot online update after storing exemplar `i`: add it to its class (weight
    /// 1 - similarity, so familiar cases add little) and, when a wrong label `wrong` had been
    /// predicted, subtract it from that class.
    pub fn online(&mut self, i: usize, wrong: Option<Action>) {
        let w = self.cfg.words;
        let q: Vec<u64> = self.hvs[i * w..(i + 1) * w].to_vec();
        let y = self.labels[i] as usize;
        let sy = self.proto_sim(&q, y).max(-1.0);
        let wy = ((1.0 - sy) * SCALE) as i32;
        self.add_counts(y, &q, wy.max(1));
        self.quantize(y);
        if let Some(p) = wrong {
            let p = p.idx();
            if p != y && self.n_label[p] > 0 {
                let sp = self.proto_sim(&q, p);
                let wp = ((1.0 + sp) * 0.5 * SCALE) as i32;
                self.add_counts(p, &q, -wp.max(1));
                self.quantize(p);
            }
        }
    }

    /// Score a query vector.
    pub fn score_hv(&self, q: &[u64]) -> Scores {
        let mut out = Scores::empty();
        if self.is_empty() {
            return out;
        }
        let k = self.cfg.k.max(1);
        // per label: top-k similarities (small fixed arrays)
        let mut top = [[-2.0f32; 8]; N_LABELS];
        let kk = k.min(8);
        let ka = kk.max(3);
        let mut glob: [(f32, usize); 8] = [(-2.0, 0); 8];
        for i in 0..self.len() {
            let s = hv::sim(q, self.hv(i));
            let l = self.labels[i] as usize;
            ins(&mut top[l][..kk], s);
            insi(&mut glob[..ka], (s, i));
        }
        out.best_sim = glob[0].0;
        out.nearest = Some(glob[0].1);
        let a = self.cfg.alpha;
        for l in 0..N_LABELS {
            if self.n_label[l] == 0 {
                continue;
            }
            let m = (self.n_label[l] as usize).min(kk);
            let knn = top[l][..m].iter().sum::<f32>() / m as f32;
            let pr = if a < 1.0 { self.proto_sim(q, l) } else { 0.0 };
            out.s[l] = a * knn + (1.0 - a) * pr;
        }
        let tl = argmax(&out.s);
        let n = glob[..ka].iter().filter(|g| g.0 > -2.0).count().max(1);
        out.agree = glob[..ka]
            .iter()
            .filter(|g| g.0 > -2.0 && self.labels[g.1] as usize == tl)
            .count() as f32
            / n as f32;
        out
    }

    /// Consolidation: merge near duplicates (same label, similarity >= `dup`), list label
    /// conflicts (different labels, similarity >= `conflict`), rebuild prototypes.
    /// Work is bounded by capacity^2 vector comparisons.
    pub fn sleep(&mut self, dup: f32, conflict: f32) -> SleepReport {
        let w = self.cfg.words;
        let n = self.len();
        let mut keep = vec![true; n];
        let mut merged = 0;
        for i in 0..n {
            if !keep[i] {
                continue;
            }
            for j in i + 1..n {
                if keep[j]
                    && self.labels[i] == self.labels[j]
                    && hv::sim(self.hv(i), self.hv(j)) >= dup
                {
                    keep[j] = false;
                    merged += 1;
                }
            }
        }
        if merged > 0 {
            let mut hvs = Vec::with_capacity(self.hvs.capacity());
            let mut labels = Vec::with_capacity(self.labels.capacity());
            let mut notes = Vec::with_capacity(self.notes.capacity());
            self.n_label = [0; N_LABELS];
            for i in 0..n {
                if keep[i] {
                    hvs.extend_from_slice(&self.hvs[i * w..(i + 1) * w]);
                    labels.push(self.labels[i]);
                    notes.push(self.notes[i].clone());
                    self.n_label[self.labels[i] as usize] += 1;
                }
            }
            self.hvs = hvs;
            self.labels = labels;
            self.notes = notes;
        }
        let n = self.len();
        let mut conflicts: Vec<Conflict> = Vec::new();
        for i in 0..n {
            for j in i + 1..n {
                if self.labels[i] != self.labels[j] {
                    let s = hv::sim(self.hv(i), self.hv(j));
                    if s >= conflict {
                        conflicts.push(Conflict { a: i, b: j, sim: s });
                    }
                }
            }
        }
        conflicts.sort_by(|x, y| {
            y.sim
                .partial_cmp(&x.sim)
                .unwrap_or(core::cmp::Ordering::Equal)
        });
        conflicts.truncate(MAX_CONFLICTS);
        let passes = self.rebuild();
        SleepReport {
            merged,
            kept: n,
            conflicts,
            passes,
        }
    }
}

/// Index of the largest score (first on ties).
pub fn argmax(s: &[f32; N_LABELS]) -> usize {
    let mut b = 0;
    for l in 1..N_LABELS {
        if s[l] > s[b] {
            b = l;
        }
    }
    b
}

fn ins(top: &mut [f32], s: f32) {
    if top.is_empty() || s <= top[top.len() - 1] {
        return;
    }
    let mut p = top.len() - 1;
    top[p] = s;
    while p > 0 && top[p] > top[p - 1] {
        top.swap(p, p - 1);
        p -= 1;
    }
}

fn insi(top: &mut [(f32, usize)], v: (f32, usize)) {
    if top.is_empty() || v.0 <= top[top.len() - 1].0 {
        return;
    }
    let mut p = top.len() - 1;
    top[p] = v;
    while p > 0 && top[p].0 > top[p - 1].0 {
        top.swap(p, p - 1);
        p -= 1;
    }
}

/// Sparse weighted feature set: sorted by key, weights summed for repeated keys.
pub fn sparse(feats: &[Feat]) -> Vec<(u64, u32)> {
    let mut v: Vec<(u64, u32)> = feats.iter().map(|f| (f.key(), f.w as u32)).collect();
    v.sort_unstable_by_key(|x| x.0);
    let mut o: Vec<(u64, u32)> = Vec::with_capacity(v.len());
    for (k, w) in v {
        match o.last_mut() {
            Some(l) if l.0 == k => l.1 += w,
            _ => o.push((k, w)),
        }
    }
    o
}

/// Weighted Dice similarity of two sparse sets, in [0, 1].
pub fn dice(a: &[(u64, u32)], b: &[(u64, u32)]) -> f32 {
    let (mut i, mut j, mut inter) = (0, 0, 0u64);
    while i < a.len() && j < b.len() {
        if a[i].0 == b[j].0 {
            inter += a[i].1.min(b[j].1) as u64;
            i += 1;
            j += 1;
        } else if a[i].0 < b[j].0 {
            i += 1;
        } else {
            j += 1;
        }
    }
    let ta: u64 = a.iter().map(|x| x.1 as u64).sum();
    let tb: u64 = b.iter().map(|x| x.1 as u64).sum();
    if ta + tb == 0 {
        return 0.0;
    }
    2.0 * inter as f32 / (ta + tb) as f32
}

/// Nearest exemplar over sparse feature sets (no hypervectors).
#[derive(Clone)]
pub struct NearestModel {
    /// exemplars per label averaged (as in HvModel)
    pub k: usize,
    /// capacity
    pub max_exemplars: usize,
    sets: Vec<Vec<(u64, u32)>>,
    labels: Vec<u8>,
    notes: Vec<String>,
    n_label: [u32; N_LABELS],
}

impl NearestModel {
    /// Empty memory.
    pub fn new(k: usize, max_exemplars: usize) -> NearestModel {
        NearestModel {
            k,
            max_exemplars,
            sets: Vec::new(),
            labels: Vec::new(),
            notes: Vec::new(),
            n_label: [0; N_LABELS],
        }
    }
    /// Number of exemplars.
    pub fn len(&self) -> usize {
        self.labels.len()
    }
    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
    /// Exemplar label and note.
    pub fn exemplar(&self, i: usize) -> (Action, &str) {
        (Action::from_idx(self.labels[i] as usize), &self.notes[i])
    }
    /// Store one exemplar.
    pub fn push(&mut self, f: &[Feat], label: Action, note: &str) -> Result<usize, MemoryFull> {
        if self.labels.len() >= self.max_exemplars {
            return Err(MemoryFull);
        }
        self.sets.push(sparse(f));
        self.labels.push(label.idx() as u8);
        self.notes.push(short(note));
        self.n_label[label.idx()] += 1;
        Ok(self.labels.len() - 1)
    }
    /// Bytes held.
    pub fn bytes(&self) -> usize {
        self.sets
            .iter()
            .map(|s| s.capacity() * 16 + 24)
            .sum::<usize>()
            + self.labels.capacity()
            + self.notes.iter().map(|n| n.capacity() + 24).sum::<usize>()
    }
    /// Score.
    pub fn score(&self, f: &[Feat]) -> Scores {
        let mut out = Scores::empty();
        if self.is_empty() {
            return out;
        }
        let q = sparse(f);
        let kk = self.k.clamp(1, 8);
        let ka = kk.max(3);
        let mut top = [[-2.0f32; 8]; N_LABELS];
        let mut glob: [(f32, usize); 8] = [(-2.0, 0); 8];
        for (i, s) in self.sets.iter().enumerate() {
            let d = dice(&q, s);
            ins(&mut top[self.labels[i] as usize][..kk], d);
            insi(&mut glob[..ka], (d, i));
        }
        out.best_sim = glob[0].0;
        out.nearest = Some(glob[0].1);
        for l in 0..N_LABELS {
            if self.n_label[l] == 0 {
                continue;
            }
            let m = (self.n_label[l] as usize).min(kk);
            out.s[l] = top[l][..m].iter().sum::<f32>() / m as f32;
        }
        let tl = argmax(&out.s);
        let n = glob[..ka].iter().filter(|g| g.0 > -2.0).count().max(1);
        out.agree = glob[..ka]
            .iter()
            .filter(|g| g.0 > -2.0 && self.labels[g.1] as usize == tl)
            .count() as f32
            / n as f32;
        out
    }
}

/// Averaged multiclass perceptron over sparse features.
#[derive(Clone)]
pub struct PerceptronModel {
    /// training passes
    pub epochs: u32,
    /// bound on distinct features
    pub max_features: usize,
    w: BTreeMap<u64, [f32; N_LABELS]>,
    train: Vec<(Vec<(u64, u32)>, u8)>,
    n_label: [u32; N_LABELS],
}

impl PerceptronModel {
    /// Empty model.
    pub fn new(epochs: u32, max_features: usize) -> PerceptronModel {
        PerceptronModel {
            epochs,
            max_features,
            w: BTreeMap::new(),
            train: Vec::new(),
            n_label: [0; N_LABELS],
        }
    }
    /// Queue one training example.
    pub fn push(&mut self, f: &[Feat], label: Action) {
        self.train.push((sparse(f), label.idx() as u8));
        self.n_label[label.idx()] += 1;
    }
    /// Bytes held.
    pub fn bytes(&self) -> usize {
        self.w.len() * (8 + 4 * N_LABELS + 32)
    }
    fn raw(w: &BTreeMap<u64, [f32; N_LABELS]>, x: &[(u64, u32)]) -> [f32; N_LABELS] {
        let mut s = [0.0f32; N_LABELS];
        for (k, v) in x {
            if let Some(r) = w.get(k) {
                for l in 0..N_LABELS {
                    s[l] += r[l] * *v as f32;
                }
            }
        }
        s
    }
    /// Train with averaging; deterministic shuffle per pass.
    pub fn fit(&mut self) {
        let mut w: BTreeMap<u64, [f32; N_LABELS]> = BTreeMap::new();
        let mut u: BTreeMap<u64, [f32; N_LABELS]> = BTreeMap::new();
        let mut c = 1.0f32;
        let n = self.train.len();
        let mut order: Vec<usize> = (0..n).collect();
        let mut rng = hv::SEED;
        for _ in 0..self.epochs {
            for i in (1..n).rev() {
                let j = (hv::splitmix(&mut rng) % (i as u64 + 1)) as usize;
                order.swap(i, j);
            }
            for &i in &order {
                let (x, y) = (&self.train[i].0, self.train[i].1 as usize);
                let mut s = Self::raw(&w, x);
                for (l, sl) in s.iter_mut().enumerate() {
                    if self.n_label[l] == 0 {
                        *sl = f32::MIN;
                    }
                }
                let p = argmax(&s);
                if p != y {
                    for (k, v) in x {
                        if !w.contains_key(k) && w.len() >= self.max_features {
                            continue;
                        }
                        let r = w.entry(*k).or_insert([0.0; N_LABELS]);
                        r[y] += *v as f32;
                        r[p] -= *v as f32;
                        let a = u.entry(*k).or_insert([0.0; N_LABELS]);
                        a[y] += c * *v as f32;
                        a[p] -= c * *v as f32;
                    }
                }
                c += 1.0;
            }
        }
        for (k, r) in w.iter_mut() {
            if let Some(a) = u.get(k) {
                for l in 0..N_LABELS {
                    r[l] -= a[l] / c;
                }
            }
        }
        self.w = w;
    }
    /// Online correction: perceptron steps on this example until it is predicted right
    /// (at most 8 steps).
    pub fn online(&mut self, f: &[Feat], label: Action) {
        let x = sparse(f);
        let y = label.idx();
        self.n_label[y] += 1;
        self.train.push((x.clone(), y as u8));
        for _ in 0..8 {
            let s = self.score_sparse(&x);
            let p = argmax(&s.s);
            if p == y {
                break;
            }
            for (k, v) in &x {
                if !self.w.contains_key(k) && self.w.len() >= self.max_features {
                    continue;
                }
                let r = self.w.entry(*k).or_insert([0.0; N_LABELS]);
                r[y] += *v as f32;
                r[p] -= *v as f32;
            }
        }
    }
    fn score_sparse(&self, x: &[(u64, u32)]) -> Scores {
        let mut out = Scores::empty();
        let tot: f32 = x.iter().map(|v| v.1 as f32).sum::<f32>().max(1.0);
        let s = Self::raw(&self.w, x);
        for l in 0..N_LABELS {
            if self.n_label[l] > 0 {
                out.s[l] = s[l] / tot;
            }
        }
        out.best_sim = 1.0;
        out.agree = 1.0;
        out
    }
    /// Score.
    pub fn score(&self, f: &[Feat]) -> Scores {
        self.score_sparse(&sparse(f))
    }
}
