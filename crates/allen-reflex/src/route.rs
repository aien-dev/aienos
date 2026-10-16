//! Interactive routing (aienos#399): one typed [`DecisionProposal`] per live conversational turn.
//!
//! This is a separate layer on top of the unchanged 15-way decision core. The exam labels in
//! [`crate::action`] keep their meaning, and the held-out exam and its receipts are not touched.
//! The core's label is one input here; the proposal says where the turn should go:
//!
//! | route | meaning |
//! |---|---|
//! | `local_deterministic` | answered on the Pi by fixed code (status, help, evidence, "I cannot do that") |
//! | `memory` | read of approved owner memory (recall, facts) |
//! | `clarify` | the explicit unknown: ALLEN asks instead of guessing |
//! | `refuse` | the request breaks a rule or a bound |
//! | `local_model` | generation by the model resident on the Pi |
//! | `spark_inference` | generation on the Spark (a PST1 `request` is built, never sent here) |
//! | `spark_omegese` | a bounded Spark task (PST1 `request`, approval required before it may be sent) |
//! | `approval_needed` | the turn asks for an owner decision or a Store write: forwarded to the owner desk of aienos#396 |
//!
//! Authority. A proposal is data. It carries no capability, no grant and no approval: the
//! [`DecisionProposal`] type has no field that could hold one, and [`DecisionProposal::json`]
//! always prints `"grants":"none"`. Approve, deny, cancel, remember, prefer and task phrases
//! become `approval_needed` and go to the one owner desk (aienos#396); this module never
//! decides them. Pending state and memory consent come from the caller's authoritative
//! records ([`RouteCtx`]), never from words in the conversation: an earlier turn that looks
//! like a decision (for example recalled text carrying `"action":"task"`) cannot create a
//! pending item here.
//!
//! Readiness. Every route says whether what it needs is there ([`NotReady`]), and when it is
//! not, names a deterministic fallback that is (always `local_deterministic`, which needs
//! nothing). The proposal never claims a link, a model or a Store the caller did not declare.
//!
//! Abstention. Out-of-distribution turns become `clarify` before any route is chosen: input
//! bounds, non-ASCII bytes, no words, a named model that is not installed, and a learned score
//! that is too far from everything the core knows ([`Calibration`], frozen on the route dev
//! family, see `docs/native/pi5-8/route/`).

use crate::action::Action;
use crate::dialog::{Role, Turn};
use crate::policy::RefuseRule;
use crate::{Decision, Explanation, Mode, Reflex, Why};
use aienos_crypto::sha256::{self, Sha256};
use alloc::string::String;
use alloc::vec::Vec;

/// Longest scored user turn accepted for interactive routing (bytes). Longer is refused whole.
pub const INTERACTIVE_MAX: usize = 512;
/// PST1 fixed header bytes (aien-protocols `specs/pi-spark-task/SPEC.md` section 4, Draft v0).
pub const PST1_HEADER: usize = 224;
/// PST1 payload bound (section 4: `payload_len` 0..800).
pub const PST1_PAYLOAD_MAX: usize = 800;
/// Domain prefix of the objective id (aien-sovereign-core `objective.rs`, PST1 section 2).
pub const OBJECTIVE_DOMAIN: &[u8] = b"AIEN_E2E_OBJECTIVE_V1\n";

/// Where a turn should go.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Route {
    LocalDeterministic = 0,
    Memory,
    Clarify,
    Refuse,
    LocalModel,
    SparkInference,
    SparkOmegese,
    ApprovalNeeded,
}

impl Route {
    /// All routes in index order.
    pub const ALL: [Route; 8] = [
        Route::LocalDeterministic,
        Route::Memory,
        Route::Clarify,
        Route::Refuse,
        Route::LocalModel,
        Route::SparkInference,
        Route::SparkOmegese,
        Route::ApprovalNeeded,
    ];

    /// Name used in the proposal line and the route families.
    pub fn name(self) -> &'static str {
        match self {
            Route::LocalDeterministic => "local_deterministic",
            Route::Memory => "memory",
            Route::Clarify => "clarify",
            Route::Refuse => "refuse",
            Route::LocalModel => "local_model",
            Route::SparkInference => "spark_inference",
            Route::SparkOmegese => "spark_omegese",
            Route::ApprovalNeeded => "approval_needed",
        }
    }

    /// Parse a route name (exact).
    pub fn from_name(s: &str) -> Option<Route> {
        Route::ALL.iter().copied().find(|r| r.name() == s)
    }

    /// Routes that may run without an owner decision once ready. `approval_needed` and
    /// `spark_omegese` always wait for the owner desk; `clarify` and `refuse` run nothing.
    pub fn runs_without_owner(self) -> bool {
        matches!(
            self,
            Route::LocalDeterministic | Route::Memory | Route::LocalModel | Route::SparkInference
        )
    }
}

/// The owner decision an `approval_needed` (or `spark_omegese`) proposal waits for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Then {
    Approve,
    Deny,
    Cancel,
    Remember,
    Prefer,
    NoteTask,
    SparkTask,
}

impl Then {
    /// Name used in the proposal line.
    pub fn name(self) -> &'static str {
        match self {
            Then::Approve => "approve",
            Then::Deny => "deny",
            Then::Cancel => "cancel",
            Then::Remember => "remember",
            Then::Prefer => "prefer",
            Then::NoteTask => "note_task",
            Then::SparkTask => "spark_task",
        }
    }

    /// Parse (exact).
    pub fn from_name(s: &str) -> Option<Then> {
        [
            Then::Approve,
            Then::Deny,
            Then::Cancel,
            Then::Remember,
            Then::Prefer,
            Then::NoteTask,
            Then::SparkTask,
        ]
        .into_iter()
        .find(|t| t.name() == s)
    }
}

/// Who is speaking, as established by the owner-access path of aienos#396.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Speaker {
    /// owner access established for this session
    Owner,
    /// skip/guest mode: no named profile, no owner memory, no Store writes
    Guest,
}

impl Speaker {
    /// Name used in the proposal line.
    pub fn name(self) -> &'static str {
        match self {
            Speaker::Owner => "owner",
            Speaker::Guest => "guest",
        }
    }
}

/// What the running image really has. Only the caller knows; the proposal never assumes more.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Caps {
    /// sealed Store open (memory reads, approved writes)
    pub store: bool,
    /// the owner desk of aienos#396 is present to take approvals
    pub desk: bool,
    /// a local model is resident
    pub local_model: bool,
    /// an authenticated Spark session (M6-B) is up
    pub spark_link: bool,
}

impl Caps {
    /// Bit form for the C side: 1 store, 2 desk, 4 local model, 8 Spark link.
    pub fn from_bits(b: u32) -> Caps {
        Caps {
            store: b & 1 != 0,
            desk: b & 2 != 0,
            local_model: b & 4 != 0,
            spark_link: b & 8 != 0,
        }
    }
}

/// Learned-score abstention thresholds. Frozen per mode on the route dev family.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Calibration {
    /// below this similarity to the nearest stored example: `clarify` (unfamiliar)
    pub min_sim: f32,
    /// below this score margin between the top two labels: `clarify` (unsure)
    pub min_margin: f32,
}

impl Calibration {
    /// Off: never abstain on score (the exam setting).
    pub const OFF: Calibration = Calibration {
        min_sim: -1.0,
        min_margin: f32::MIN,
    };

    /// The frozen route calibration for `mode` (chosen on `route-dev.psv` only; see
    /// `docs/native/pi5-8/route/README.md`). The perceptron has no similarity, only a margin.
    pub fn frozen(mode: Mode) -> Calibration {
        match mode {
            Mode::Reflex => Calibration {
                min_sim: 0.20,
                min_margin: f32::MIN,
            },
            Mode::Nearest => Calibration {
                min_sim: 0.35,
                min_margin: f32::MIN,
            },
            Mode::Perceptron => Calibration {
                min_sim: -1.0,
                min_margin: 0.15,
            },
        }
    }
}

/// Authoritative context of one turn, from the caller's own records.
#[derive(Clone, Copy, Debug)]
pub struct RouteCtx<'a> {
    /// who is speaking
    pub speaker: Speaker,
    /// the owner consented (through aienos#396) to memory use in this profile revision
    pub memory_consent: bool,
    /// the lifecycle has a pending item right now
    pub pending: bool,
    /// what the image has
    pub caps: Caps,
    /// the installed local model's short name, if any (lower case)
    pub installed_model: Option<&'a str>,
    /// ALLEN subject reference for PST1 `subject_id` (all zero when unknown)
    pub subject_id: [u8; 32],
    /// score abstention
    pub cal: Calibration,
}

/// One interactive request with its references.
#[derive(Clone, Copy, Debug)]
pub struct RouteRequest<'a> {
    /// request id given by the input path (aienos#396), unique per session
    pub request_id: u64,
    /// session id given by the input path
    pub session_id: u64,
    /// the conversation; the last user turn is the request
    pub turns: &'a [Turn<'a>],
}

/// Why a route cannot run now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NotReady {
    /// no sealed Store open in this image
    StoreAbsent,
    /// the owner has not consented to memory use
    NoConsent,
    /// no owner desk to take the decision
    DeskAbsent,
    /// no local model resident
    NoLocalModel,
    /// no authenticated Spark session
    SparkLinkDown,
}

impl NotReady {
    /// Name used in the proposal line.
    pub fn name(self) -> &'static str {
        match self {
            NotReady::StoreAbsent => "store_absent",
            NotReady::NoConsent => "no_memory_consent",
            NotReady::DeskAbsent => "owner_desk_absent",
            NotReady::NoLocalModel => "no_local_model",
            NotReady::SparkLinkDown => "spark_link_down",
        }
    }
}

/// Why the route came out as it did.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RouteWhy {
    /// the core's label, mapped
    Scored,
    /// the core recalled an (almost) identical stored example
    ExactRecall,
    /// the core's policy layer refused
    Policy(RefuseRule),
    /// no user turn
    NoUserTurn,
    /// scored turn longer than [`INTERACTIVE_MAX`]
    InputTooLong,
    /// a byte outside printable ASCII
    NonAscii,
    /// no words
    NoWords,
    /// the core abstained or asked (its own clarify)
    CoreClarify,
    /// a text verb without a usable subject
    MissingSubject,
    /// too far from every stored example
    Unfamiliar,
    /// top labels too close
    Unsure,
    /// approve/deny/cancel with nothing pending in the lifecycle
    NothingPending,
    /// the turn names a model that is not installed
    ModelUnavailable,
    /// a guest asked for owner memory or a Store write
    GuestScope,
    /// a request the agent has no capability for
    OutOfCapability,
    /// explicit Spark task cue
    SparkCue,
}

impl RouteWhy {
    /// Name used in the proposal line.
    pub fn name(self) -> &'static str {
        match self {
            RouteWhy::Scored => "scored",
            RouteWhy::ExactRecall => "exact_recall",
            RouteWhy::Policy(_) => "policy",
            RouteWhy::NoUserTurn => "no_user_turn",
            RouteWhy::InputTooLong => "input_too_long",
            RouteWhy::NonAscii => "non_ascii",
            RouteWhy::NoWords => "no_words",
            RouteWhy::CoreClarify => "core_clarify",
            RouteWhy::MissingSubject => "missing_subject",
            RouteWhy::Unfamiliar => "unfamiliar",
            RouteWhy::Unsure => "unsure",
            RouteWhy::NothingPending => "nothing_pending",
            RouteWhy::ModelUnavailable => "model_unavailable",
            RouteWhy::GuestScope => "guest_scope",
            RouteWhy::OutOfCapability => "out_of_capability",
            RouteWhy::SparkCue => "spark_cue",
        }
    }
}

/// The typed proposal for one interactive turn. Data only: it grants nothing.
#[derive(Clone, Debug, PartialEq)]
pub struct DecisionProposal {
    /// request id as given
    pub request_id: u64,
    /// session id as given
    pub session_id: u64,
    /// who spoke
    pub speaker: Speaker,
    /// SHA-256 of [`OBJECTIVE_DOMAIN`] and the exact bytes of the scored user turn
    /// (all zero when there is no user turn)
    pub objective_id: [u8; 32],
    /// where the turn should go
    pub route: Route,
    /// the owner decision it waits for (approval_needed, spark_omegese)
    pub then: Option<Then>,
    /// `None`: ready; `Some`: the first missing piece
    pub not_ready: Option<NotReady>,
    /// what runs instead while not ready (always `local_deterministic`)
    pub fallback: Option<Route>,
    /// reason
    pub why: RouteWhy,
    /// the core's label (input to the routing, kept for the record)
    pub label: Action,
    /// the core's copied argument text, if any
    pub text: Option<String>,
    /// SHA-256 of the PST1 `request` message built for a Spark route (never sent here)
    pub pst1_digest: Option<[u8; 32]>,
}

fn hex(out: &mut String, b: &[u8]) {
    const H: &[u8; 16] = b"0123456789abcdef";
    for &x in b {
        out.push(H[(x >> 4) as usize] as char);
        out.push(H[(x & 15) as usize] as char);
    }
}

fn push_u64(out: &mut String, mut v: u64) {
    let mut b = [0u8; 20];
    let mut i = b.len();
    loop {
        i -= 1;
        b[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for &c in &b[i..] {
        out.push(c as char);
    }
}

impl DecisionProposal {
    /// One JSON line. Field order is fixed so the Pi and the host print the same bytes.
    /// Every string is printable ASCII without `"` or `\` (names, hex, and the core's text,
    /// which [`crate::span`] already restricts).
    pub fn json(&self) -> String {
        let mut s = String::with_capacity(320);
        s.push_str("{\"req\":");
        push_u64(&mut s, self.request_id);
        s.push_str(",\"session\":");
        push_u64(&mut s, self.session_id);
        s.push_str(",\"speaker\":\"");
        s.push_str(self.speaker.name());
        s.push_str("\",\"objective\":\"");
        hex(&mut s, &self.objective_id);
        s.push_str("\",\"route\":\"");
        s.push_str(self.route.name());
        s.push_str("\",\"then\":\"");
        s.push_str(self.then.map(|t| t.name()).unwrap_or("-"));
        s.push_str("\",\"ready\":\"");
        match self.not_ready {
            None => s.push_str("yes"),
            Some(n) => {
                s.push_str("no:");
                s.push_str(n.name());
            }
        }
        s.push_str("\",\"fallback\":\"");
        s.push_str(self.fallback.map(|r| r.name()).unwrap_or("-"));
        s.push_str("\",\"why\":\"");
        s.push_str(self.why.name());
        if let RouteWhy::Policy(r) = self.why {
            s.push(':');
            s.push_str(r.name());
        }
        s.push_str("\",\"label\":\"");
        s.push_str(self.label.name());
        s.push_str("\",\"text\":\"");
        if let Some(t) = &self.text {
            s.push_str(t);
        }
        s.push_str("\",\"pst1\":\"");
        match &self.pst1_digest {
            Some(d) => hex(&mut s, d),
            None => s.push('-'),
        }
        s.push_str("\",\"grants\":\"none\"}");
        s
    }
}

/// Objective id of a request text (PST1 `objective_id`).
pub fn objective_id(text: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(OBJECTIVE_DOMAIN);
    h.update(text);
    h.finalize()
}

fn take16(d: &[u8; 32]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o.copy_from_slice(&d[..16]);
    o
}

/// Build the PST1 `request` message (header + payload) for a Spark route. Draft v0 layout of
/// aien-protocols `specs/pi-spark-task/SPEC.md`; big-endian; reserved bytes zero. It is built
/// so its exact bytes are on record; nothing here sends it, and a Spark task still needs the
/// owner desk before any sender may take it. `None` when the payload exceeds the bound or
/// the route is not a Spark route.
pub fn pst1_request(
    p: &DecisionProposal,
    payload: &[u8],
    subject_id: &[u8; 32],
) -> Option<Vec<u8>> {
    let effect_class: u8 = match p.route {
        Route::SparkInference | Route::SparkOmegese => 1, // COMPUTE: a claim, never a permission
        _ => return None,
    };
    if payload.len() > PST1_PAYLOAD_MAX {
        return None;
    }
    let mut cause = Sha256::new();
    cause.update(b"AIENOS_PST1_CAUSE_V1\n");
    cause.update(&p.session_id.to_be_bytes());
    cause.update(&p.request_id.to_be_bytes());
    cause.update(&p.objective_id);
    let cause_id = cause.finalize();
    let mut t = Sha256::new();
    t.update(b"AIENOS_PST1_TASK_V1\n");
    t.update(&cause_id);
    let task_id = take16(&t.finalize());
    let mut k = Sha256::new();
    k.update(b"AIENOS_PST1_IDEMPOTENCE_V1\n");
    k.update(&cause_id);
    let idem = take16(&k.finalize());
    let mut m = Vec::with_capacity(PST1_HEADER + payload.len());
    m.push(1); // version
    m.push(1); // type: request (Pi side)
    m.extend_from_slice(&[0, 0]); // reserved0
    m.extend_from_slice(&cause_id); // cause_id
    m.extend_from_slice(&[0u8; 32]); // origin_run_id: opaque, none on the Pi
    m.extend_from_slice(&p.objective_id); // objective_id
    m.extend_from_slice(subject_id); // subject_id
    m.extend_from_slice(&[0u8; 16]); // parent_task_id: no parent
    m.extend_from_slice(&task_id);
    m.extend_from_slice(&idem);
    m.extend_from_slice(&0u32.to_be_bytes()); // ordinal 0
    m.push(effect_class);
    m.extend_from_slice(&[0, 0, 0]); // reserved1
    m.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    m.extend_from_slice(&[0, 0]); // reserved2
    m.extend_from_slice(&sha256::hash(payload));
    debug_assert_eq!(m.len(), PST1_HEADER);
    m.extend_from_slice(payload);
    Some(m)
}

/// Model family words a request may name. A named family that is not the installed model
/// makes the turn `clarify` (`model_unavailable`) instead of silently using another model.
const MODEL_WORDS: [&str; 14] = [
    "gpt",
    "chatgpt",
    "claude",
    "gemini",
    "llama",
    "tinyllama",
    "mistral",
    "qwen",
    "danube",
    "phi",
    "grok",
    "deepseek",
    "gemma",
    "copilot",
];

/// Words that mark an explicit Spark task ("run the benchmark on the spark").
const SPARK_TASK_VERBS: [&str; 10] = [
    "run",
    "compile",
    "build",
    "benchmark",
    "train",
    "test",
    "verify",
    "execute",
    "measure",
    "compute",
];

fn lower_words(msg: &str) -> impl Iterator<Item = &str> {
    msg.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
}

fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn named_model(msg: &str) -> Option<&str> {
    lower_words(msg).find(|w| MODEL_WORDS.iter().any(|m| eq_ci(w, m)))
}

fn spark_cue(msg: &str) -> bool {
    let mut spark = false;
    let mut verb = false;
    for w in lower_words(msg) {
        spark |= eq_ci(w, "spark") || eq_ci(w, "gb10");
        verb |= SPARK_TASK_VERBS.iter().any(|v| eq_ci(w, v));
    }
    spark && verb
}

/// Decide one interactive turn. Never fails: every outcome is one proposal.
pub fn propose(core: &Reflex, req: &RouteRequest, ctx: &RouteCtx) -> DecisionProposal {
    let last = req.turns.iter().rposition(|t| t.role == Role::User);
    let msg: &str = last.map(|i| req.turns[i].text).unwrap_or("");
    let mut p = DecisionProposal {
        request_id: req.request_id,
        session_id: req.session_id,
        speaker: ctx.speaker,
        objective_id: if last.is_some() {
            objective_id(msg.as_bytes())
        } else {
            [0u8; 32]
        },
        route: Route::Clarify,
        then: None,
        not_ready: None,
        fallback: None,
        why: RouteWhy::NoUserTurn,
        label: Action::Clarify,
        text: None,
        pst1_digest: None,
    };
    if last.is_none() {
        return p;
    }
    // Bounds and byte checks before the core sees anything.
    if msg.len() > INTERACTIVE_MAX {
        p.route = Route::Refuse;
        p.why = RouteWhy::InputTooLong;
        return p;
    }
    if !msg.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        p.why = RouteWhy::NonAscii;
        return p;
    }
    let (d, e): (Decision, Explanation) = core.decide(req.turns);
    p.label = d.action;
    p.text = d.text;
    // The core's own refusals and abstentions.
    match e.why {
        Why::Policy(r) => {
            p.route = Route::Refuse;
            p.why = RouteWhy::Policy(r);
            p.text = None;
            return p;
        }
        Why::NoUserTurn => {
            p.why = RouteWhy::NoUserTurn;
            return p;
        }
        Why::InputTooLong => {
            p.route = Route::Refuse;
            p.why = RouteWhy::InputTooLong;
            return p;
        }
        Why::NoWords => {
            p.why = RouteWhy::NoWords;
            return p;
        }
        Why::Span(_) => {
            p.why = RouteWhy::MissingSubject;
            return p;
        }
        _ => {}
    }
    // Score abstention (explicit unknown). An exact recall is a known message. A scored `refuse`
    // far from every example also becomes `clarify` (dev: unfamiliar words otherwise scored as
    // refuse); policy refusals returned above are never softened.
    if e.why != Why::ExactRecall {
        if e.best_sim < ctx.cal.min_sim {
            p.route = Route::Clarify;
            p.why = RouteWhy::Unfamiliar;
            p.text = None;
            return p;
        }
        if e.margin < ctx.cal.min_margin {
            p.route = Route::Clarify;
            p.why = RouteWhy::Unsure;
            p.text = None;
            return p;
        }
    }
    let why = if e.why == Why::ExactRecall {
        RouteWhy::ExactRecall
    } else {
        RouteWhy::Scored
    };
    p.why = why;
    // A named model that is not installed: ask, never substitute.
    if let Some(m) = named_model(msg) {
        if !ctx.installed_model.is_some_and(|im| eq_ci(im, m)) {
            p.route = Route::Clarify;
            p.why = RouteWhy::ModelUnavailable;
            p.text = None;
            return p;
        }
    }
    let owner = ctx.speaker == Speaker::Owner;
    match d.action {
        Action::Status | Action::Help | Action::Evidence => {
            p.route = Route::LocalDeterministic;
        }
        Action::None => {
            p.route = Route::LocalDeterministic;
            p.why = RouteWhy::OutOfCapability;
        }
        Action::Recall | Action::Facts => {
            // MUTANT: a guest reads owner memory.
            #[cfg(feature = "route-mutant-guest-memory")]
            let owner = true;
            if !owner {
                p.route = Route::Refuse;
                p.why = RouteWhy::GuestScope;
                return p;
            }
            p.route = Route::Memory;
            p.not_ready = if !ctx.memory_consent {
                Some(NotReady::NoConsent)
            } else if !ctx.caps.store {
                Some(NotReady::StoreAbsent)
            } else {
                None
            };
        }
        Action::Remember | Action::Prefer | Action::Task => {
            if !owner {
                p.route = Route::Refuse;
                p.why = RouteWhy::GuestScope;
                return p;
            }
            if d.action == Action::Task && spark_cue(msg) {
                p.route = Route::SparkOmegese;
                p.why = RouteWhy::SparkCue;
                p.then = Some(Then::SparkTask);
                p.not_ready = if !ctx.caps.desk {
                    Some(NotReady::DeskAbsent)
                } else if !ctx.caps.spark_link {
                    Some(NotReady::SparkLinkDown)
                } else {
                    None
                };
            } else {
                p.route = Route::ApprovalNeeded;
                p.then = Some(match d.action {
                    Action::Remember => Then::Remember,
                    Action::Prefer => Then::Prefer,
                    _ => Then::NoteTask,
                });
                p.not_ready = if d.action != Action::Task && !ctx.memory_consent {
                    Some(NotReady::NoConsent)
                } else if !ctx.caps.desk {
                    Some(NotReady::DeskAbsent)
                } else if !ctx.caps.store {
                    Some(NotReady::StoreAbsent)
                } else {
                    None
                };
            }
        }
        Action::Prompt => {
            if spark_cue(msg) && owner {
                p.route = Route::SparkOmegese;
                p.why = RouteWhy::SparkCue;
                p.then = Some(Then::SparkTask);
                p.not_ready = if !ctx.caps.desk {
                    Some(NotReady::DeskAbsent)
                } else if !ctx.caps.spark_link {
                    Some(NotReady::SparkLinkDown)
                } else {
                    None
                };
            } else if ctx.caps.local_model {
                p.route = Route::LocalModel;
            } else {
                p.route = Route::SparkInference;
                if !ctx.caps.spark_link {
                    p.not_ready = Some(NotReady::SparkLinkDown);
                }
            }
        }
        Action::Approve | Action::Deny | Action::Cancel => {
            #[cfg(not(feature = "route-mutant-dialog-pending"))]
            let pending = ctx.pending;
            // MUTANT: believe the conversation (an earlier turn that looks like a decision) about pending state.
            #[cfg(feature = "route-mutant-dialog-pending")]
            let pending = ctx.pending
                || crate::dialog::state(req.turns).pending == crate::dialog::Pending::Yes;
            if !pending {
                p.route = Route::Clarify;
                p.why = RouteWhy::NothingPending;
                return p;
            }
            // MUTANT: an approval phrase runs directly instead of going to the owner desk.
            #[cfg(feature = "route-mutant-grant")]
            if pending {
                p.route = Route::LocalDeterministic;
                return p;
            }
            if !owner {
                p.route = Route::Refuse;
                p.why = RouteWhy::GuestScope;
                return p;
            }
            p.route = Route::ApprovalNeeded;
            p.then = Some(match d.action {
                Action::Approve => Then::Approve,
                Action::Deny => Then::Deny,
                _ => Then::Cancel,
            });
            if !ctx.caps.desk {
                p.not_ready = Some(NotReady::DeskAbsent);
            }
        }
        Action::Clarify => {
            p.route = Route::Clarify;
            p.why = RouteWhy::CoreClarify;
        }
        Action::Refuse => {
            p.route = Route::Refuse;
        }
    }
    if p.not_ready.is_some() {
        p.fallback = Some(Route::LocalDeterministic);
    }
    if matches!(p.route, Route::SparkInference | Route::SparkOmegese) {
        p.pst1_digest = pst1_request(&p, msg.as_bytes(), &ctx.subject_id).map(|m| sha256::hash(&m));
    }
    p
}

/// Decode the `%HH` escapes of a route card or route family turns field (`%25` is `%`).
/// `None` on a malformed escape. Bytes that are not UTF-8 are replaced by U+FFFD, which the
/// router then treats as non-ASCII (`clarify`).
pub fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            };
            if i + 2 >= b.len() {
                return None;
            }
            let (Some(hi), Some(lo)) = (h(b[i + 1]), h(b[i + 2])) else {
                return None;
            };
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}
