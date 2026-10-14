//! The 15 decisions of the exam contract (`docs/native/pi5-8/orchestrator-exam/system_prompt.txt`).
//! The 12 verbs are exactly the card-script verbs of `native/kernel/core/agent_cmd.c`;
//! `none`, `clarify` and `refuse` are the three non-actions.

/// One decision label.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Action {
    Status = 0,
    Help,
    Evidence,
    Recall,
    Facts,
    Remember,
    Prefer,
    Task,
    Prompt,
    Approve,
    Deny,
    Cancel,
    None,
    Clarify,
    Refuse,
}

/// Number of labels.
pub const N_LABELS: usize = 15;

impl Action {
    /// All labels in index order.
    pub const ALL: [Action; N_LABELS] = [
        Action::Status,
        Action::Help,
        Action::Evidence,
        Action::Recall,
        Action::Facts,
        Action::Remember,
        Action::Prefer,
        Action::Task,
        Action::Prompt,
        Action::Approve,
        Action::Deny,
        Action::Cancel,
        Action::None,
        Action::Clarify,
        Action::Refuse,
    ];

    /// Index 0..15.
    pub fn idx(self) -> usize {
        self as usize
    }

    /// Label from index (panics never: out of range maps to Clarify).
    pub fn from_idx(i: usize) -> Action {
        if i < N_LABELS {
            Action::ALL[i]
        } else {
            Action::Clarify
        }
    }

    /// The action name used in the JSON decision.
    pub fn name(self) -> &'static str {
        match self {
            Action::Status => "status",
            Action::Help => "help",
            Action::Evidence => "evidence",
            Action::Recall => "recall",
            Action::Facts => "facts",
            Action::Remember => "remember",
            Action::Prefer => "prefer",
            Action::Task => "task",
            Action::Prompt => "prompt",
            Action::Approve => "approve",
            Action::Deny => "deny",
            Action::Cancel => "cancel",
            Action::None => "none",
            Action::Clarify => "clarify",
            Action::Refuse => "refuse",
        }
    }

    /// Parse an action name (exact, lower case).
    pub fn from_name(s: &str) -> Option<Action> {
        Action::ALL.iter().copied().find(|a| a.name() == s)
    }

    /// The four verbs that carry text (1..48 printable ASCII bytes).
    pub fn has_text(self) -> bool {
        matches!(
            self,
            Action::Remember | Action::Prefer | Action::Task | Action::Prompt
        )
    }

    /// approve, deny and cancel need a pending task (lifecycle_fsm.c).
    pub fn needs_pending(self) -> bool {
        matches!(self, Action::Approve | Action::Deny | Action::Cancel)
    }

    /// task and prompt create a pending item; approve, deny, cancel clear it.
    pub fn creates_pending(self) -> bool {
        matches!(self, Action::Task | Action::Prompt)
    }
}
