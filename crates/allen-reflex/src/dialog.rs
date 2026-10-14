//! Dialog state with explicit roles and turn order. Earlier assistant turns are decision
//! JSON; walking them in order gives the pending-task state the lifecycle uses
//! (`lifecycle_fsm.c`: task and prompt create a pending item; approve, deny and cancel
//! resolve it; remember and prefer never change it).

use crate::action::Action;

/// Who wrote a turn.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// the operator
    User,
    /// the agent (its earlier decision JSON)
    Assistant,
}

/// One turn of the conversation.
#[derive(Clone, Copy, Debug)]
pub struct Turn<'a> {
    /// author
    pub role: Role,
    /// raw text
    pub text: &'a str,
}

/// Is there a pending task or reply waiting for the operator?
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pending {
    /// no earlier turn tells us
    Unknown,
    /// a task or prompt is waiting
    Yes,
    /// the last one was approved, denied or cancelled
    No,
}

/// What the earlier turns say.
#[derive(Clone, Copy, Debug)]
pub struct DialogState {
    /// pending-task state before the scored turn
    pub pending: Pending,
    /// the agent's previous decision, if it was readable
    pub prev: Option<Action>,
    /// index of the scored (last) user turn, if any
    pub last_user: Option<usize>,
}

/// Read the `"action"` value out of an assistant decision line. Tolerant: returns None
/// for anything that is not a recognisable decision.
pub fn parse_action(s: &str) -> Option<Action> {
    let k = s.find("\"action\"")?;
    let rest = &s[k + 8..];
    let c = rest.find(':')?;
    let rest = rest[c + 1..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let e = rest.find('"')?;
    Action::from_name(&rest[..e])
}

/// Walk the turns in order. The scored turn is the last user turn; turns after it are ignored.
pub fn state(turns: &[Turn]) -> DialogState {
    let last_user = turns.iter().rposition(|t| t.role == Role::User);
    let upto = last_user.unwrap_or(0);
    let mut pending = Pending::Unknown;
    let mut prev = None;
    for t in &turns[..upto] {
        if t.role != Role::Assistant {
            continue;
        }
        let a = parse_action(t.text);
        prev = a;
        if let Some(a) = a {
            if a.creates_pending() {
                pending = Pending::Yes;
            } else if a.needs_pending() {
                pending = Pending::No;
            }
        }
    }
    DialogState {
        pending,
        prev,
        last_user,
    }
}
