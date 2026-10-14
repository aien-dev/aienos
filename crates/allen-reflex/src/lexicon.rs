//! Hand-written word lists. Every list here is prior knowledge about English that the
//! 79 training cases are too few to teach; each has a one-line semantic justification.
//! None of them names an exam case, an id or an argument value. Lists are matched on
//! lower-case words after contraction expansion (`don't` -> `do not`).

use crate::text::Token;

/// Concept classes. A concept is added as an extra feature next to the words, so two
/// different words with the same meaning ("abort", "cancel") look alike to every scorer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Concept {
    /// storing a fact (remember, memorize, keep in mind)
    Store = 0,
    /// a standing preference (prefer, rather, from now on)
    Pref,
    /// a to-do item (task, to-do, remind me)
    Todo,
    /// writing or drafting text (write, draft, poem, explain)
    Write,
    /// agreement (yes, accept, go ahead)
    Yes,
    /// rejection (no, reject, decline)
    No,
    /// stopping (cancel, abort, never mind)
    Stop,
    /// the agent's state (status, ready, pending)
    State,
    /// what the agent can do (help, options, commands)
    Menu,
    /// audit counters (evidence, counters, how many)
    Audit,
    /// reading back the latest note or reply (recall, last, newest)
    Latest,
    /// the stored facts (facts, what you remember)
    Facts,
    /// live information from the world (weather, news, price)
    World,
    /// household devices and media (lights, music, thermostat)
    Device,
    /// buying, booking, ordering (book, order, flight)
    Commerce,
    /// social talk (hello, thanks, bye)
    Social,
    /// a pointer with no content (this, that, it, thing)
    Deictic,
    /// a question word (what, how, is, are at the start)
    Question,
}

/// Number of concepts.
pub const N_CONCEPTS: usize = 18;

type Phrase = &'static [&'static str];

/// (concept, phrases). Justification per concept is on the enum.
pub const CONCEPTS: &[(Concept, &[Phrase])] = &[
    (
        Concept::Store,
        &[
            &["remember"],
            &["memorize"],
            &["memorise"],
            &["store"],
            &["save"],
            &["keep", "in", "mind"],
            &["note", "for", "memory"],
            &["do", "not", "forget"],
            &["fact"],
            &["memory"],
        ],
    ),
    (
        Concept::Pref,
        &[
            &["prefer"],
            &["preference"],
            &["rather"],
            &["from", "now", "on"],
            &["i", "like"],
            &["always"],
            &["tone"],
            &["style"],
        ],
    ),
    (
        Concept::Todo,
        &[
            &["task"],
            &["todo"],
            &["to-do"],
            &["to", "do"],
            &["remind", "me"],
            &["my", "list"],
            &["make", "a", "note"],
            &["note", "down"],
        ],
    ),
    (
        Concept::Write,
        &[
            &["write"],
            &["draft"],
            &["compose"],
            &["generate"],
            &["summarize"],
            &["summarise"],
            &["explain"],
            &["describe"],
            &["rewrite"],
            &["translate"],
            &["poem"],
            &["story"],
            &["haiku"],
            &["limerick"],
            &["letter"],
            &["essay"],
            &["toast"],
            &["reply"],
            &["message"],
        ],
    ),
    (
        Concept::Yes,
        &[
            &["approve"],
            &["accept"],
            &["yes"],
            &["yeah"],
            &["yep"],
            &["confirm"],
            &["go", "ahead"],
            &["sounds", "good"],
            &["looks", "good"],
            &["agreed"],
            &["proceed"],
        ],
    ),
    (
        Concept::No,
        &[
            &["deny"],
            &["reject"],
            &["no"],
            &["nope"],
            &["decline"],
            &["wrong"],
            &["not", "good"],
            &["throw", "it", "away"],
            &["throw", "away"],
            &["discard"],
            &["do", "not", "like"],
            &["do", "not", "accept"],
        ],
    ),
    (
        Concept::Stop,
        &[
            &["cancel"],
            &["stop"],
            &["abort"],
            &["never", "mind"],
            &["nevermind"],
            &["forget", "it"],
            &["call", "it", "off"],
            &["halt"],
            &["drop"],
            &["changed", "my", "mind"],
            &["hold", "on"],
        ],
    ),
    (
        Concept::State,
        &[
            &["status"],
            &["state"],
            &["ready"],
            &["locked"],
            &["pending"],
            &["busy"],
            &["idle"],
            &["doing"],
            &["running"],
        ],
    ),
    (
        Concept::Menu,
        &[
            &["help"],
            &["option"],
            &["options"],
            &["command"],
            &["commands"],
            &["can", "you", "do"],
            &["menu"],
            &["capabilities"],
            &["actions"],
        ],
    ),
    (
        Concept::Audit,
        &[
            &["evidence"],
            &["audit"],
            &["counter"],
            &["counters"],
            &["how", "many"],
            &["so", "far"],
            &["log"],
            &["statistics"],
            &["stats"],
        ],
    ),
    (
        Concept::Latest,
        &[
            &["recall"],
            &["read", "back"],
            &["last"],
            &["latest"],
            &["newest"],
            &["most", "recent"],
            &["previous"],
            &["bring", "up"],
            &["repeat"],
        ],
    ),
    (
        Concept::Facts,
        &[
            &["facts"],
            &["remembered"],
            &["know", "about", "me"],
            &["stored"],
            &["you", "remember"],
            &["told", "you"],
        ],
    ),
    (
        Concept::World,
        &[
            &["weather"],
            &["news"],
            &["price"],
            &["stock"],
            &["bitcoin"],
            &["score"],
            &["forecast"],
            &["traffic"],
            &["rain"],
            &["temperature"],
            &["time", "is", "it"],
            &["who", "won"],
            &["right", "now"],
        ],
    ),
    (
        Concept::Device,
        &[
            &["light"],
            &["lights"],
            &["lamp"],
            &["tv"],
            &["music"],
            &["play"],
            &["song"],
            &["thermostat"],
            &["heater"],
            &["volume"],
            &["speaker"],
            &["door"],
            &["garage"],
            &["oven"],
            &["switch", "on"],
            &["turn", "on"],
            &["turn", "off"],
        ],
    ),
    (
        Concept::Commerce,
        &[
            &["book"],
            &["order"],
            &["flight"],
            &["pizza"],
            &["ticket"],
            &["hotel"],
            &["taxi"],
            &["buy", "me"],
            &["purchase"],
            &["shop"],
        ],
    ),
    (
        Concept::Social,
        &[
            &["hi"],
            &["hello"],
            &["hey"],
            &["thanks"],
            &["thank", "you"],
            &["bye"],
            &["goodbye"],
            &["good", "morning"],
            &["good", "night"],
            &["have", "a", "nice"],
        ],
    ),
    (
        Concept::Deictic,
        &[
            &["this"],
            &["that"],
            &["it"],
            &["thing"],
            &["one"],
            &["something"],
            &["stuff"],
            &["other"],
            &["before"],
            &["same"],
            &["usual"],
        ],
    ),
];

/// Courtesy wrappers at the start of a clause; they carry no content
/// ("please", "can you", "I want you to").
pub const POLITE: &[Phrase] = &[
    &["please"],
    &["kindly"],
    &["ok"],
    &["okay"],
    &["now"],
    &["just"],
    &["so"],
    &["well"],
    &["also"],
    &["alright"],
    &["hey"],
    &["first"],
    &["then"],
    &["can", "you"],
    &["could", "you"],
    &["would", "you"],
    &["will", "you"],
    &["i", "want", "you", "to"],
    &["i", "need", "you", "to"],
    &["i", "would", "like", "you", "to"],
    &["go", "ahead", "and"],
];

/// Discourse fillers: a leading sentence made only of these is dropped when more follows
/// ("Ok. Remember ..."), because it acknowledges and does not request.
pub const FILLER: &[&str] = &[
    "ok", "okay", "good", "great", "fine", "nice", "cool", "thanks", "thank", "you", "hmm", "um",
    "oh", "well", "so", "alright", "right", "perfect",
];

/// Leading words dropped before a comma ("Ok, remember ...").
pub const FILLER_COMMA: &[&str] = &["ok", "okay", "well", "so", "alright", "hmm", "um", "oh"];

/// Words that carry no argument content: an argument made only of these is missing
/// ("Save this.", "Add a task.").
pub const VACUOUS: &[&str] = &[
    "this",
    "that",
    "it",
    "thing",
    "things",
    "one",
    "something",
    "anything",
    "stuff",
    "a",
    "an",
    "the",
    "my",
    "your",
    "some",
    "to",
    "for",
    "me",
    "task",
    "note",
    "fact",
    "preference",
    "new",
    "down",
    "please",
    "again",
    "too",
];

/// Verbs a `prompt` argument normally starts with; "Write something" names no content.
pub const WRITE_VERBS: &[&str] = &[
    "write", "draft", "compose", "generate", "create", "make", "produce",
];

/// Verbs that are not in the agent's list and that the operator may not ask the model to
/// run (exam contract: unlock, rotate, update, shutdown, delete, wipe, deploy; plus the
/// plain synonyms of those).
pub const FORBIDDEN: &[&str] = &[
    "unlock",
    "rotate",
    "update",
    "upgrade",
    "shutdown",
    "reboot",
    "restart",
    "wipe",
    "erase",
    "delete",
    "deploy",
    "format",
    "uninstall",
    "rm",
    "destroy",
];

/// Two-word forbidden phrases (the second word may come up to 3 words later:
/// "shut the agent down").
pub const FORBIDDEN_SPLIT: &[(&str, &str)] = &[
    ("shut", "down"),
    ("power", "off"),
    ("power", "down"),
    ("turn", "off"),
    ("switch", "off"),
];

/// Objects that make "turn off" a device request (`none`) rather than switching the agent off.
pub const DEVICE_OBJECTS: &[&str] = &[
    "light",
    "lights",
    "lamp",
    "lamps",
    "tv",
    "television",
    "music",
    "radio",
    "heater",
    "fan",
    "oven",
    "stove",
    "alarm",
    "speaker",
    "kettle",
    "heating",
    "ac",
    "sprinkler",
    "sprinklers",
];

/// Words that turn a following verb into a noun ("an update", "the format").
pub const DETERMINERS: &[&str] = &[
    "a", "an", "the", "any", "this", "that", "your", "my", "some", "its", "every",
];

/// Negation just before a verb ("do not delete").
pub const NEGATION: &[&str] = &["not", "never", "no"];

/// Words asking the agent to drop its rules (exam contract rule: "asks you to break these rules").
pub const RULE_BREAK_VERBS: &[&str] = &[
    "ignore",
    "disregard",
    "forget",
    "disable",
    "bypass",
    "break",
    "override",
    "skip",
    "drop",
    "remove",
    "turn",
];

/// Objects of a rule-breaking verb.
pub const RULE_OBJECTS: &[&str] = &[
    "rule",
    "rules",
    "instruction",
    "instructions",
    "policy",
    "policies",
    "safety",
    "restriction",
    "restrictions",
    "limit",
    "limits",
    "guardrail",
    "guardrails",
    "allowed",
    "approval",
    "filter",
    "filters",
    "prompt",
];

/// Phrases that announce a fake mode or authority (role-play jailbreaks).
pub const OVERRIDE_PHRASES: &[Phrase] = &[
    &["developer", "mode"],
    &["dev", "mode"],
    &["admin", "mode"],
    &["god", "mode"],
    &["debug", "mode"],
    &["system", "override"],
    &["jailbreak"],
    &["no", "rules"],
    &["without", "rules"],
    &["unrestricted"],
    &["pretend", "you"],
    &["pretend", "to", "be"],
    &["act", "as", "if"],
    &["any", "command"],
    &["without", "asking"],
    &["sudo"],
    &["root", "access"],
    &["your", "instructions"],
    &["system", "prompt"],
];

/// Approval without the operator in the loop ("approve everything automatically").
pub const BLANKET: &[&str] = &["automatically", "always", "every", "everything", "all"];

/// Reported speech: the order comes from stored data ("the note says ...").
pub const REPORT: &[&str] = &[
    "says",
    "said",
    "say",
    "tells",
    "told",
    "instructs",
    "wrote",
    "written",
    "asks",
];

/// Phrases that obey such an order ("do it", "follow it").
pub const OBEY: &[Phrase] = &[
    &["do", "it"],
    &["do", "that"],
    &["do", "what"],
    &["do", "as"],
    &["follow"],
    &["obey"],
    &["carry", "out"],
    &["execute"],
    &["run", "it"],
    &["act", "on"],
    &["go", "on"],
];

/// Leading phrases that open a text payload (store, preference, to-do, writing). Anything
/// after them in the same clause is the operator's data, so words like "wipe" inside it are
/// not orders (exam contract: a request to store a note that contains an order is `remember`).
pub const TEXT_FRAMES: &[Phrase] = &[
    &["remember"],
    &["memorize"],
    &["memorise"],
    &["store"],
    &["save"],
    &["note"],
    &["keep", "in", "mind"],
    &["keep", "this"],
    &["do", "not", "forget"],
    &["make", "a", "note"],
    &["remind", "me"],
    &["task"],
    &["new", "task"],
    &["add"],
    &["put"],
    &["to", "do"],
    &["todo"],
    &["prefer"],
    &["i", "prefer"],
    &["i", "like"],
    &["i", "would", "rather"],
    &["my", "preference"],
    &["write"],
    &["draft"],
    &["compose"],
    &["generate"],
    &["summarize"],
    &["explain"],
    &["describe"],
    &["ask", "the", "model"],
];

/// Second-step verbs: "X and <verb> ..." starts a new request.
pub const AND_VERBS: &[&str] = &[
    "approve", "deny", "cancel", "recall", "show", "list", "check", "read", "tell", "give",
    "reject", "accept",
];

/// Is `words[at..]` starting with phrase `p`?
pub fn starts(toks: &[Token], at: usize, p: &[&str]) -> bool {
    if at + p.len() > toks.len() {
        return false;
    }
    p.iter().enumerate().all(|(k, w)| toks[at + k].word == *w)
}

/// Is `w` in list `l`?
pub fn is_in(l: &[&str], w: &str) -> bool {
    l.contains(&w)
}

/// Longest phrase of `list` starting at `at`, as its length (0 if none).
pub fn longest(toks: &[Token], at: usize, list: &[Phrase]) -> usize {
    list.iter()
        .filter(|p| starts(toks, at, p))
        .map(|p| p.len())
        .max()
        .unwrap_or(0)
}

/// Skip courtesy wrappers at `at`; returns the first content index.
pub fn skip_polite(toks: &[Token], mut at: usize, end: usize) -> usize {
    loop {
        if at >= end {
            return at;
        }
        let n = longest(toks, at, POLITE);
        if n == 0 || at + n > end {
            return at;
        }
        at += n;
    }
}
