//! Fails unless every line of each file deserializes as
//! `korg_registry::log::JournalEvent` carrying an `AgentToolCall`.
use korg_registry::log::{CapabilityEvent, JournalEvent};

fn main() {
    let files: Vec<String> = std::env::args().skip(1).collect();
    assert!(!files.is_empty(), "usage: okto-korg-compat <export.jsonl>...");
    for path in files {
        let text = std::fs::read_to_string(&path).expect("read export");
        let mut count = 0;
        for (n, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let ev: JournalEvent = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{path}:{}: not a Korg JournalEvent: {e}", n + 1));
            match ev.event {
                CapabilityEvent::AgentToolCall { .. } => count += 1,
                _ => panic!("{path}:{}: expected AgentToolCall", n + 1),
            }
        }
        println!("ok: {path}: {count} JournalEvents (AgentToolCall)");
    }
}
