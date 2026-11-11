//! The assistant "Neues BridgeNet" between its steps (ADR 0017): the 24 words are made in step 2, shown once (only
//! in the answer to that POST), checked with a short quiz, and used in step 4 to create the network. In between they
//! live only here, in memory, wiped on drop ([`Mnemonic`] keeps its entropy in `Zeroizing`): never written to disk,
//! never logged, never in a URL. An assistant that is not finished within [`WIZARD_TTL_MS`] is dropped.

use std::collections::HashMap;
use std::sync::Mutex;

use bridge_core::Mnemonic;
use bridge_core::encoding::b64;
use bridge_net::JoinMode;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// How long an unfinished assistant is kept (30 minutes).
pub const WIZARD_TTL_MS: i64 = 30 * 60 * 1000;
/// Most assistants open at once.
pub const MAX_WIZARDS: usize = 4;
/// Words asked in the quiz.
pub const QUIZ_WORDS: usize = 3;

/// One assistant in progress.
pub struct Wizard {
    /// Name of the new network.
    pub name: String,
    /// Its template.
    pub mode: JoinMode,
    /// The master key's words (never leave this process except in the answer of step 2).
    pub words: Mnemonic,
    /// Positions (1-24) asked in the quiz, ascending.
    pub quiz: [usize; QUIZ_WORDS],
    /// Quiz passed and "written down" confirmed.
    pub confirmed: bool,
    /// Created at (ms).
    pub created: i64,
}

/// The open assistants, by a random ID.
#[derive(Default)]
pub struct Wizards {
    open: Mutex<HashMap<String, Wizard>>,
}

impl Wizards {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Wizard>> {
        self.open.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Starts an assistant with new words. Returns its ID, the words (to show once) and the quiz positions. The
    /// oldest assistant goes when [`MAX_WIZARDS`] are open.
    pub fn begin(&self, name: String, mode: JoinMode, now: i64) -> (String, Zeroizing<String>, [usize; QUIZ_WORDS]) {
        let words = Mnemonic::generate(&mut OsRng);
        let quiz = quiz_positions(&mut OsRng);
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let id = b64(&id);
        let text = words.words();
        let mut open = self.lock();
        open.retain(|_, wizard| now.saturating_sub(wizard.created) < WIZARD_TTL_MS);
        while open.len() >= MAX_WIZARDS {
            let Some(oldest) = open.iter().min_by_key(|(_, wizard)| wizard.created).map(|(id, _)| id.clone()) else {
                break;
            };
            open.remove(&oldest);
        }
        open.insert(id.clone(), Wizard { name, mode, words, quiz, confirmed: false, created: now });
        (id, text, quiz)
    }

    /// Checks the quiz answers (position → word, compared without case and outer spaces) and the confirmation. The
    /// answer names the positions that are wrong (German) - nothing about the right words.
    pub fn confirm(&self, id: &str, answers: &[(usize, String)], written: bool, now: i64) -> Result<(), String> {
        let mut open = self.lock();
        let wizard = live(&mut open, id, now)?;
        if !written {
            return Err("Bitte bestätige, dass die Wörter auf Papier stehen.".into());
        }
        let words = wizard.words.words();
        let list: Vec<&str> = words.split(' ').collect();
        let mut wrong = Vec::new();
        for position in wizard.quiz {
            let given =
                answers.iter().find(|(asked, _)| *asked == position).map(|(_, word)| word.trim().to_lowercase());
            let right = list.get(position.saturating_sub(1)).copied();
            if given.as_deref() != right || right.is_none() {
                wrong.push(position.to_string());
            }
        }
        if !wrong.is_empty() {
            return Err(format!("Wort {} stimmt nicht - schau noch einmal auf dein Papier.", wrong.join(", ")));
        }
        wizard.confirmed = true;
        Ok(())
    }

    /// Takes a confirmed assistant out (for step 4); it is gone afterwards either way it ends.
    pub fn take(&self, id: &str, now: i64) -> Result<Wizard, String> {
        let mut open = self.lock();
        let confirmed = live(&mut open, id, now)?.confirmed;
        if !confirmed {
            return Err("Erst die Wörter bestätigen (Schritt 2).".into());
        }
        open.remove(id).ok_or_else(|| "Assistent abgelaufen - bitte neu beginnen.".to_owned())
    }

    /// Puts an assistant back after a failed step 4 (e.g. port taken), so the words need not be shown again.
    pub fn put_back(&self, id: String, wizard: Wizard) {
        let mut open = self.lock();
        if open.len() < MAX_WIZARDS {
            open.insert(id, wizard);
        }
    }

    /// Whether an assistant is open and confirmed.
    #[must_use]
    pub fn is_confirmed(&self, id: &str, now: i64) -> bool {
        live(&mut self.lock(), id, now).is_ok_and(|wizard| wizard.confirmed)
    }

    /// Cancels an assistant (its words are wiped).
    pub fn cancel(&self, id: &str) {
        self.lock().remove(id);
    }
}

fn live<'a>(open: &'a mut HashMap<String, Wizard>, id: &str, now: i64) -> Result<&'a mut Wizard, String> {
    open.retain(|_, wizard| now.saturating_sub(wizard.created) < WIZARD_TTL_MS);
    open.get_mut(id).ok_or_else(|| "Assistent abgelaufen - bitte neu beginnen.".to_owned())
}

/// Three different positions 1-24, ascending (uniform: rejection sampling on a byte).
fn quiz_positions(rng: &mut impl RngCore) -> [usize; QUIZ_WORDS] {
    let mut chosen: Vec<usize> = Vec::with_capacity(QUIZ_WORDS);
    let mut byte = [0u8; 1];
    while chosen.len() < QUIZ_WORDS {
        rng.fill_bytes(&mut byte);
        if byte[0] >= 240 {
            continue; // 240 = 10 × 24: keep the choice uniform
        }
        let position = usize::from(byte[0] % 24) + 1;
        if !chosen.contains(&position) {
            chosen.push(position);
        }
    }
    chosen.sort_unstable();
    [chosen[0], chosen[1], chosen[2]]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answers(words: &str, quiz: [usize; 3]) -> Vec<(usize, String)> {
        let list: Vec<&str> = words.split(' ').collect();
        quiz.iter().map(|&position| (position, format!("  {}  ", list[position - 1].to_uppercase()))).collect()
    }

    #[test]
    fn quiz_must_be_passed_before_taking() -> Result<(), String> {
        let wizards = Wizards::default();
        let (id, words, quiz) = wizards.begin("Testnetz".into(), JoinMode::Invite, 0);
        assert_eq!(words.split(' ').count(), 24);
        assert!(quiz[0] < quiz[1] && quiz[1] < quiz[2] && quiz[0] >= 1 && quiz[2] <= 24, "{quiz:?}");
        assert!(wizards.take(&id, 1).is_err(), "not confirmed yet");
        let mut wrong = answers(&words, quiz);
        wrong[1].1 = "zzzz".into();
        let error = wizards.confirm(&id, &wrong, true, 1).err().unwrap_or_default();
        assert!(error.contains(&quiz[1].to_string()) && !error.contains(wrong[0].1.trim()), "{error}");
        assert!(wizards.confirm(&id, &answers(&words, quiz), false, 1).is_err(), "checkbox needed");
        assert!(wizards.confirm(&id, &answers(&words, quiz)[..2], true, 1).is_err(), "all three needed");
        wizards.confirm(&id, &answers(&words, quiz), true, 2)?;
        assert!(wizards.is_confirmed(&id, 3));
        let wizard = wizards.take(&id, 3)?;
        assert_eq!(wizard.words.words().as_str(), words.as_str());
        assert!(wizards.take(&id, 4).is_err(), "taken once");
        wizards.put_back(id.clone(), wizard);
        assert!(wizards.take(&id, 5).is_ok(), "back after a failed step 4");
        Ok(())
    }

    #[test]
    fn expiry_and_bounds() {
        let wizards = Wizards::default();
        let (id, _, _) = wizards.begin("A".into(), JoinMode::Open, 0);
        assert!(wizards.confirm(&id, &[], true, WIZARD_TTL_MS).is_err(), "expired");
        let ids: Vec<String> = (0..6).map(|n| wizards.begin("B".into(), JoinMode::Open, n).0).collect();
        assert_eq!(wizards.lock().len(), MAX_WIZARDS);
        assert!(!wizards.lock().contains_key(&ids[0]), "the oldest went");
        wizards.cancel(&ids[5]);
        assert!(!wizards.lock().contains_key(&ids[5]));
    }

    #[test]
    fn quiz_positions_cover_all_words() {
        let mut seen = [false; 25];
        for _ in 0..2000 {
            for position in quiz_positions(&mut OsRng) {
                seen[position] = true;
            }
        }
        assert!(seen[1..].iter().all(|seen| *seen) && !seen[0]);
    }
}
