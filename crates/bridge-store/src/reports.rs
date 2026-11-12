//! Reports (schema 9, docs/08 §6): what members report about names and apps, kept at the gateway that received them
//! and at the log operator they are handed on to. Not in the log - who reports what is private.
//!
//! The store checks nothing cryptographic - the node verified the signed report before. It enforces the bounds
//! atomically with the insert: the same report (ID) only once, an open report of the same reporter about the same
//! target within `dedup_ms` counts as a duplicate, at most `per_reporter` reports of one reporter within a day, at most
//! `max_rows` reports per network. A full table makes room by deleting the oldest handled report, else (review 9) the
//! oldest open report of the lowest level below the new reporter's - so members of level 0 can not crowd out the
//! reports of others; open reports of level 0 also age out ([`Store::purge_open_reports`]). The texts are sealed to
//! the log operator inside the signed report (`request`); `text` holds only texts of reports from before that.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, StoreResult};

/// One day (ms).
const DAY_MS: i64 = 24 * 3600 * 1000;

/// A stored report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRow {
    /// ID: Base64url SHA-256 of the canonical bytes of the signed report.
    pub id: String,
    /// Who reported (member ID).
    pub reporter: String,
    /// What is reported (name or ID).
    pub target: String,
    /// Reason (wire name).
    pub reason: String,
    /// Free text (0-500 characters).
    pub text: String,
    /// The signed report (canonical bytes of the member's request).
    pub request: Vec<u8>,
    /// The reporter's key card.
    pub card: Vec<u8>,
    /// The gateway it was handed in at.
    pub via: String,
    /// When this node received it (ms).
    pub received: i64,
    /// `open` or `done`.
    pub status: String,
    /// Admin who set the status last.
    pub handled_by: Option<String>,
    /// When (ms).
    pub handled_at: Option<i64>,
    /// Handed on to the log operator (or this node is it).
    pub forwarded: bool,
    /// The reporter's level when the report came in (0-3).
    pub level: u8,
}

/// Bounds of the report table (decided by the node).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportLimits {
    /// Most reports per network.
    pub max_rows: u64,
    /// Most reports of one reporter within a day.
    pub per_reporter: u64,
    /// An open report of the same reporter about the same target within this time is a duplicate.
    pub dedup_ms: i64,
}

impl Default for ReportLimits {
    fn default() -> Self {
        Self { max_rows: 10_000, per_reporter: 10, dedup_ms: DAY_MS }
    }
}

/// What storing a report did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportStored {
    /// New.
    Stored,
    /// Known already (the same report, or an open one of the same reporter about the same target): its ID.
    Duplicate(String),
    /// The reporter reached its limit for the day.
    ReporterLimit,
    /// The table is full of open reports.
    Full,
}

fn row_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReportRow> {
    Ok(ReportRow {
        id: row.get(0)?,
        reporter: row.get(1)?,
        target: row.get(2)?,
        reason: row.get(3)?,
        text: row.get(4)?,
        request: row.get(5)?,
        card: row.get(6)?,
        via: row.get(7)?,
        received: row.get(8)?,
        status: row.get(9)?,
        handled_by: row.get(10)?,
        handled_at: row.get(11)?,
        forwarded: row.get(12)?,
        level: row.get(13)?,
    })
}

const COLUMNS: &str = "id, reporter, target, reason, text, request, card, via, received, status, handled_by, \
                       handled_at, forwarded, level";

impl Store {
    /// Stores a verified report of `net` (see module docs for the bounds).
    pub fn report_put(&self, net: &str, row: &ReportRow, limits: &ReportLimits, now: i64) -> StoreResult<ReportStored> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let known: Option<String> = transaction
            .query_row("SELECT id FROM reports WHERE net = ?1 AND id = ?2", params![net, row.id], |r| r.get(0))
            .optional()?;
        if let Some(id) = known {
            return Ok(ReportStored::Duplicate(id));
        }
        let open: Option<String> = transaction
            .query_row(
                "SELECT id FROM reports WHERE net = ?1 AND reporter = ?2 AND target = ?3 AND status = 'open'
                 AND received >= ?4 ORDER BY received DESC LIMIT 1",
                params![net, row.reporter, row.target, now.saturating_sub(limits.dedup_ms)],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = open {
            return Ok(ReportStored::Duplicate(id));
        }
        let today: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM reports WHERE net = ?1 AND reporter = ?2 AND received >= ?3",
            params![net, row.reporter, now.saturating_sub(DAY_MS)],
            |r| r.get(0),
        )?;
        if u64::try_from(today).unwrap_or(u64::MAX) >= limits.per_reporter {
            return Ok(ReportStored::ReporterLimit);
        }
        let count: i64 = transaction.query_row("SELECT COUNT(*) FROM reports WHERE net = ?1", [net], |r| r.get(0))?;
        if u64::try_from(count).unwrap_or(u64::MAX) >= limits.max_rows {
            let mut removed = transaction.execute(
                "DELETE FROM reports WHERE net = ?1 AND id = (SELECT id FROM reports WHERE net = ?1 AND status = 'done'
                 ORDER BY received, id LIMIT 1)",
                [net],
            )?;
            if removed == 0 {
                removed = transaction.execute(
                    "DELETE FROM reports WHERE net = ?1 AND id = (SELECT id FROM reports WHERE net = ?1 AND status = 'open'
                     AND level < ?2 ORDER BY level, received, id LIMIT 1)",
                    params![net, row.level],
                )?;
            }
            if removed == 0 {
                return Ok(ReportStored::Full);
            }
        }
        transaction.execute(
            &format!(
                "INSERT INTO reports (net, {COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                 ?15)"
            ),
            params![
                net,
                row.id,
                row.reporter,
                row.target,
                row.reason,
                row.text,
                row.request,
                row.card,
                row.via,
                row.received,
                row.status,
                row.handled_by,
                row.handled_at,
                row.forwarded,
                row.level
            ],
        )?;
        transaction.commit()?;
        Ok(ReportStored::Stored)
    }

    /// Reports of `net`, newest first: with `status` only those, with `before` only older than that (ms); at most
    /// `max`.
    pub fn reports_list(
        &self,
        net: &str,
        status: Option<&str>,
        before: Option<i64>,
        max: u32,
    ) -> StoreResult<Vec<ReportRow>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(&format!(
            "SELECT {COLUMNS} FROM reports WHERE net = ?1 AND (?2 IS NULL OR status = ?2) AND received < ?3
             ORDER BY received DESC, id DESC LIMIT ?4"
        ))?;
        let rows = statement
            .query_map(params![net, status, before.unwrap_or(i64::MAX), max], row_of)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// One report.
    pub fn report_get(&self, net: &str, id: &str) -> StoreResult<Option<ReportRow>> {
        let connection = self.lock()?;
        Ok(connection
            .query_row(&format!("SELECT {COLUMNS} FROM reports WHERE net = ?1 AND id = ?2"), params![net, id], row_of)
            .optional()?)
    }

    /// Sets the status of a report (`open`/`done`) and who did it; `false` if there is no such report.
    pub fn report_set_status(&self, net: &str, id: &str, status: &str, by: &str, now: i64) -> StoreResult<bool> {
        let changed = self.lock()?.execute(
            "UPDATE reports SET status = ?3, handled_by = ?4, handled_at = ?5 WHERE net = ?1 AND id = ?2",
            params![net, id, status, by, now],
        )?;
        Ok(changed > 0)
    }

    /// Reports of `net` not handed on yet, received at or after `since` (oldest first, at most `max`).
    pub fn reports_unforwarded(&self, net: &str, since: i64, max: u32) -> StoreResult<Vec<ReportRow>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(&format!(
            "SELECT {COLUMNS} FROM reports WHERE net = ?1 AND forwarded = 0 AND received >= ?2
             ORDER BY received, id LIMIT ?3"
        ))?;
        let rows = statement.query_map(params![net, since, max], row_of)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Marks a report as handed on.
    pub fn report_forwarded(&self, net: &str, id: &str) -> StoreResult<()> {
        self.lock()?.execute("UPDATE reports SET forwarded = 1 WHERE net = ?1 AND id = ?2", params![net, id])?;
        Ok(())
    }

    /// Deletes handled reports handled before `before` (ms). Returns how many.
    pub fn purge_reports(&self, before: i64) -> StoreResult<usize> {
        Ok(self.lock()?.execute("DELETE FROM reports WHERE status = 'done' AND handled_at < ?1", [before])?)
    }

    /// Deletes open reports of reporters below `level` received before `before` (ms) - they age out (review 9).
    /// Returns how many.
    pub fn purge_open_reports(&self, level: u8, before: i64) -> StoreResult<usize> {
        Ok(self.lock()?.execute(
            "DELETE FROM reports WHERE status = 'open' AND level < ?1 AND received < ?2",
            params![level, before],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StoreError;

    const NOW: i64 = 1_794_200_000_000;

    fn row(id: &str, reporter: &str, target: &str, received: i64) -> ReportRow {
        ReportRow {
            id: id.into(),
            reporter: reporter.into(),
            target: target.into(),
            reason: "phishing".into(),
            text: "sieht aus wie meine Bank".into(),
            request: b"{}".to_vec(),
            card: b"{}".to_vec(),
            via: "gw".into(),
            received,
            status: "open".into(),
            handled_by: None,
            handled_at: None,
            forwarded: false,
            level: 1,
        }
    }

    #[test]
    fn bounds_duplicates_and_status() -> Result<(), StoreError> {
        let store = Store::open_in_memory()?;
        let limits = ReportLimits { max_rows: 3, per_reporter: 2, dedup_ms: DAY_MS };
        assert_eq!(store.report_put("n", &row("a", "alice", "shop", NOW), &limits, NOW)?, ReportStored::Stored);
        // The same ID, and an open report of the same reporter about the same target: duplicates.
        assert_eq!(
            store.report_put("n", &row("a", "alice", "x", NOW), &limits, NOW)?,
            ReportStored::Duplicate("a".into())
        );
        assert_eq!(
            store.report_put("n", &row("b", "alice", "shop", NOW), &limits, NOW)?,
            ReportStored::Duplicate("a".into())
        );
        assert_eq!(store.report_put("n", &row("c", "alice", "other", NOW), &limits, NOW)?, ReportStored::Stored);
        // Two a day per reporter.
        assert_eq!(store.report_put("n", &row("d", "alice", "third", NOW), &limits, NOW)?, ReportStored::ReporterLimit);
        assert_eq!(store.report_put("n", &row("e", "bob", "shop", NOW), &limits, NOW)?, ReportStored::Stored);
        // Full of open reports: refused; once one is done, it makes room.
        assert_eq!(store.report_put("n", &row("f", "carol", "shop", NOW), &limits, NOW)?, ReportStored::Full);
        assert!(store.report_set_status("n", "a", "done", "admin", NOW + 1)?);
        assert!(!store.report_set_status("n", "zz", "done", "admin", NOW + 1)?);
        assert_eq!(store.report_put("n", &row("f", "carol", "shop", NOW + 2), &limits, NOW + 2)?, ReportStored::Stored);
        assert!(store.report_get("n", "a")?.is_none(), "the oldest done one went");
        // Another network has its own table; lists are newest first, filtered and paged.
        assert_eq!(store.report_put("m", &row("a", "alice", "shop", NOW), &limits, NOW)?, ReportStored::Stored);
        let open = store.reports_list("n", Some("open"), None, 10)?;
        assert_eq!(open.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["f", "e", "c"]);
        assert_eq!(store.reports_list("n", None, Some(NOW + 2), 10)?.len(), 2);
        assert_eq!(store.reports_unforwarded("n", NOW, 1)?.len(), 1);
        store.report_forwarded("n", "c")?;
        assert_eq!(store.reports_unforwarded("n", NOW, 10)?.len(), 2);
        // A new day: the reporter may report again.
        let later = NOW + DAY_MS + 1;
        assert!(store.report_set_status("n", "c", "done", "admin", later)?);
        assert_eq!(store.report_put("n", &row("g", "alice", "third", later), &limits, later)?, ReportStored::Stored);
        assert!(store.report_get("n", "c")?.is_none(), "the full table made room with the done one");
        assert!(store.report_set_status("n", "f", "done", "admin", later)?);
        assert_eq!(store.purge_reports(later)?, 0, "only handled before");
        assert_eq!(store.purge_reports(later + 1)?, 1);
        assert!(store.report_get("n", "f")?.is_none());
        Ok(())
    }

    /// Review 9, finding 6: a table full of open reports once refused every new one - members of level 0 could fill it
    /// for everybody. Now a report makes room with the oldest open report of a lower level (level 0 first); reports of
    /// the same or a higher level stay, and open reports of level 0 age out.
    #[test]
    fn open_reports_of_lower_levels_make_room() -> Result<(), StoreError> {
        let store = Store::open_in_memory()?;
        let limits = ReportLimits { max_rows: 3, per_reporter: 10, dedup_ms: DAY_MS };
        let at =
            |level: u8, id: &str, reporter: &str, received: i64| ReportRow { level, ..row(id, reporter, id, received) };
        assert_eq!(store.report_put("n", &at(1, "a", "alice", NOW), &limits, NOW)?, ReportStored::Stored);
        assert_eq!(store.report_put("n", &at(0, "b", "spam1", NOW + 1), &limits, NOW + 1)?, ReportStored::Stored);
        assert_eq!(store.report_put("n", &at(0, "c", "spam2", NOW + 2), &limits, NOW + 2)?, ReportStored::Stored);
        // Level 0 can not push out level 0 (nor anybody else): full.
        assert_eq!(store.report_put("n", &at(0, "d", "spam3", NOW + 3), &limits, NOW + 3)?, ReportStored::Full);
        // Level 2 pushes out the oldest of level 0 first, then the next one; level 1 stays.
        assert_eq!(store.report_put("n", &at(2, "e", "bea", NOW + 4), &limits, NOW + 4)?, ReportStored::Stored);
        assert!(store.report_get("n", "b")?.is_none() && store.report_get("n", "c")?.is_some());
        assert_eq!(store.report_put("n", &at(2, "f", "bea", NOW + 5), &limits, NOW + 5)?, ReportStored::Stored);
        assert!(store.report_get("n", "c")?.is_none() && store.report_get("n", "a")?.is_some());
        assert_eq!(store.report_put("n", &at(1, "g", "carl", NOW + 6), &limits, NOW + 6)?, ReportStored::Full);
        assert_eq!(store.report_get("n", "e")?.map(|row| row.level), Some(2), "the level is kept");
        // Open reports of level 0 age out; others stay.
        assert_eq!(store.report_put("m", &at(0, "x", "spam1", NOW), &limits, NOW)?, ReportStored::Stored);
        assert_eq!(store.report_put("m", &at(1, "y", "alice", NOW), &limits, NOW)?, ReportStored::Stored);
        assert_eq!(store.purge_open_reports(1, NOW + 1)?, 1);
        assert!(store.report_get("m", "x")?.is_none() && store.report_get("m", "y")?.is_some());
        Ok(())
    }
}
