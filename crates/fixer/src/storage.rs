use crate::models::{
    Capability, FindingInput, FindingRecord, OpportunityRecord, ProposalRecord, StatusSnapshot,
    TopEntry, ValidationRecord,
};
use crate::util::now_rfc3339;
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open database {}", path.display()))?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS capabilities (
                name TEXT PRIMARY KEY,
                binary TEXT NOT NULL,
                available INTEGER NOT NULL,
                path TEXT,
                notes TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT UNIQUE,
                package_name TEXT,
                repo_root TEXT,
                ecosystem TEXT,
                metadata_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                summary TEXT NOT NULL,
                details_json TEXT NOT NULL,
                artifact_id INTEGER REFERENCES artifacts(id),
                repo_root TEXT,
                ecosystem TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS opportunities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL UNIQUE REFERENCES findings(id),
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                score INTEGER NOT NULL,
                state TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                repo_root TEXT,
                ecosystem TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS validation_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                opportunity_id INTEGER NOT NULL REFERENCES opportunities(id),
                command TEXT NOT NULL,
                status TEXT NOT NULL,
                output TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                opportunity_id INTEGER NOT NULL REFERENCES opportunities(id),
                engine TEXT NOT NULL,
                state TEXT NOT NULL,
                bundle_path TEXT NOT NULL,
                output_path TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    pub fn sync_capabilities(&self, capabilities: &[Capability]) -> Result<()> {
        let now = now_rfc3339();
        for capability in capabilities {
            self.conn.execute(
                "
                INSERT INTO capabilities (name, binary, available, path, notes, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(name) DO UPDATE SET
                    binary = excluded.binary,
                    available = excluded.available,
                    path = excluded.path,
                    notes = excluded.notes,
                    updated_at = excluded.updated_at
                ",
                params![
                    capability.name,
                    capability.binary,
                    i64::from(capability.available),
                    capability
                        .path
                        .as_ref()
                        .map(|x| x.to_string_lossy().to_string()),
                    capability.notes,
                    now
                ],
            )?;
        }
        Ok(())
    }

    pub fn capability_available(&self, name: &str) -> Result<bool> {
        let value: Option<i64> = self
            .conn
            .query_row(
                "SELECT available FROM capabilities WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.unwrap_or(0) != 0)
    }

    pub fn list_capabilities(&self) -> Result<Vec<Capability>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, binary, available, path, notes FROM capabilities ORDER BY name ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Capability {
                name: row.get(0)?,
                binary: row.get(1)?,
                available: row.get::<_, i64>(2)? != 0,
                path: row
                    .get::<_, Option<String>>(3)?
                    .map(PathBuf::from),
                notes: row.get(4)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn prune_stackless_crash_findings(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            DELETE FROM proposals
            WHERE opportunity_id IN (
                SELECT o.id
                FROM opportunities o
                JOIN findings f ON f.id = o.finding_id
                WHERE f.kind = 'crash'
                  AND (
                    f.details_json NOT LIKE '%\"primary_stack\"%'
                    OR f.details_json LIKE '%\"primary_stack\":[]%'
                    OR f.details_json NOT LIKE '%\"symbolization\"%'
                  )
            );

            DELETE FROM validation_runs
            WHERE opportunity_id IN (
                SELECT o.id
                FROM opportunities o
                JOIN findings f ON f.id = o.finding_id
                WHERE f.kind = 'crash'
                  AND (
                    f.details_json NOT LIKE '%\"primary_stack\"%'
                    OR f.details_json LIKE '%\"primary_stack\":[]%'
                    OR f.details_json NOT LIKE '%\"symbolization\"%'
                  )
            );

            DELETE FROM opportunities
            WHERE finding_id IN (
                SELECT f.id
                FROM findings f
                WHERE f.kind = 'crash'
                  AND (
                    f.details_json NOT LIKE '%\"primary_stack\"%'
                    OR f.details_json LIKE '%\"primary_stack\":[]%'
                    OR f.details_json NOT LIKE '%\"symbolization\"%'
                  )
            );

            DELETE FROM findings
            WHERE kind = 'crash'
              AND (
                details_json NOT LIKE '%\"primary_stack\"%'
                OR details_json LIKE '%\"primary_stack\":[]%'
                OR details_json NOT LIKE '%\"symbolization\"%'
              );

            DELETE FROM proposals
            WHERE opportunity_id IN (
                SELECT o.id
                FROM opportunities o
                JOIN findings f ON f.id = o.finding_id
                WHERE f.kind = 'crash'
                  AND EXISTS (
                    SELECT 1
                    FROM findings newer
                    WHERE newer.kind = 'crash'
                      AND newer.id > f.id
                      AND json_extract(newer.details_json, '$.pid') = json_extract(f.details_json, '$.pid')
                      AND COALESCE(json_extract(newer.details_json, '$.timestamp'), '') = COALESCE(json_extract(f.details_json, '$.timestamp'), '')
                      AND COALESCE(json_extract(newer.details_json, '$.executable'), '') = COALESCE(json_extract(f.details_json, '$.executable'), '')
                  )
            );

            DELETE FROM validation_runs
            WHERE opportunity_id IN (
                SELECT o.id
                FROM opportunities o
                JOIN findings f ON f.id = o.finding_id
                WHERE f.kind = 'crash'
                  AND EXISTS (
                    SELECT 1
                    FROM findings newer
                    WHERE newer.kind = 'crash'
                      AND newer.id > f.id
                      AND json_extract(newer.details_json, '$.pid') = json_extract(f.details_json, '$.pid')
                      AND COALESCE(json_extract(newer.details_json, '$.timestamp'), '') = COALESCE(json_extract(f.details_json, '$.timestamp'), '')
                      AND COALESCE(json_extract(newer.details_json, '$.executable'), '') = COALESCE(json_extract(f.details_json, '$.executable'), '')
                  )
            );

            DELETE FROM opportunities
            WHERE finding_id IN (
                SELECT f.id
                FROM findings f
                WHERE f.kind = 'crash'
                  AND EXISTS (
                    SELECT 1
                    FROM findings newer
                    WHERE newer.kind = 'crash'
                      AND newer.id > f.id
                      AND json_extract(newer.details_json, '$.pid') = json_extract(f.details_json, '$.pid')
                      AND COALESCE(json_extract(newer.details_json, '$.timestamp'), '') = COALESCE(json_extract(f.details_json, '$.timestamp'), '')
                      AND COALESCE(json_extract(newer.details_json, '$.executable'), '') = COALESCE(json_extract(f.details_json, '$.executable'), '')
                  )
            );

            DELETE FROM findings
            WHERE kind = 'crash'
              AND EXISTS (
                SELECT 1
                FROM findings newer
                WHERE newer.kind = 'crash'
                  AND newer.id > findings.id
                  AND json_extract(newer.details_json, '$.pid') = json_extract(findings.details_json, '$.pid')
                  AND COALESCE(json_extract(newer.details_json, '$.timestamp'), '') = COALESCE(json_extract(findings.details_json, '$.timestamp'), '')
                  AND COALESCE(json_extract(newer.details_json, '$.executable'), '') = COALESCE(json_extract(findings.details_json, '$.executable'), '')
              );
            ",
        )?;
        Ok(())
    }

    pub fn upsert_artifact(&self, artifact: &crate::models::ObservedArtifact) -> Result<i64> {
        let now = now_rfc3339();
        let metadata = artifact.metadata.to_string();
        let path = artifact
            .path
            .as_ref()
            .map(|x| x.to_string_lossy().to_string());
        let repo_root = artifact
            .repo_root
            .as_ref()
            .map(|x| x.to_string_lossy().to_string());

        self.conn.execute(
            "
            INSERT INTO artifacts (kind, name, path, package_name, repo_root, ecosystem, metadata_json, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(path) DO UPDATE SET
                kind = excluded.kind,
                name = excluded.name,
                package_name = excluded.package_name,
                repo_root = excluded.repo_root,
                ecosystem = excluded.ecosystem,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            ",
            params![
                artifact.kind,
                artifact.name,
                path,
                artifact.package_name,
                repo_root,
                artifact.ecosystem,
                metadata,
                now
            ],
        )?;

        let id = if artifact.path.is_some() {
            self.conn.query_row(
                "SELECT id FROM artifacts WHERE path = ?1",
                [artifact
                    .path
                    .as_ref()
                    .map(|x| x.to_string_lossy().to_string())
                    .unwrap_or_default()],
                |row| row.get(0),
            )?
        } else {
            self.conn.execute(
                "
                INSERT INTO artifacts (kind, name, path, package_name, repo_root, ecosystem, metadata_json, updated_at)
                VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7)
                ",
                params![
                    artifact.kind,
                    artifact.name,
                    artifact.package_name,
                    repo_root,
                    artifact.ecosystem,
                    metadata,
                    now
                ],
            )?;
            self.conn.last_insert_rowid()
        };
        Ok(id)
    }

    pub fn record_finding(&self, finding: &FindingInput) -> Result<i64> {
        let now = now_rfc3339();
        let artifact_id = if let Some(artifact) = &finding.artifact {
            Some(self.upsert_artifact(artifact)?)
        } else {
            None
        };
        let repo_root = finding
            .repo_root
            .as_ref()
            .or_else(|| finding.artifact.as_ref().and_then(|x| x.repo_root.as_ref()))
            .map(|x| x.to_string_lossy().to_string());
        let ecosystem = finding
            .ecosystem
            .clone()
            .or_else(|| finding.artifact.as_ref().and_then(|x| x.ecosystem.clone()));
        let details_json = finding.details.to_string();

        let existing = self
            .conn
            .query_row(
                "SELECT id, first_seen FROM findings WHERE fingerprint = ?1",
                [finding.fingerprint.as_str()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;

        let finding_id = if let Some((existing_id, _)) = existing {
            self.conn.execute(
                "
                UPDATE findings
                SET kind = ?1,
                    title = ?2,
                    severity = ?3,
                    summary = ?4,
                    details_json = ?5,
                    artifact_id = ?6,
                    repo_root = ?7,
                    ecosystem = ?8,
                    last_seen = ?9
                WHERE id = ?10
                ",
                params![
                    finding.kind,
                    finding.title,
                    finding.severity,
                    finding.summary,
                    details_json,
                    artifact_id,
                    repo_root,
                    ecosystem,
                    now,
                    existing_id
                ],
            )?;
            existing_id
        } else {
            self.conn.execute(
                "
                INSERT INTO findings
                    (kind, title, severity, fingerprint, summary, details_json, artifact_id, repo_root, ecosystem, first_seen, last_seen)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                ",
                params![
                    finding.kind,
                    finding.title,
                    finding.severity,
                    finding.fingerprint,
                    finding.summary,
                    details_json,
                    artifact_id,
                    repo_root,
                    ecosystem,
                    now,
                    now
                ],
            )?;
            self.conn.last_insert_rowid()
        };

        self.upsert_opportunity_from_finding(finding_id)?;
        Ok(finding_id)
    }

    fn upsert_opportunity_from_finding(&self, finding_id: i64) -> Result<()> {
        let mut stmt = self.conn.prepare(
            "
            SELECT
                f.kind,
                f.title,
                f.severity,
                f.summary,
                f.details_json,
                f.repo_root,
                f.ecosystem,
                a.name,
                a.path,
                a.package_name
            FROM findings f
            LEFT JOIN artifacts a ON a.id = f.artifact_id
            WHERE f.id = ?1
            ",
        )?;
        let (kind, title, severity, summary, details_json, repo_root, ecosystem, artifact_name, artifact_path, package_name): (
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = stmt.query_row([finding_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
            ))
        })?;

        let score = score_for(&kind, &severity, repo_root.is_some(), ecosystem.is_some());
        let now = now_rfc3339();
        let evidence = json!({
            "details": serde_json::from_str::<Value>(&details_json).unwrap_or_else(|_| json!({})),
            "artifact_name": artifact_name,
            "artifact_path": artifact_path,
            "package_name": package_name,
            "severity": severity,
        });

        let existing = self
            .conn
            .query_row(
                "SELECT id, created_at FROM opportunities WHERE finding_id = ?1",
                [finding_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;

        if let Some((id, created_at)) = existing {
            self.conn.execute(
                "
                UPDATE opportunities
                SET kind = ?1,
                    title = ?2,
                    score = ?3,
                    summary = ?4,
                    evidence_json = ?5,
                    repo_root = ?6,
                    ecosystem = ?7,
                    updated_at = ?8
                WHERE id = ?9
                ",
                params![
                    kind,
                    title,
                    score,
                    summary,
                    evidence.to_string(),
                    repo_root,
                    ecosystem,
                    now,
                    id
                ],
            )?;
            let _ = created_at;
        } else {
            self.conn.execute(
                "
                INSERT INTO opportunities
                    (finding_id, kind, title, score, state, summary, evidence_json, repo_root, ecosystem, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6, ?7, ?8, ?9, ?10)
                ",
                params![
                    finding_id,
                    kind,
                    title,
                    score,
                    summary,
                    evidence.to_string(),
                    repo_root,
                    ecosystem,
                    now,
                    now
                ],
            )?;
        }
        Ok(())
    }

    pub fn status(&self) -> Result<StatusSnapshot> {
        Ok(StatusSnapshot {
            capabilities: self.count("capabilities")?,
            artifacts: self.count("artifacts")?,
            findings: self.count("findings")?,
            opportunities: self.count("opportunities")?,
            proposals: self.count("proposals")?,
        })
    }

    pub fn list_findings(&self, kind: &str) -> Result<Vec<FindingRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT
                f.id,
                f.kind,
                f.title,
                f.severity,
                f.fingerprint,
                f.summary,
                f.details_json,
                a.name,
                a.path,
                a.package_name,
                COALESCE(f.repo_root, a.repo_root),
                COALESCE(f.ecosystem, a.ecosystem),
                f.first_seen,
                f.last_seen
            FROM findings f
            LEFT JOIN artifacts a ON a.id = f.artifact_id
            WHERE f.kind = ?1
            ORDER BY f.last_seen DESC
            ",
        )?;
        let rows = stmt.query_map([kind], |row| {
            Ok(FindingRecord {
                id: row.get(0)?,
                kind: row.get(1)?,
                title: row.get(2)?,
                severity: row.get(3)?,
                fingerprint: row.get(4)?,
                summary: row.get(5)?,
                details: serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or_else(|_| json!({})),
                artifact_name: row.get(7)?,
                artifact_path: row.get::<_, Option<String>>(8)?.map(PathBuf::from),
                package_name: row.get(9)?,
                repo_root: row.get::<_, Option<String>>(10)?.map(PathBuf::from),
                ecosystem: row.get(11)?,
                first_seen: row.get(12)?,
                last_seen: row.get(13)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn list_opportunities(&self, state: Option<&str>) -> Result<Vec<OpportunityRecord>> {
        let sql = if state.is_some() {
            "SELECT id, finding_id, kind, title, score, state, summary, evidence_json, repo_root, ecosystem, created_at, updated_at
             FROM opportunities WHERE state = ?1 ORDER BY score DESC, updated_at DESC"
        } else {
            "SELECT id, finding_id, kind, title, score, state, summary, evidence_json, repo_root, ecosystem, created_at, updated_at
             FROM opportunities ORDER BY score DESC, updated_at DESC"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(OpportunityRecord {
                id: row.get(0)?,
                finding_id: row.get(1)?,
                kind: row.get(2)?,
                title: row.get(3)?,
                score: row.get(4)?,
                state: row.get(5)?,
                summary: row.get(6)?,
                evidence: serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_else(|_| json!({})),
                repo_root: row.get::<_, Option<String>>(8)?.map(PathBuf::from),
                ecosystem: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        };
        let rows = if let Some(state) = state {
            stmt.query_map([state], mapper)?
        } else {
            stmt.query_map([], mapper)?
        };
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn get_opportunity(&self, id: i64) -> Result<OpportunityRecord> {
        self.conn.query_row(
            "SELECT id, finding_id, kind, title, score, state, summary, evidence_json, repo_root, ecosystem, created_at, updated_at
             FROM opportunities WHERE id = ?1",
            [id],
            |row| {
                Ok(OpportunityRecord {
                    id: row.get(0)?,
                    finding_id: row.get(1)?,
                    kind: row.get(2)?,
                    title: row.get(3)?,
                    score: row.get(4)?,
                    state: row.get(5)?,
                    summary: row.get(6)?,
                    evidence: serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_else(|_| json!({})),
                    repo_root: row.get::<_, Option<String>>(8)?.map(PathBuf::from),
                    ecosystem: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                })
            },
        ).map_err(Into::into)
    }

    pub fn list_top(&self, kind: &str) -> Result<Vec<TopEntry>> {
        let sql = match kind {
            "package" => {
                "SELECT COALESCE(package_name, '(unknown)'), COUNT(*) FROM artifacts GROUP BY COALESCE(package_name, '(unknown)') ORDER BY COUNT(*) DESC, 1 ASC LIMIT 20"
            }
            "repo" => {
                "SELECT COALESCE(repo_root, '(none)'), COUNT(*) FROM artifacts GROUP BY COALESCE(repo_root, '(none)') ORDER BY COUNT(*) DESC, 1 ASC LIMIT 20"
            }
            _ => {
                "SELECT name, COUNT(*) FROM artifacts WHERE kind = 'binary' GROUP BY name ORDER BY COUNT(*) DESC, 1 ASC LIMIT 20"
            }
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([], |row| {
            Ok(TopEntry {
                group: row.get(0)?,
                count: row.get(1)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn list_repo_owners(&self) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT name, COALESCE(repo_root, ''), metadata_json
            FROM artifacts
            WHERE kind = 'repo'
            ORDER BY updated_at DESC
            ",
        )?;
        let rows = stmt.query_map([], |row| {
            let metadata_json: String = row.get(2)?;
            let metadata: Value = serde_json::from_str(&metadata_json).unwrap_or_else(|_| json!({}));
            let owners = metadata
                .get("owners")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            Ok((row.get(0)?, row.get(1)?, owners))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn record_validation(
        &self,
        opportunity_id: i64,
        command: &str,
        status: &str,
        output: &str,
    ) -> Result<i64> {
        let created_at = now_rfc3339();
        self.conn.execute(
            "
            INSERT INTO validation_runs (opportunity_id, command, status, output, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ",
            params![opportunity_id, command, status, output, created_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_validations(&self, opportunity_id: i64) -> Result<Vec<ValidationRecord>> {
        let mut stmt = self.conn.prepare(
            "
            SELECT id, opportunity_id, command, status, output, created_at
            FROM validation_runs
            WHERE opportunity_id = ?1
            ORDER BY created_at DESC
            ",
        )?;
        let rows = stmt.query_map([opportunity_id], |row| {
            Ok(ValidationRecord {
                id: row.get(0)?,
                opportunity_id: row.get(1)?,
                command: row.get(2)?,
                status: row.get(3)?,
                output: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn create_proposal(
        &self,
        opportunity_id: i64,
        engine: &str,
        state: &str,
        bundle_path: &Path,
        output_path: Option<&Path>,
    ) -> Result<ProposalRecord> {
        let now = now_rfc3339();
        self.conn.execute(
            "
            INSERT INTO proposals (opportunity_id, engine, state, bundle_path, output_path, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ",
            params![
                opportunity_id,
                engine,
                state,
                bundle_path.to_string_lossy().to_string(),
                output_path.map(|x| x.to_string_lossy().to_string()),
                now,
                now
            ],
        )?;
        Ok(ProposalRecord {
            id: self.conn.last_insert_rowid(),
            opportunity_id,
            engine: engine.to_string(),
            state: state.to_string(),
            bundle_path: bundle_path.to_path_buf(),
            output_path: output_path.map(PathBuf::from),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn get_proposal(&self, id: i64) -> Result<ProposalRecord> {
        self.conn.query_row(
            "
            SELECT id, opportunity_id, engine, state, bundle_path, output_path, created_at, updated_at
            FROM proposals WHERE id = ?1
            ",
            [id],
            |row| {
                Ok(ProposalRecord {
                    id: row.get(0)?,
                    opportunity_id: row.get(1)?,
                    engine: row.get(2)?,
                    state: row.get(3)?,
                    bundle_path: PathBuf::from(row.get::<_, String>(4)?),
                    output_path: row.get::<_, Option<String>>(5)?.map(PathBuf::from),
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        ).map_err(Into::into)
    }

    fn count(&self, table: &str) -> Result<i64> {
        self.conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
            .map_err(Into::into)
    }
}

fn score_for(kind: &str, severity: &str, has_repo: bool, has_ecosystem: bool) -> i64 {
    let base = match kind {
        "crash" => 90,
        "hotspot" => 75,
        "warning" => 60,
        "repo" => 35,
        _ => 25,
    };
    let severity_boost = match severity {
        "critical" => 10,
        "high" => 8,
        "medium" => 4,
        "low" => 1,
        _ => 0,
    };
    base + severity_boost + i64::from(has_repo) * 5 + i64::from(has_ecosystem) * 3
}

#[cfg(test)]
mod tests {
    use super::Store;
    use crate::models::FindingInput;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn records_findings_and_opportunities() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("fixer.sqlite")).unwrap();
        store
            .record_finding(&FindingInput {
                kind: "warning".to_string(),
                title: "Example warning".to_string(),
                severity: "medium".to_string(),
                fingerprint: "abc".to_string(),
                summary: "warning summary".to_string(),
                details: json!({"line": "warning: test"}),
                artifact: None,
                repo_root: None,
                ecosystem: None,
            })
            .unwrap();
        let status = store.status().unwrap();
        assert_eq!(status.findings, 1);
        assert_eq!(status.opportunities, 1);
    }
}
