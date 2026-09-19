//! Self-healing postgres handle.
//!
//! A `tokio_postgres::Client` is bound to exactly one TCP connection. When the
//! server goes away, that client is dead for good: every later statement fails
//! with `connection closed`. A handle that stores a single client therefore
//! turns one postgres restart into a permanent outage that only a process
//! restart clears.
//!
//! [`PgClient`] keeps the connection string next to the current client and
//! swaps in a fresh client as soon as it sees the old one fail, so the process
//! heals itself once postgres is back.
//!
//! A restart is not one failure but three, and the retry rule has to cover all
//! of them. A statement already in flight when the socket dies fails with an
//! `Io` error (`error communicating with the server`) and never reaches the
//! server at all. A statement that arrives while postgres is shutting down gets
//! a real answer: `57P01`, `57P02` or `57P03`. Everything after that fails with
//! `connection closed`. Only the middle case carries a SQLSTATE, so the rule is
//! phrased around whether the server answered — see [`should_retry`].

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::{RwLock, RwLockWriteGuard};
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Error, NoTls, Row, ToStatement};

/// SQLSTATEs postgres reports while it is going down or not yet taking work.
/// A connection that answers with one of these is finished, but the answer
/// itself proves the statement was rejected rather than applied.
const SHUTDOWN_SQLSTATES: [&str; 3] = [
    "57P01", // admin_shutdown
    "57P02", // crash_shutdown
    "57P03", // cannot_connect_now
];

/// Which kind of statement failed, for [`should_retry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DbOp {
    /// A statement with no server-side effect (`query`, `query_one`, `query_opt`).
    Read,
    /// A statement that may have changed server state (`execute`, `batch_execute`).
    Write,
}

/// Whether the failure means this connection is finished, rather than the
/// statement being wrong.
///
/// `db_error_sqlstate` is the SQLSTATE the server reported, or `None` when the
/// server reported nothing at all — an IO, protocol or already-closed failure.
/// `None` is the interesting case: no server answer means the statement did not
/// run, and the connection that should have carried it is gone.
pub(crate) fn connection_is_at_fault(db_error_sqlstate: Option<&str>) -> bool {
    match db_error_sqlstate {
        None => true,
        Some(code) => SHUTDOWN_SQLSTATES.contains(&code),
    }
}

/// Decide whether a failed statement may be replayed on a fresh connection.
///
/// A read is replayed once when the connection, not the statement, was at
/// fault: a read has no side effect, so running it again on a new connection is
/// indistinguishable from having run it on a healthy one.
///
/// A write is never replayed. Neither a dead socket nor a shutdown code says
/// whether the server applied the statement before the connection died, so a
/// blind retry can duplicate an insert or double-apply an update. The caller
/// gets the error and decides; the handle still drops the broken connection, so
/// the caller's *next* call runs on a fresh one.
///
/// Any other SQLSTATE — `42601` syntax_error, `23505` unique_violation — is the
/// server answering correctly about a bad statement. Replaying it would fail
/// identically forever, so neither reads nor writes retry.
pub(crate) fn should_retry(op: DbOp, db_error_sqlstate: Option<&str>) -> bool {
    matches!(op, DbOp::Read) && connection_is_at_fault(db_error_sqlstate)
}

/// The SQLSTATE the server reported for this error, if the server reported one.
fn db_error_sqlstate(error: &Error) -> Option<&str> {
    error.code().map(|state| state.code())
}

/// Tracks when the current connection was last observed dead, so a reconnect
/// can report how long the handle was unusable.
#[derive(Debug, Default)]
struct Liveness {
    dead_since: Mutex<Option<Instant>>,
}

impl Liveness {
    /// Record that the connection just died, keeping the earliest observation.
    fn mark_dead(&self, at: Instant) {
        let mut slot = self.lock();
        if slot.is_none() {
            *slot = Some(at);
        }
    }

    /// Read the current observation without consuming it.
    fn observe(&self) -> Option<Instant> {
        *self.lock()
    }

    /// Clear the observation, but only if it is still the one we acted on.
    ///
    /// A replacement connection can die while we are installing it; clearing
    /// unconditionally would erase that fresher observation.
    fn clear_if(&self, observed: Option<Instant>) {
        let mut slot = self.lock();
        if *slot == observed {
            *slot = None;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        // A panic in a connection-driver task must not poison the whole handle
        // into returning errors forever; the payload is a single `Option`.
        self.dead_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A postgres client that reconnects instead of staying dead.
///
/// The inherent methods mirror the [`Client`] methods the callers already use,
/// with the same names, signatures and `tokio_postgres::Error` error type, so
/// call sites keep chaining `?` and `map_err` unchanged.
pub struct PgClient {
    url: String,
    client: RwLock<Arc<Client>>,
    liveness: Arc<Liveness>,
}

impl PgClient {
    /// Connect to `url` and start driving the connection.
    pub async fn connect(url: &str) -> Result<Self, Error> {
        let liveness = Arc::new(Liveness::default());
        let client = Self::spawn_connection(url, &liveness).await?;
        Ok(Self {
            url: url.to_string(),
            client: RwLock::new(client),
            liveness,
        })
    }

    /// Return a usable client, reconnecting first if the current one is closed.
    pub async fn current(&self) -> Result<Arc<Client>, Error> {
        {
            let client = self.client.read().await;
            if !client.is_closed() {
                return Ok(Arc::clone(&client));
            }
        }
        self.reconnect().await
    }

    /// Replace the stored client because it is closed.
    async fn reconnect(&self) -> Result<Arc<Client>, Error> {
        let mut slot = self.client.write().await;
        if !slot.is_closed() {
            // Lost the race to another caller; its client is fresh.
            return Ok(Arc::clone(&slot));
        }
        self.install(&mut slot).await
    }

    /// Replace `stale` after a statement failed on it.
    ///
    /// Identity, not `is_closed()`, decides: a statement can fail on a socket
    /// that has not been reaped yet, and such a client would pass an
    /// `is_closed()` check and be handed straight back to the retry.
    async fn replace(&self, stale: &Arc<Client>) -> Result<Arc<Client>, Error> {
        let mut slot = self.client.write().await;
        if !Arc::ptr_eq(&slot, stale) {
            // Another caller already replaced this client.
            return Ok(Arc::clone(&slot));
        }
        self.install(&mut slot).await
    }

    /// Connect and store the result, with the caller already holding the lock.
    async fn install(
        &self,
        slot: &mut RwLockWriteGuard<'_, Arc<Client>>,
    ) -> Result<Arc<Client>, Error> {
        let observed = self.liveness.observe();
        let client = Self::spawn_connection(&self.url, &self.liveness).await?;
        **slot = Arc::clone(&client);
        self.liveness.clear_if(observed);
        tracing::info!(
            dead_for = ?observed.map(|since| since.elapsed()),
            "reconnected to postgres"
        );
        Ok(client)
    }

    /// Open one connection and spawn the task that drives it.
    async fn spawn_connection(url: &str, liveness: &Arc<Liveness>) -> Result<Arc<Client>, Error> {
        let (client, connection) = tokio_postgres::connect(url, NoTls).await?;
        let liveness = Arc::clone(liveness);
        tokio::spawn(async move {
            let outcome = connection.await;
            liveness.mark_dead(Instant::now());
            match outcome {
                Ok(()) => {
                    tracing::warn!("postgres connection lost; will reconnect on next use");
                }
                Err(error) => {
                    tracing::warn!(?error, "postgres connection lost; will reconnect on next use");
                }
            }
        });
        Ok(Arc::new(client))
    }

    /// React to a failed statement: drop the connection when the connection was
    /// at fault, and hand back a fresh client only when the statement may be
    /// replayed on it.
    ///
    /// Both reads and writes come through here, which is what lets a write heal
    /// the handle for the next caller while still refusing to replay itself.
    async fn recover(&self, op: DbOp, stale: &Arc<Client>, error: &Error) -> Option<Arc<Client>> {
        let sqlstate = db_error_sqlstate(error);
        if !connection_is_at_fault(sqlstate) {
            // The connection is healthy; the statement is not. Keep both.
            return None;
        }
        let fresh = match self.replace(stale).await {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "postgres reconnect after a failed statement did not succeed"
                );
                return None;
            }
        };
        should_retry(op, sqlstate).then_some(fresh)
    }

    /// Like [`Client::query`], retried once on a fresh connection when the
    /// connection, not the statement, was at fault.
    pub async fn query<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error>
    where
        T: ?Sized + ToStatement,
    {
        let client = self.current().await?;
        match client.query(statement, params).await {
            Ok(rows) => Ok(rows),
            Err(error) => match self.recover(DbOp::Read, &client, &error).await {
                Some(fresh) => fresh.query(statement, params).await,
                None => Err(error),
            },
        }
    }

    /// Like [`Client::query_one`], retried once on a fresh connection when the
    /// connection, not the statement, was at fault.
    pub async fn query_one<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error>
    where
        T: ?Sized + ToStatement,
    {
        let client = self.current().await?;
        match client.query_one(statement, params).await {
            Ok(row) => Ok(row),
            Err(error) => match self.recover(DbOp::Read, &client, &error).await {
                Some(fresh) => fresh.query_one(statement, params).await,
                None => Err(error),
            },
        }
    }

    /// Like [`Client::query_opt`], retried once on a fresh connection when the
    /// connection, not the statement, was at fault.
    pub async fn query_opt<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error>
    where
        T: ?Sized + ToStatement,
    {
        let client = self.current().await?;
        match client.query_opt(statement, params).await {
            Ok(row) => Ok(row),
            Err(error) => match self.recover(DbOp::Read, &client, &error).await {
                Some(fresh) => fresh.query_opt(statement, params).await,
                None => Err(error),
            },
        }
    }

    /// Like [`Client::execute`].
    ///
    /// Never auto-retried: a write that fails mid-restart may already have been
    /// applied by the server, so replaying it could duplicate the effect. The
    /// handle still heals, so the caller's next call runs on a fresh connection.
    pub async fn execute<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error>
    where
        T: ?Sized + ToStatement,
    {
        let client = self.current().await?;
        match client.execute(statement, params).await {
            Ok(rows) => Ok(rows),
            Err(error) => {
                // `should_retry` is false for every write, so `recover` only
                // drops the broken connection here; it never returns a client
                // to replay on.
                let _never_replayed = self.recover(DbOp::Write, &client, &error).await;
                Err(error)
            }
        }
    }

    /// Like [`Client::batch_execute`].
    ///
    /// Never auto-retried, for the same reason as [`PgClient::execute`]: the
    /// batch may have been applied in part or in full before the connection
    /// died.
    pub async fn batch_execute(&self, query: &str) -> Result<(), Error> {
        let client = self.current().await?;
        match client.batch_execute(query).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let _never_replayed = self.recover(DbOp::Write, &client, &error).await;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The measured failure of a real restart: the socket died mid-statement,
    /// so the server reported no SQLSTATE at all.
    const NO_SERVER_ANSWER: Option<&str> = None;

    #[test]
    fn retries_a_read_when_the_server_did_not_answer() {
        assert!(should_retry(DbOp::Read, NO_SERVER_ANSWER));
    }

    #[test]
    fn retries_a_read_on_admin_shutdown() {
        assert!(should_retry(DbOp::Read, Some("57P01")));
    }

    #[test]
    fn retries_a_read_on_crash_shutdown() {
        assert!(should_retry(DbOp::Read, Some("57P02")));
    }

    #[test]
    fn retries_a_read_on_cannot_connect_now() {
        assert!(should_retry(DbOp::Read, Some("57P03")));
    }

    #[test]
    fn does_not_retry_a_read_on_syntax_error() {
        assert!(!should_retry(DbOp::Read, Some("42601")));
    }

    #[test]
    fn does_not_retry_a_read_on_unique_violation() {
        assert!(!should_retry(DbOp::Read, Some("23505")));
    }

    #[test]
    fn does_not_retry_a_write_when_the_server_did_not_answer() {
        assert!(!should_retry(DbOp::Write, NO_SERVER_ANSWER));
    }

    #[test]
    fn does_not_retry_a_write_on_admin_shutdown() {
        assert!(!should_retry(DbOp::Write, Some("57P01")));
    }

    #[test]
    fn blames_the_connection_when_the_server_did_not_answer() {
        assert!(connection_is_at_fault(NO_SERVER_ANSWER));
    }

    #[test]
    fn blames_the_connection_for_every_shutdown_sqlstate() {
        for code in SHUTDOWN_SQLSTATES {
            assert!(connection_is_at_fault(Some(code)), "{code} ends a connection");
        }
    }

    #[test]
    fn blames_the_statement_for_an_ordinary_sql_error() {
        assert!(!connection_is_at_fault(Some("42601")));
        assert!(!connection_is_at_fault(Some("23505")));
    }

    #[test]
    fn a_write_is_never_replayed_whatever_the_failure() {
        for sqlstate in [NO_SERVER_ANSWER, Some("57P01"), Some("57P02"), Some("57P03")] {
            assert!(
                !should_retry(DbOp::Write, sqlstate),
                "{sqlstate:?} must not replay a write"
            );
        }
    }

    #[test]
    fn liveness_starts_alive() {
        let liveness = Liveness::default();
        assert_eq!(liveness.observe(), None);
    }

    #[test]
    fn liveness_keeps_earliest_death() {
        let liveness = Liveness::default();
        let first = Instant::now();
        let second = first + Duration::from_secs(5);
        liveness.mark_dead(first);
        liveness.mark_dead(second);
        assert_eq!(liveness.observe(), Some(first));
    }

    #[test]
    fn liveness_clears_the_observation_it_acted_on() {
        let liveness = Liveness::default();
        let death = Instant::now();
        liveness.mark_dead(death);
        let observed = liveness.observe();
        liveness.clear_if(observed);
        assert_eq!(liveness.observe(), None);
    }

    #[test]
    fn liveness_keeps_a_fresher_observation() {
        let liveness = Liveness::default();
        let stale = Instant::now();
        let fresh = stale + Duration::from_secs(1);
        liveness.mark_dead(fresh);
        liveness.clear_if(Some(stale));
        assert_eq!(liveness.observe(), Some(fresh));
    }

    #[test]
    fn pg_client_is_shareable_across_tasks() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PgClient>();
    }
}
