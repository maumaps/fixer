//! Self-healing postgres handle.
//!
//! A `tokio_postgres::Client` is bound to exactly one TCP connection. When the
//! server goes away — a restart hands out `57P01 terminating connection due to
//! administrator command` and then closes the socket — that client is dead for
//! good and every later statement fails with `connection closed`. A handle that
//! stores a single client therefore turns one postgres restart into a permanent
//! outage that only a process restart clears.
//!
//! [`PgClient`] keeps the connection string next to the current client and
//! swaps in a fresh client the first time it notices the old one is closed, so
//! the process heals itself once postgres is back.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::RwLock;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Error, NoTls, Row, ToStatement};

/// Which kind of statement failed, for [`should_retry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DbOp {
    /// A statement with no server-side effect (`query`, `query_one`, `query_opt`).
    Read,
    /// A statement that may have changed server state (`execute`, `batch_execute`).
    Write,
}

/// Decide whether a failed statement may be replayed on a fresh connection.
///
/// Reads are replayed once when the failure was the connection dropping: the
/// statement had no effect, so running it again on a new connection is
/// indistinguishable from having run it on a healthy one.
///
/// Writes are never replayed. `connection closed` does not say whether the
/// server applied the statement before the socket died, so a blind retry can
/// duplicate an insert or double-apply an update. The caller gets the error and
/// decides; the handle has already dropped the dead client, so the caller's
/// *next* call reconnects.
pub(crate) fn should_retry(op: DbOp, connection_closed: bool) -> bool {
    matches!(op, DbOp::Read) && connection_closed
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

    /// Replace the stored client unless another task already did it.
    async fn reconnect(&self) -> Result<Arc<Client>, Error> {
        let mut slot = self.client.write().await;
        if !slot.is_closed() {
            // Lost the race to another caller; its client is fresh.
            return Ok(Arc::clone(&slot));
        }
        let observed = self.liveness.observe();
        let client = Self::spawn_connection(&self.url, &self.liveness).await?;
        *slot = Arc::clone(&client);
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

    /// Like [`Client::query`], retried once on a fresh connection if the
    /// connection dropped.
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
            Err(error) if should_retry(DbOp::Read, error.is_closed()) => {
                self.reconnect().await?.query(statement, params).await
            }
            Err(error) => Err(error),
        }
    }

    /// Like [`Client::query_one`], retried once on a fresh connection if the
    /// connection dropped.
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
            Err(error) if should_retry(DbOp::Read, error.is_closed()) => {
                self.reconnect().await?.query_one(statement, params).await
            }
            Err(error) => Err(error),
        }
    }

    /// Like [`Client::query_opt`], retried once on a fresh connection if the
    /// connection dropped.
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
            Err(error) if should_retry(DbOp::Read, error.is_closed()) => {
                self.reconnect().await?.query_opt(statement, params).await
            }
            Err(error) => Err(error),
        }
    }

    /// Like [`Client::execute`].
    ///
    /// Never auto-retried: a write that fails with `connection closed` may
    /// already have been applied by the server, so replaying it could duplicate
    /// the effect. The dead client is still dropped, so the next call
    /// reconnects.
    pub async fn execute<T>(
        &self,
        statement: &T,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error>
    where
        T: ?Sized + ToStatement,
    {
        debug_assert!(!should_retry(DbOp::Write, true));
        self.current().await?.execute(statement, params).await
    }

    /// Like [`Client::batch_execute`].
    ///
    /// Never auto-retried, for the same reason as [`PgClient::execute`]: the
    /// batch may have been applied in part or in full before the connection
    /// dropped.
    pub async fn batch_execute(&self, query: &str) -> Result<(), Error> {
        debug_assert!(!should_retry(DbOp::Write, true));
        self.current().await?.batch_execute(query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn should_retry_read_when_connection_closed() {
        assert!(should_retry(DbOp::Read, true));
    }

    #[test]
    fn should_not_retry_read_when_connection_alive() {
        assert!(!should_retry(DbOp::Read, false));
    }

    #[test]
    fn should_not_retry_write_when_connection_closed() {
        assert!(!should_retry(DbOp::Write, true));
    }

    #[test]
    fn should_not_retry_write_when_connection_alive() {
        assert!(!should_retry(DbOp::Write, false));
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
