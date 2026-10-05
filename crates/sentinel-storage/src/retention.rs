//! Retention: bounded local storage by policy.
//!
//! Sentinel stores flow history and traffic samples, never packets, but even aggregates grow
//! without bound. Retention makes the growth finite and explicit: the user picks a period, and
//! a job enforces it.
//!
//! The job runs at session start and then on an interval. It reports what it deleted so the
//! UI and CLI can show it, rather than silently reclaiming space.

use sentinel_common::clock;
use sentinel_common::config::{AppConfig, RetentionPeriod};

use crate::db::Database;
use crate::error::Result;

/// What a retention pass removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Flow rows deleted.
    pub flows_removed: u64,
    /// Traffic sample rows deleted.
    pub samples_removed: u64,
    /// Whether anything at all was removed.
    pub ran: bool,
}

impl CleanupReport {
    /// True when the pass removed nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.flows_removed == 0 && self.samples_removed == 0
    }

    /// One-line summary for logs and the CLI.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "retention removed {} flows and {} traffic samples",
            self.flows_removed, self.samples_removed
        )
    }
}

/// Enforces configured retention on a database.
pub struct RetentionJob {
    flows_cutoff: Option<u64>,
    samples_cutoff: Option<u64>,
    last_run_us: Option<u64>,
    interval_us: u64,
}

impl RetentionJob {
    /// Builds a job from the configured retention policy.
    ///
    /// `now_us` is passed in rather than read from the clock so the cutoff arithmetic is
    /// testable without sleeping.
    #[must_use]
    pub fn from_config(config: &AppConfig, now_us: u64) -> Self {
        Self {
            flows_cutoff: cutoff(config.retention.flows, now_us),
            samples_cutoff: cutoff(config.retention.traffic_samples, now_us),
            last_run_us: None,
            interval_us: 3_600_000_000, // hourly
        }
    }

    /// Overrides the run interval, for tests and for the CLI's short-lived mode.
    #[must_use]
    pub fn with_interval_us(mut self, interval_us: u64) -> Self {
        self.interval_us = interval_us.max(1);
        self
    }

    /// Cutoff for flow rows, when retention is finite.
    #[must_use]
    pub const fn flows_cutoff(&self) -> Option<u64> {
        self.flows_cutoff
    }

    /// Cutoff for traffic samples, when retention is finite.
    #[must_use]
    pub const fn samples_cutoff(&self) -> Option<u64> {
        self.samples_cutoff
    }

    /// True when enough time has passed since the last run.
    #[must_use]
    pub fn is_due(&self, now_us: u64) -> bool {
        match self.last_run_us {
            None => true,
            Some(last) => now_us.saturating_sub(last) >= self.interval_us,
        }
    }

    /// Records that a sweep ran at `now_us`.
    ///
    /// Separate from running the sweep, because the engine hands the sweep to the storage
    /// writer thread: the engine must only mark the job done once the writer has accepted it.
    pub fn mark_ran(&mut self, now_us: u64) {
        self.last_run_us = Some(now_us);
    }

    /// Runs the cleanup if it is due, then records that it ran.
    ///
    /// # Errors
    /// Propagates SQLite failures from the delete statements.
    pub fn run_if_due(&mut self, database: &mut Database, now_us: u64) -> Result<CleanupReport> {
        if !self.is_due(now_us) {
            return Ok(CleanupReport::default());
        }
        let report = self.run(database)?;
        self.mark_ran(now_us);
        Ok(report)
    }

    /// Runs the cleanup unconditionally.
    ///
    /// Cutoffs are fixed when the job is built, so no clock is needed here: a caller that wants
    /// fresh cutoffs rebuilds the job with [`RetentionJob::from_config`].
    ///
    /// # Errors
    /// Propagates SQLite failures from the delete statements.
    pub fn run(&self, database: &mut Database) -> Result<CleanupReport> {
        let mut report = CleanupReport {
            ran: true,
            ..CleanupReport::default()
        };

        if let Some(cutoff) = self.flows_cutoff {
            report.flows_removed = database.delete_flows_before(cutoff)?;
        }
        if let Some(cutoff) = self.samples_cutoff {
            report.samples_removed = database.delete_samples_before(cutoff)?;
        }

        if !report.is_empty() {
            tracing::info!(
                flows = report.flows_removed,
                samples = report.samples_removed,
                "retention cleanup applied"
            );
        }
        Ok(report)
    }
}

/// Computes the delete cutoff for a retention period, or `None` when data is kept forever.
fn cutoff(period: RetentionPeriod, now_us: u64) -> Option<u64> {
    period
        .as_secs()
        .map(|seconds| now_us.saturating_sub(seconds * 1_000_000))
}

/// Current time, used by callers that do not track their own clock.
#[must_use]
pub fn now_us() -> u64 {
    clock::now_unix_micros()
}

#[cfg(test)]
mod tests {
    use sentinel_common::config::RetentionConfig;

    use super::*;
    use crate::db::DatabaseOptions;
    use sentinel_common::packet::TransportProtocol;
    use sentinel_flow::aggregate::TrafficSample;
    use sentinel_flow::flow::{Flow, FlowState};
    use sentinel_flow::key::{Endpoint, FlowKey};

    use crate::schema::FlowRecord;

    /// A fixed reference time: 2025-01-01T00:00:00Z.
    const NOW: u64 = 1_735_689_600_000_000;

    fn config_with(flows: RetentionPeriod, samples: RetentionPeriod) -> AppConfig {
        AppConfig {
            retention: RetentionConfig {
                flows,
                traffic_samples: samples,
            },
            ..AppConfig::default()
        }
    }

    fn database() -> Database {
        Database::open_in_memory(DatabaseOptions::default()).expect("in-memory database")
    }

    fn flow(age_seconds: u64, port: u16) -> Flow {
        Flow {
            key: FlowKey::new(
                TransportProtocol::Tcp,
                Endpoint::new("192.168.1.10".parse().expect("valid"), Some(port)),
                Endpoint::new("93.184.216.34".parse().expect("valid"), Some(443)),
            ),
            state: FlowState::Established,
            first_seen_us: NOW - age_seconds * 1_000_000,
            last_seen_us: NOW - age_seconds * 1_000_000,
            bytes_sent: 10,
            bytes_received: 20,
            packets_sent: 1,
            packets_received: 2,
            service: Some("HTTPS".to_string()),
            domain: None,
            process: None,
            risk_score: None,
            alert_count: 0,
            tags: Default::default(),
            initiator: None,
        }
    }

    #[test]
    fn cutoffs_follow_the_configured_period() {
        let job = RetentionJob::from_config(
            &config_with(RetentionPeriod::Hours24, RetentionPeriod::Days7),
            NOW,
        );
        assert_eq!(job.flows_cutoff(), Some(NOW - 86_400 * 1_000_000));
        assert_eq!(job.samples_cutoff(), Some(NOW - 604_800 * 1_000_000));
    }

    #[test]
    fn custom_periods_are_honoured() {
        let job = RetentionJob::from_config(
            &config_with(RetentionPeriod::Custom(2), RetentionPeriod::Custom(1)),
            NOW,
        );
        assert_eq!(job.flows_cutoff(), Some(NOW - 172_800 * 1_000_000));
        assert_eq!(job.samples_cutoff(), Some(NOW - 86_400 * 1_000_000));
    }

    #[test]
    fn forever_means_no_cutoff() {
        let job = RetentionJob::from_config(
            &config_with(RetentionPeriod::Forever, RetentionPeriod::Forever),
            NOW,
        );
        assert_eq!(job.flows_cutoff(), None);
        assert_eq!(job.samples_cutoff(), None);
    }

    #[test]
    fn the_job_runs_once_then_waits_for_the_interval() {
        let mut job = RetentionJob::from_config(
            &config_with(RetentionPeriod::Days30, RetentionPeriod::Days30),
            NOW,
        )
        .with_interval_us(1_000_000);

        assert!(job.is_due(NOW), "a fresh job is due immediately");

        let mut database = database();
        job.run_if_due(&mut database, NOW).expect("first run");
        assert!(!job.is_due(NOW), "a job that just ran is not due again");
        assert!(!job.is_due(NOW + 999_999), "still inside the interval");
        assert!(job.is_due(NOW + 1_000_000), "the interval has elapsed");
    }

    #[test]
    fn a_skipped_run_returns_an_empty_report() {
        let mut job = RetentionJob::from_config(
            &config_with(RetentionPeriod::Days30, RetentionPeriod::Days30),
            NOW,
        )
        .with_interval_us(1_000_000);
        let mut database = database();

        job.run_if_due(&mut database, NOW).expect("first run");
        let skipped = job.run_if_due(&mut database, NOW).expect("second run");

        assert!(!skipped.ran, "a skipped run must say so");
        assert!(skipped.is_empty());
    }

    #[test]
    fn cleanup_deletes_only_data_older_than_the_cutoff() {
        let mut database = database();
        // 31 days, 7 days and 1 hour old. The oldest is strictly beyond the 30-day cutoff;
        // the other two are inside it.
        let ages = [31 * 86_400u64, 7 * 86_400, 3_600];
        for (index, age) in ages.iter().enumerate() {
            database
                .upsert_flow(&FlowRecord::new(flow(*age, 50_001 + index as u16)))
                .expect("write flow");
            database
                .upsert_traffic_sample(&TrafficSample {
                    bucket_start_us: NOW - age * 1_000_000,
                    ..TrafficSample::default()
                })
                .expect("write sample");
        }

        let job = RetentionJob::from_config(
            &config_with(RetentionPeriod::Days30, RetentionPeriod::Days30),
            NOW,
        );
        let report = job.run(&mut database).expect("cleanup");

        assert_eq!(
            report.flows_removed, 1,
            "only the 31-day-old flow is past the cutoff"
        );
        assert_eq!(report.samples_removed, 1);
        assert!(report.ran);
        assert!(!report.is_empty());
        assert_eq!(database.row_count("flows").expect("count"), 2);
    }

    #[test]
    fn forever_retention_removes_nothing() {
        let mut database = database();
        database
            .upsert_flow(&FlowRecord::new(flow(100_000_000, 50_001)))
            .expect("write ancient flow");

        let job = RetentionJob::from_config(
            &config_with(RetentionPeriod::Forever, RetentionPeriod::Forever),
            NOW,
        );
        let report = job.run(&mut database).expect("cleanup");

        assert!(report.is_empty());
        assert_eq!(
            database.row_count("flows").expect("count"),
            1,
            "nothing may be deleted"
        );
    }

    #[test]
    fn cleanup_on_an_empty_database_is_harmless() {
        let mut database = database();
        let job = RetentionJob::from_config(&AppConfig::default(), NOW);
        let report = job.run(&mut database).expect("cleanup");
        assert!(report.ran);
        assert!(report.is_empty());
        assert!(report.summary().contains("removed 0"));
    }

    #[test]
    fn a_cutoff_never_underflows_at_the_epoch() {
        // A "now" near the epoch must not wrap into a huge cutoff that deletes nothing.
        let cutoff = cutoff(RetentionPeriod::Days30, 1_000).expect("cutoff");
        assert_eq!(cutoff, 0);
    }
}
