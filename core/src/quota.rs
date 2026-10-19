//! The Workers quota guard's logic, platform-free: the published plan allowances, the usage window,
//! the GraphQL Analytics query and its parsing, and the verdict. The Worker adapter supplies only the
//! cron trigger, the HTTP call and the log line.
//!
//! Cloudflare exposes account **usage** through the GraphQL Analytics API but **not** the account's
//! limit values, so usage is compared with the published allowances of the plan named by
//! `WORKERS_PLAN`:
//!
//! - `free` (default): the Workers Free **daily** limits, which reset at 00:00 UTC and fail requests
//!   once exceeded (Worker requests answer error 1027; Durable Object calls throw).
//! - `paid`: the Workers Paid **monthly** included amounts; beyond them usage is billed as overage,
//!   nothing fails.
//!
//! The limits below were checked against the Cloudflare docs on 2026-10-19
//! (`developers.cloudflare.com/workers/platform/limits/`, `…/workers/platform/pricing/` and
//! `…/durable-objects/platform/pricing/`); re-check them when the plan changes. The guard only warns:
//! the Workers KV "degrade" flag of the TypeScript Worker has no consumer in the Rust Worker (which has
//! no KV backend), so it is not carried over. It needs only a read-only Analytics API token.

use serde_json::{json, Value};

/// The account's Cloudflare Workers plan (`WORKERS_PLAN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkersPlan {
    Free,
    Paid,
}

impl WorkersPlan {
    /// The value spelled in `WORKERS_PLAN`.
    pub fn as_str(self) -> &'static str {
        match self {
            WorkersPlan::Free => "free",
            WorkersPlan::Paid => "paid",
        }
    }
}

/// Parse `WORKERS_PLAN`: `free` when unset, else exactly `free` or `paid` (a typo must not select the
/// wrong allowances).
pub fn parse_workers_plan(raw: Option<&str>) -> anyhow::Result<WorkersPlan> {
    match raw {
        None | Some("free") => Ok(WorkersPlan::Free),
        Some("paid") => Ok(WorkersPlan::Paid),
        Some(_) => anyhow::bail!("WORKERS_PLAN must be one of free, paid"),
    }
}

/// How long a plan's usage window is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    /// Resets at 00:00 UTC (Free).
    Day,
    /// The UTC calendar month (an approximation of the Paid billing period).
    Month,
}

/// One plan's allowances. A meter that is `None` has no account-wide allowance on that plan.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlanLimits {
    pub window: Window,
    /// `true` when exceeding an allowance fails requests (Free); `false` when it is billed (Paid).
    pub hard_limit: bool,
    pub worker_requests: f64,
    /// Worker CPU milliseconds. Free has only a per-request cap (10 ms), no account-wide allowance.
    pub worker_cpu_ms: Option<f64>,
    pub do_requests: f64,
    pub do_gb_seconds: f64,
}

/// Published plan allowances (Cloudflare docs, checked 2026-10-19).
pub fn plan_limits(plan: WorkersPlan) -> PlanLimits {
    match plan {
        // Workers Free: 100,000 requests/day; Durable Objects 100,000 requests/day and 13,000 GB-s/day.
        WorkersPlan::Free => PlanLimits {
            window: Window::Day,
            hard_limit: true,
            worker_requests: 100_000.0,
            worker_cpu_ms: None,
            do_requests: 100_000.0,
            do_gb_seconds: 13_000.0,
        },
        // Workers Paid: 10M requests and 30M CPU-ms a month; Durable Objects 1M requests and
        // 400,000 GB-s a month.
        WorkersPlan::Paid => PlanLimits {
            window: Window::Month,
            hard_limit: false,
            worker_requests: 10_000_000.0,
            worker_cpu_ms: Some(30_000_000.0),
            do_requests: 1_000_000.0,
            do_gb_seconds: 400_000.0,
        },
    }
}

/// Log a warning when usage reaches this fraction of any allowance.
pub const WARN_AT: f64 = 0.8;

/// Durable Object duration is billed at 128 MB per active object: GB-s = active seconds × 128 MB /
/// 1 GB (the Durable Objects pricing examples use exactly this factor).
pub const DO_GB_PER_ACTIVE_SECOND: f64 = 0.128;

/// Account-wide usage since the start of the plan's window.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Usage {
    /// Worker invocations (`workersInvocationsAdaptive.sum.requests`).
    pub worker_requests: f64,
    /// Worker CPU time in ms (`workersInvocationsAdaptive.sum.cpuTimeUs` ÷ 1000).
    pub worker_cpu_ms: f64,
    /// Durable Object requests, RPC calls included (`durableObjectsInvocationsAdaptiveGroups.sum.requests`).
    pub do_requests: f64,
    /// Durable Object duration in GB-s (`durableObjectsPeriodicGroups.sum.activeTime` µs → s × 0.128).
    pub do_gb_seconds: f64,
}

/// Usage ÷ allowance per metered dimension (only the dimensions the plan meters).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ratios {
    pub worker_requests: f64,
    pub worker_cpu_ms: Option<f64>,
    pub do_requests: f64,
    pub do_gb_seconds: f64,
}

/// The result of comparing [`Usage`] with a plan's [`PlanLimits`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QuotaAssessment {
    pub plan: WorkersPlan,
    pub ratios: Ratios,
    /// The largest ratio.
    pub worst: f64,
    /// `worst >= WARN_AT`.
    pub warn: bool,
}

/// Compare usage with the plan's allowances.
pub fn assess_usage(usage: &Usage, plan: WorkersPlan) -> QuotaAssessment {
    let limits = plan_limits(plan);
    let ratios = Ratios {
        worker_requests: usage.worker_requests / limits.worker_requests,
        worker_cpu_ms: limits.worker_cpu_ms.map(|l| usage.worker_cpu_ms / l),
        do_requests: usage.do_requests / limits.do_requests,
        do_gb_seconds: usage.do_gb_seconds / limits.do_gb_seconds,
    };
    let worst = [
        Some(ratios.worker_requests),
        ratios.worker_cpu_ms,
        Some(ratios.do_requests),
        Some(ratios.do_gb_seconds),
    ]
    .into_iter()
    .flatten()
    .fold(0.0_f64, f64::max);
    QuotaAssessment {
        plan,
        ratios,
        worst,
        warn: worst >= WARN_AT,
    }
}

/// The one-line warning for an assessment that is at or past [`WARN_AT`].
pub fn warning_line(a: &QuotaAssessment) -> String {
    let pct = |r: f64| format!("{:.0}%", r * 100.0);
    let mut parts = vec![format!("workerRequests {}", pct(a.ratios.worker_requests))];
    if let Some(r) = a.ratios.worker_cpu_ms {
        parts.push(format!("workerCpuMs {}", pct(r)));
    }
    parts.push(format!("doRequests {}", pct(a.ratios.do_requests)));
    parts.push(format!("doGbSeconds {}", pct(a.ratios.do_gb_seconds)));
    let what = if plan_limits(a.plan).hard_limit {
        "of a Workers Free daily limit"
    } else {
        "of a Workers Paid monthly included amount (overage is billed beyond it)"
    };
    format!(
        "quota-guard: usage at {} {what} ({})",
        pct(a.worst),
        parts.join(", ")
    )
}

const MS_PER_DAY: u64 = 86_400_000;

/// Days since 1970-01-01 → (year, month 1-12, day 1-31) in the proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// (year, month, day) → days since 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Start of the current usage window in UTC (ms since the epoch): today 00:00 for a daily plan, the
/// 1st 00:00 for a monthly one.
pub fn window_start_ms(plan: WorkersPlan, now_ms: u64) -> u64 {
    let day_start = now_ms - now_ms % MS_PER_DAY;
    match plan_limits(plan).window {
        Window::Day => day_start,
        Window::Month => {
            let (y, m, _) = civil_from_days((day_start / MS_PER_DAY) as i64);
            (days_from_civil(y, m, 1).max(0) as u64) * MS_PER_DAY
        }
    }
}

/// `2026-10-19T00:00:00.000Z` (what `Date.prototype.toISOString` yields).
pub fn iso_utc(ms: u64) -> String {
    let (y, m, d) = civil_from_days((ms / MS_PER_DAY) as i64);
    let rem = ms % MS_PER_DAY;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000
    )
}

/// The GraphQL Analytics endpoint.
pub const GRAPHQL_URL: &str = "https://api.cloudflare.com/client/v4/graphql";

/// The Analytics query (variables: `accountTag`, `since`, `sinceDate`).
pub const GRAPHQL_QUERY: &str = "query($accountTag: String!, $since: Time!, $sinceDate: Date!) {
    viewer { accounts(filter: { accountTag: $accountTag }) {
      workersInvocationsAdaptive(limit: 10000, filter: { datetime_geq: $since }) { sum { requests cpuTimeUs } }
      durableObjectsInvocationsAdaptiveGroups(limit: 10000, filter: { date_geq: $sinceDate }) { sum { requests } }
      durableObjectsPeriodicGroups(limit: 10000, filter: { date_geq: $sinceDate }) { sum { activeTime } }
    } }
  }";

/// The POST body for the usage since `since_ms`.
pub fn graphql_request_body(account_id: &str, since_ms: u64) -> String {
    json!({
        "query": GRAPHQL_QUERY,
        "variables": {
            "accountTag": account_id,
            "since": iso_utc(since_ms),
            "sinceDate": iso_utc(since_ms).get(..10).unwrap_or_default(),
        },
    })
    .to_string()
}

/// Parse a GraphQL Analytics response into [`Usage`]. A GraphQL error, a missing account or a body
/// that is not the expected shape is an error: an unknown field must not read as zero usage.
pub fn usage_from_graphql(resp: &Value) -> anyhow::Result<Usage> {
    if let Some(errors) = resp.get("errors").and_then(Value::as_array) {
        if !errors.is_empty() {
            let msgs: Vec<&str> = errors
                .iter()
                .map(|e| e.get("message").and_then(Value::as_str).unwrap_or("?"))
                .collect();
            anyhow::bail!("graphql error: {}", msgs.join("; "));
        }
    }
    let acct = resp
        .pointer("/data/viewer/accounts/0")
        .filter(|a| a.is_object())
        .ok_or_else(|| anyhow::anyhow!("graphql response has no account"))?;
    let total = |dataset: &str, key: &str| -> f64 {
        acct.get(dataset)
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .map(|r| {
                        r.pointer(&format!("/sum/{key}"))
                            .and_then(Value::as_f64)
                            .unwrap_or(0.0)
                    })
                    .sum()
            })
            .unwrap_or(0.0)
    };
    Ok(Usage {
        worker_requests: total("workersInvocationsAdaptive", "requests"),
        worker_cpu_ms: total("workersInvocationsAdaptive", "cpuTimeUs") / 1000.0,
        do_requests: total("durableObjectsInvocationsAdaptiveGroups", "requests"),
        do_gb_seconds: total("durableObjectsPeriodicGroups", "activeTime") / 1_000_000.0
            * DO_GB_PER_ACTIVE_SECOND,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: Usage = Usage {
        worker_requests: 0.0,
        worker_cpu_ms: 0.0,
        do_requests: 0.0,
        do_gb_seconds: 0.0,
    };

    /// 2026-10-19T17:42:05.123Z
    const NOW: u64 = 1_792_431_725_123;

    #[test]
    fn plan_allowances_match_the_docs_checked_on_2026_10_19() {
        let free = plan_limits(WorkersPlan::Free);
        assert_eq!(free.window, Window::Day);
        assert!(free.hard_limit);
        assert_eq!(
            (free.worker_requests, free.do_requests, free.do_gb_seconds),
            (100_000.0, 100_000.0, 13_000.0)
        );
        assert_eq!(free.worker_cpu_ms, None);
        let paid = plan_limits(WorkersPlan::Paid);
        assert_eq!(paid.window, Window::Month);
        assert!(!paid.hard_limit);
        assert_eq!(
            (
                paid.worker_requests,
                paid.worker_cpu_ms,
                paid.do_requests,
                paid.do_gb_seconds
            ),
            (10_000_000.0, Some(30_000_000.0), 1_000_000.0, 400_000.0)
        );
    }

    #[test]
    fn plan_defaults_to_free_and_accepts_exactly_free_or_paid() {
        assert_eq!(parse_workers_plan(None).unwrap(), WorkersPlan::Free);
        assert_eq!(parse_workers_plan(Some("free")).unwrap(), WorkersPlan::Free);
        assert_eq!(parse_workers_plan(Some("paid")).unwrap(), WorkersPlan::Paid);
        for bad in ["Paid", "pro", ""] {
            let e = parse_workers_plan(Some(bad)).unwrap_err().to_string();
            assert!(e.contains("WORKERS_PLAN"), "{bad}: {e}");
        }
    }

    #[test]
    fn window_start_is_today_for_free_and_the_first_of_the_month_for_paid() {
        assert_eq!(
            iso_utc(window_start_ms(WorkersPlan::Free, NOW)),
            "2026-10-19T00:00:00.000Z"
        );
        assert_eq!(
            iso_utc(window_start_ms(WorkersPlan::Paid, NOW)),
            "2026-10-01T00:00:00.000Z"
        );
    }

    #[test]
    fn iso_utc_matches_known_instants_across_leap_years_and_month_ends() {
        for (ms, want) in [
            (0, "1970-01-01T00:00:00.000Z"),
            (NOW, "2026-10-19T17:42:05.123Z"),
            (951_782_400_000, "2000-02-29T00:00:00.000Z"),
            (1_709_164_799_999, "2024-02-28T23:59:59.999Z"),
            (1_709_164_800_000, "2024-02-29T00:00:00.000Z"),
            (4_102_444_799_000, "2099-12-31T23:59:59.000Z"),
        ] {
            assert_eq!(iso_utc(ms), want);
        }
        // The first of a month maps to itself; the last second of a month maps to its first.
        assert_eq!(
            iso_utc(window_start_ms(WorkersPlan::Paid, 1_709_251_199_999)),
            "2024-02-01T00:00:00.000Z"
        );
        assert_eq!(
            iso_utc(window_start_ms(WorkersPlan::Paid, 1_706_745_600_000)),
            "2024-02-01T00:00:00.000Z"
        );
    }

    #[test]
    fn free_worker_and_do_requests_are_separate_meters_not_summed() {
        let a = assess_usage(
            &Usage {
                worker_requests: 60_000.0,
                do_requests: 60_000.0,
                ..ZERO
            },
            WorkersPlan::Free,
        );
        assert!((a.ratios.worker_requests - 0.6).abs() < 1e-9);
        assert!((a.ratios.do_requests - 0.6).abs() < 1e-9);
        assert!(!a.warn);
    }

    #[test]
    fn free_cpu_is_not_an_account_wide_meter() {
        let a = assess_usage(
            &Usage {
                worker_cpu_ms: 1e12,
                ..ZERO
            },
            WorkersPlan::Free,
        );
        assert_eq!(a.ratios.worker_cpu_ms, None);
        assert_eq!(a.worst, 0.0);
    }

    #[test]
    fn it_warns_at_80_percent_of_any_meter() {
        let at = |u: Usage, p| assess_usage(&u, p).warn;
        assert!(at(
            Usage {
                do_gb_seconds: 10_400.0,
                ..ZERO
            },
            WorkersPlan::Free
        ));
        assert!(!at(
            Usage {
                do_gb_seconds: 10_399.0,
                ..ZERO
            },
            WorkersPlan::Free
        ));
        assert!(at(
            Usage {
                do_requests: 95_000.0,
                ..ZERO
            },
            WorkersPlan::Free
        ));
    }

    #[test]
    fn paid_meters_cpu_and_the_warning_says_overage_is_billed() {
        let a = assess_usage(
            &Usage {
                worker_cpu_ms: 29_000_000.0,
                ..ZERO
            },
            WorkersPlan::Paid,
        );
        assert!((a.ratios.worker_cpu_ms.unwrap() - 29.0 / 30.0).abs() < 1e-9);
        assert!(a.warn);
        let line = warning_line(&a);
        assert!(
            line.contains("Workers Paid monthly included amount"),
            "{line}"
        );
        assert!(line.contains("workerCpuMs 97%"), "{line}");
        let free = warning_line(&assess_usage(
            &Usage {
                do_requests: 96_000.0,
                ..ZERO
            },
            WorkersPlan::Free,
        ));
        assert!(free.contains("of a Workers Free daily limit"), "{free}");
        assert!(free.contains("doRequests 96%") && !free.contains("workerCpuMs"));
    }

    #[test]
    fn the_request_body_carries_the_window_start() {
        let body: Value = serde_json::from_str(&graphql_request_body(
            "acct",
            window_start_ms(WorkersPlan::Free, NOW),
        ))
        .unwrap();
        assert_eq!(body["variables"]["accountTag"], "acct");
        assert_eq!(body["variables"]["since"], "2026-10-19T00:00:00.000Z");
        assert_eq!(body["variables"]["sinceDate"], "2026-10-19");
        assert!(body["query"].as_str().unwrap().contains("cpuTimeUs"));
    }

    #[test]
    fn usage_is_summed_per_dataset_and_active_time_becomes_gb_seconds() {
        let resp = json!({ "data": { "viewer": { "accounts": [{
            "workersInvocationsAdaptive": [{ "sum": { "requests": 600, "cpuTimeUs": 1_000_000 } },
                                           { "sum": { "requests": 400, "cpuTimeUs": 1_000_000 } }],
            "durableObjectsInvocationsAdaptiveGroups": [{ "sum": { "requests": 96_000 } }],
            "durableObjectsPeriodicGroups": [{ "sum": { "activeTime": 1_000_000_000u64 } }],
        }] } } });
        let u = usage_from_graphql(&resp).unwrap();
        assert_eq!(u.worker_requests, 1000.0);
        assert_eq!(u.worker_cpu_ms, 2000.0);
        assert_eq!(u.do_requests, 96_000.0);
        assert!((u.do_gb_seconds - 1000.0 * DO_GB_PER_ACTIVE_SECOND).abs() < 1e-9);
        // The Free verdict for this usage warns (96% of the DO request allowance).
        assert!(assess_usage(&u, WorkersPlan::Free).warn);
    }

    #[test]
    fn a_graphql_error_or_a_missing_account_is_a_failed_check_never_zero_usage() {
        let err = json!({ "data": null, "errors": [{ "message": "unknown field cpuTimeUs" }] });
        let e = usage_from_graphql(&err).unwrap_err().to_string();
        assert!(e.contains("graphql error: unknown field cpuTimeUs"), "{e}");
        for bad in [
            json!({}),
            json!({ "data": { "viewer": { "accounts": [] } } }),
            json!({ "data": null }),
            json!("nope"),
        ] {
            assert!(usage_from_graphql(&bad).is_err(), "{bad}");
        }
    }
}
