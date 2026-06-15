//! Passive and active discovery helpers.
//!
//! Wraps pcap-based detection into async tasks.

use std::ffi::CString;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::task;
use tracing::info;

use crate::engine::stats::Stats;
use crate::ffi;

/// Sends a single ICMPv6 ping6 to `target` from `interface` and returns
/// true if a reply arrives within `timeout_ms` milliseconds.
///
/// The actual blocking pcap wait is capped at 2 s by libty internally;
/// we simply run it on a spawn_blocking thread so the async runtime is free.
pub async fn ping6_alive(
    interface: String,
    target: String,
    _timeout_ms: u64,
) -> Result<bool> {
    let iface  = CString::new(interface).context("null in interface")?;
    let target = CString::new(target).context("null in target")?;

    task::spawn_blocking(move || -> Result<bool> {
        unsafe {
            let src = ffi::thc_get_own_ipv6(
                iface.as_ptr(),
                std::ptr::null_mut(),
                ffi::PREFER_GLOBAL,
            );
            if src.is_null() {
                bail!("no global IPv6 on interface");
            }
            let dst = ffi::thc_resolve6(target.as_ptr());
            if dst.is_null() {
                bail!("cannot resolve target");
            }
            let srcmac = ffi::thc_get_own_mac(iface.as_ptr());
            let dstmac = ffi::thc_get_mac(iface.as_ptr(), src, dst);

            let rc = ffi::thc_ping26(
                iface.as_ptr(), srcmac, dstmac, src, dst,
                16,  // payload size
                1,   // count
            );
            Ok(rc == 0)
        }
    })
    .await
    .context("spawn_blocking panicked")?
}

/// Concurrently pings a list of targets and returns those that responded.
///
/// `concurrency` controls how many pings run simultaneously (tokio tasks).
pub async fn alive_scan(
    interface: String,
    targets: Vec<String>,
    concurrency: usize,
    timeout_ms: u64,
    stats: Arc<Stats>,
) -> Result<Vec<String>> {
    use tokio::sync::Semaphore;
    use futures::future::join_all;

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(targets.len());

    for target in targets {
        let iface2   = interface.clone();
        let target2  = target.clone();
        let sem2     = Arc::clone(&sem);
        let stats2   = Arc::clone(&stats);
        let to       = timeout_ms;

        handles.push(tokio::spawn(async move {
            let _permit = sem2.acquire_owned().await.unwrap();
            match ping6_alive(iface2, target2.clone(), to).await {
                Ok(true) => {
                    stats2.inc_sent();
                    info!(target = %target2, "alive");
                    Some(target2)
                }
                Ok(false) => {
                    stats2.inc_sent();
                    None
                }
                Err(_) => {
                    stats2.inc_errors();
                    None
                }
            }
        }));
    }

    let results: Vec<Option<String>> = join_all(handles)
        .await
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    Ok(results.into_iter().flatten().collect())
}
