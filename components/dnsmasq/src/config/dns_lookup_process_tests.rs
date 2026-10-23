//! Resolver process contracts, run outside the threaded test harness.
use super::*;
use crate::config::{dns::parse_rules, EncodedArg};
fn finish(lookup: &mut EndpointLookup) -> LookupResult {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let before = lookup.bytes.len();
        let result = lookup.step();
        assert!(lookup.bytes.len() - before <= 4096);
        if let Some(result) = result {
            return result;
        }
        assert!(std::time::Instant::now() < deadline, "lookup timeout");
        let mut fds = Vec::new();
        lookup.append_poll_fds(&mut fds);
        dnsmasq_platform::poll::poll_fds(&mut fds, 10).unwrap();
    }
}

pub(super) fn run() {
    eprintln!("process test: resolver::fork_lookup_preserves_rules_and_cancel_reaps_before_result");
    fork_lookup_preserves_rules_and_cancel_reaps_before_result();
    eprintln!(
        "process test: resolver::large_result_uses_one_read_interest_and_bounded_owner_turns"
    );
    large_result_uses_one_read_interest_and_bounded_owner_turns();
}
fn fork_lookup_preserves_rules_and_cancel_reaps_before_result() {
    let mut rules = parse_rules(
        b"server",
        &EncodedArg::command_line(b"/one/two/127.0.0.2#5353@192.0.2.1#5300"),
    )
    .unwrap();
    for rule in &mut rules {
        let RuleTarget::Upstream(endpoint) = &mut rule.target else {
            unreachable!()
        };
        endpoint.host = ServerHost::Name(b"127.0.0.2".to_vec());
    }
    let expected = endpoints::resolve_rules(&rules, false);

    let mut lookup = EndpointLookup::start(rules.clone(), false).unwrap();
    let result = finish(&mut lookup);
    assert_eq!(result.rules, expected.rules);
    assert!(result.error.is_none());
    assert!(lookup.pid.is_none());

    let mut cancelled = EndpointLookup::start(rules, false).unwrap();
    cancelled.cancel();
    let result = finish(&mut cancelled);
    assert!(result.rules.is_empty() && result.error.is_none());
    assert!(cancelled.pid.is_none());
}

fn large_result_uses_one_read_interest_and_bounded_owner_turns() {
    let one = parse_rules(b"server", &EncodedArg::command_line(b"/one/127.0.0.2"))
        .unwrap()
        .remove(0);
    let rules = vec![one; 512];

    let mut lookup = EndpointLookup::start(rules.clone(), false).unwrap();
    let mut fds = Vec::new();
    lookup.append_poll_fds(&mut fds);
    assert_eq!(fds.len(), 1);
    assert_eq!(fds[0].events, 1);
    let result = finish(&mut lookup);
    assert_eq!(result.rules, rules);
    assert!(lookup.bytes.len() > 4096);
    assert!(result.error.is_none());
}
