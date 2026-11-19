//! DNS compatibility contracts shared with stock dnsmasq.

use dnsmasq_rs::dns::cache::clip_live_reply_ttls;
use dnsmasq_rs::dns::files::{FileStamp, ResolverSelection};
use dnsmasq_rs::dns::wire::{Message, Name, PacketWriter, Section};
use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod support;

#[test]
fn live_maximum_ttl_clips_any_nxdomain_and_mismatched_in_answer_rrs() {
    let owner = Name::from_ascii("owner.clip.test").unwrap();
    let target = Name::from_ascii("target.clip.test").unwrap();
    let other = Name::from_ascii("other.clip.test").unwrap();

    // T_ANY (qtype = 255) clips matching IN answers while leaving unrelated and non-IN RRs intact.
    let mut any_writer = PacketWriter::new(1, 0x8180, 1232).unwrap();
    any_writer.question(&owner, 255, 1).unwrap();
    any_writer
        .record_at(Section::Answer, 12, 1, 1, 600, &[198, 51, 100, 1])
        .unwrap();
    any_writer
        .record_at(Section::Answer, 12, 16, 1, 500, &[1, b'a'])
        .unwrap();
    any_writer
        .record(Section::Answer, &other, 1, 1, 700, &[198, 51, 100, 2])
        .unwrap();
    any_writer
        .record_at(Section::Answer, 12, 16, 3, 800, &[1, b'b'])
        .unwrap();
    let mut any_packet = any_writer.finish();
    clip_live_reply_ttls(&mut any_packet, 100, 0).unwrap();
    let any_ttls: Vec<_> = Message::parse(&any_packet)
        .unwrap()
        .records(Section::Answer)
        .map(|rr| rr.ttl)
        .collect();
    assert_eq!(any_ttls, [100, 100, 700, 800]);

    // NXDOMAIN (rcode = 3) clips matching IN Answer RRs and ignores unrelated or non-IN RRs.
    let mut nx_writer = PacketWriter::new(2, 0x8183, 1232).unwrap();
    nx_writer.question(&owner, 1, 1).unwrap();
    nx_writer
        .record_at(Section::Answer, 12, 16, 1, 600, &[1, b'n'])
        .unwrap();
    nx_writer
        .record(Section::Answer, &other, 1, 1, 700, &[198, 51, 100, 3])
        .unwrap();
    nx_writer
        .record_at(Section::Answer, 12, 1, 3, 800, &[198, 51, 100, 4])
        .unwrap();
    let mut nx_packet = nx_writer.finish();
    clip_live_reply_ttls(&mut nx_packet, 100, 3).unwrap();
    let nx_ttls: Vec<_> = Message::parse(&nx_packet)
        .unwrap()
        .records(Section::Answer)
        .map(|rr| rr.ttl)
        .collect();
    assert_eq!(nx_ttls, [100, 700, 800]);

    // Mismatched rrtypes (AAAA on owner, TXT on CNAME target) still get clipped.
    let mut mismatch_writer = PacketWriter::new(3, 0x8180, 1232).unwrap();
    mismatch_writer.question(&owner, 1, 1).unwrap();
    mismatch_writer
        .record_at(
            Section::Answer,
            12,
            28,
            1,
            450,
            &"2001:db8::4"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        )
        .unwrap();
    mismatch_writer
        .record_at(Section::Answer, 12, 5, 1, 500, target.as_wire())
        .unwrap();
    mismatch_writer
        .record(Section::Answer, &target, 16, 1, 550, &[1, b't'])
        .unwrap();
    mismatch_writer
        .record(Section::Answer, &target, 1, 1, 650, &[198, 51, 100, 5])
        .unwrap();
    mismatch_writer
        .record(Section::Answer, &other, 16, 1, 700, &[1, b'o'])
        .unwrap();
    mismatch_writer
        .record(Section::Answer, &target, 16, 3, 800, &[1, b'c'])
        .unwrap();
    let mut mismatch_packet = mismatch_writer.finish();
    clip_live_reply_ttls(&mut mismatch_packet, 100, 0).unwrap();
    let mismatch_ttls: Vec<_> = Message::parse(&mismatch_packet)
        .unwrap()
        .records(Section::Answer)
        .map(|rr| rr.ttl)
        .collect();
    assert_eq!(mismatch_ttls, [100, 100, 100, 100, 700, 800]);
}

#[cfg(target_os = "linux")]
#[test]
fn root_slash_resolv_file_and_symlink_report_missing_parent_like_inotify_init() {
    use dnsmasq_rs::config::dns::DnsConfig;
    use dnsmasq_rs::dns::files::DnsFiles;
    use dnsmasq_rs::dns::filewatch::WatchError;
    use std::fs;
    use std::io;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    let dir = support::TestDir::new();
    let root_path = Path::new("/").join(dir.0.file_name().unwrap());
    assert_eq!(
        fs::symlink_metadata(&root_path).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let link = dir.0.join("root-target-link");
    symlink(&root_path, &link).unwrap();
    for resolv_file in [root_path, link] {
        let mut config = DnsConfig::default();
        config.resolv_files.clear();
        config.resolv_files.push(resolv_file.clone());
        let error = match DnsFiles::new(&config, true, false) {
            Ok(_) => panic!("expected MissingParent for {}", resolv_file.display()),
            Err(error) => error,
        };
        assert!(
            matches!(&error, WatchError::MissingParent(path) if path == &resolv_file),
            "resolver path {} must report MissingParent, got {error:?}",
            resolv_file.display()
        );
        assert_eq!(
            error.to_string(),
            format!(
                "directory {} for resolv-file is missing, cannot poll",
                resolv_file.display()
            )
        );
    }
}

#[test]
fn evaporated_resolver_file_restarts_forced_and_defers_later_missing_warnings() {
    let stamp_a = Some(FileStamp {
        modified: 200,
        inode: 1,
    });
    let stamp_b = Some(FileStamp {
        modified: 100,
        inode: 2,
    });
    let mut selection = ResolverSelection::new(&[
        PathBuf::from("resolv-a"),
        PathBuf::from("resolv-b"),
        PathBuf::from("resolv-c"),
    ]);
    // Seed A and B via forced initial selection while C is absent (logged == false).
    let seeded = selection.select(true, &[stamp_a, stamp_b, None]);
    assert_eq!(seeded.selected, Some(0));
    assert!(seeded.warn_missing.is_empty());

    // Now A and C are missing while B remains unchanged: A evaporates, forces
    // fallback to B, and only index 0 is warned on this pass.
    let evaporated = selection.select(false, &[None, stamp_b, None]);
    assert_eq!(evaporated.selected, Some(1));
    assert_eq!(evaporated.warn_missing, vec![0]);

    // Next non-forced check with identical stamps warns C (index 2) once, then [].
    let next = selection.select(false, &[None, stamp_b, None]);
    assert_eq!(next.selected, None);
    assert_eq!(next.warn_missing, vec![2]);

    let steady = selection.select(false, &[None, stamp_b, None]);
    assert_eq!(steady.selected, None);
    assert!(steady.warn_missing.is_empty());
}
