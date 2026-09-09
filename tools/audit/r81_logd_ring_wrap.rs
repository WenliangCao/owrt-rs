//! R81 logd: Ring::add's wrap branch only pops entries while the deque FRONT has
//! offset <= next0. An entry left over from the previous lap at a high offset
//! (never overwritten because this lap wrapped earlier) blocks the loop, so the
//! records whose arena bytes the wrapping write just overwrote stay in `entries`
//! and are returned by `read`. Retained bytes then exceed `-S`.
//! Not run here (no cargo on the audit host). Expected: both tests FAIL on the
//! current ring.rs; a faithful port passes both.

#[path = "../../components/logd/src/ring.rs"]
mod ring;

use ring::Ring;

fn slot(msg_len: usize) -> usize {
    // sizeof(struct log_head) + PAD(strlen + 1), as in syslog.c log_next()
    32 + ((msg_len + 1 + 3) & !3)
}

fn retained_bytes(r: &Ring) -> usize {
    r.list(0).map(|e| slot(e.msg.len())).sum()
}

#[test]
fn wrap_with_abandoned_tail_entry_keeps_overwritten_records() {
    // capacity 256, 3-byte messages occupy 36 bytes each
    let mut r = Ring::new(256);
    for m in ["aaa", "bbb", "ccc", "ddd", "eee", "fff", "ggg"] {
        r.add(m.into(), 0, 1, 0); // ids 0..=6 at offsets 0,36,..,216; newest=252
    }
    r.add("hhh".into(), 0, 1, 0); // id 7 wraps to @0 (evicts a,b); newest=36
    r.add("iii".into(), 0, 1, 0); // id 8 @36 (evicts c)
    r.add("jjj".into(), 0, 1, 0); // id 9 @72 (evicts d)
    r.add("kkk".into(), 0, 1, 0); // id 10 @108 (evicts e); newest=144; f@180,g@216 remain
    // 79-byte message: slot 112; 144+112 >= 256 -> wrap, written at [0,112),
    // overwriting h,i,j,k. In C the chain from `log` is now {m} only.
    r.add("m".repeat(79), 0, 1, 0); // id 11
    let ids: Vec<u32> = r.list(0).map(|e| e.id).collect();
    for overwritten in 7..=10 {
        assert!(
            !ids.contains(&overwritten),
            "id {overwritten} was overwritten by the wrap write but is still listed: {ids:?}"
        );
    }
    assert!(
        retained_bytes(&r) <= 256,
        "retained {} bytes in a 256-byte ring: {ids:?}",
        retained_bytes(&r)
    );
}

#[test]
fn mixed_sizes_never_retain_more_than_capacity() {
    // 16 KiB ring, 60-byte lines with an occasional 1000-byte line: the lap
    // that wraps on the long line leaves the previous lap's tail unevicted.
    let mut r = Ring::new(16 * 1024);
    for lap in 0..40 {
        for i in 0..200 {
            r.add(format!("lap {lap} line {i} {}", "x".repeat(40)), 0, 1, 0);
            assert!(retained_bytes(&r) <= 16 * 1024, "lap {lap} line {i}");
        }
        r.add("L".repeat(1000), 0, 1, 0);
        assert!(retained_bytes(&r) <= 16 * 1024, "lap {lap} long line");
    }
}
