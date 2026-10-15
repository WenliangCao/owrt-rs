//! Excluded A53 cumulative-path diagnostic. Never a product optimization.
//! All modes share one ELF. Only the frozen q0000..q031f.m6a.test A/AAAA
//! packet shape is eligible, and its first 1000 queries always run in full.
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Mode { Full = 0, Receive = 1, BeforeAnswer = 2, SkipLocal = 3 }
static MODE: AtomicUsize = AtomicUsize::new(0);
static MATCHED: AtomicU64 = AtomicU64::new(0);
static CUTS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

pub fn initialize() -> std::io::Result<()> {
    let value = std::env::var("DNSMASQ_UDP_STAGE").unwrap_or_else(|_| "full".into());
    let mode = match value.as_str() {
        "full" => Mode::Full, "receive" => Mode::Receive,
        "before-answer" => Mode::BeforeAnswer, "skip-local" => Mode::SkipLocal,
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid diagnostic UDP stage")),
    };
    MODE.store(mode as usize, Relaxed);
    Ok(())
}

fn eligible(packet: &[u8]) -> bool {
    if packet.len() != 32 || packet[2..12] != [1,0,0,1,0,0,0,0,0,0]
        || packet[12..14] != [5,b'q'] || packet[18..28] != [3,b'm',b'6',b'a',4,b't',b'e',b's',b't',0]
        || packet[28] != 0 || !matches!(packet[29], 1 | 28) || packet[30..32] != [0,1]
    { return false; }
    let mut index = 0u16;
    for byte in &packet[14..18] {
        let digit = match *byte { b'0'..=b'9' => byte-b'0', b'a'..=b'f' => byte-b'a'+10, _ => return false };
        index = index * 16 + u16::from(digit);
    }
    index < 800
}

pub fn entered(packet: &[u8]) {
    if eligible(packet) { MATCHED.fetch_add(1, Relaxed); }
}

pub fn selected(mode: Mode, packet: &[u8]) -> bool {
    MODE.load(Relaxed) == mode as usize && MATCHED.load(Relaxed) > 1000 && eligible(packet)
}

pub fn record_cut(mode: Mode) { CUTS[mode as usize].fetch_add(1, Relaxed); }

/// A valid answer for this synthetic fixture only. Its TTL is fixed120,
/// unlike the naturally ageing full cache answer. It is never C equivalence.
#[inline(never)]
pub fn answer_in_place(buffer: &mut [u8], query_length: usize) -> Option<usize> {
    if buffer.len() < 60 || !eligible(buffer.get(..query_length)?) { return None; }
    let rrtype = buffer[29];
    buffer[2..12].copy_from_slice(&[0x81,0x80,0,1,0,1,0,0,0,0]);
    buffer[32..44].copy_from_slice(&[0xc0,0x0c,0,rrtype,0,1,0,0,0,120,0,if rrtype==1 {4} else {16}]);
    let data: &[u8] = if rrtype == 1 { &[192,0,2,1] } else { &[0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1] };
    buffer[44..44+data.len()].copy_from_slice(data);
    Some(44+data.len())
}

#[inline(never)]
pub fn owned_answer(packet: &[u8]) -> Vec<u8> {
    let mut answer = vec![0; 60];
    answer[..packet.len()].copy_from_slice(packet);
    let size = answer_in_place(&mut answer, packet.len()).expect("selected diagnostic packet");
    answer.truncate(size);
    answer
}

pub fn write_report() -> std::io::Result<()> {
    use std::io::Write;
    let Some(path) = std::env::var_os("DNSMASQ_UDP_STAGE_OUT") else { return Ok(()) };
    let cuts = std::array::from_fn::<_,4,_>(|i| CUTS[i].load(Relaxed));
    writeln!(std::fs::File::create(path)?, "{{\"scope\":\"excluded synthetic cumulative-path intervention, not oracle correctness or accepted performance\",\"mode\":{},\"matched_queries\":{},\"full_path_prewarm\":1000,\"cuts_by_mode\":{cuts:?}}}", MODE.load(Relaxed), MATCHED.load(Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{Header,Name,PacketWriter,Question,RecordRef};
    fn query(index: usize, rrtype: u16) -> Vec<u8> {
        let mut writer = PacketWriter::new(0x1234,0x0100,512).unwrap();
        writer.question(&Name::from_ascii(&format!("q{index:04x}.m6a.test")).unwrap(),rrtype,1).unwrap();
        writer.finish()
    }
    #[test]
    fn synthetic_replies_match_the_fixed_input_and_address_contract() {
        for index in 0..800 {
            for rrtype in [1,28] {
                let query = query(index,rrtype);
                assert!(eligible(&query));
                let answer = owned_answer(&query);
                let header = Header::parse(&answer).unwrap();
                assert_eq!(header.id,0x1234); assert_eq!(header.answers,1); assert_eq!(header.rcode(),0);
                let question = Question::parse(&answer,12).unwrap();
                assert_eq!(question.qtype,rrtype);
                let record = RecordRef::parse(&answer,question.end).unwrap();
                assert_eq!(record.rrtype,rrtype); assert_eq!(record.class,1); assert_eq!(record.ttl,120);
                assert_eq!(record.name().unwrap(),question.name); assert_eq!(record.end,answer.len());
                let expected: &[u8] = if rrtype==1 { &[192,0,2,1] } else { &[0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1] };
                assert_eq!(record.rdata,expected);
            }
        }
        assert!(!eligible(&query(800,1))); assert!(!eligible(&query(0,16)));
        let mut bad=query(0,1);bad[3]=0x10;assert!(!eligible(&bad));
        let mut bad=query(0,1);bad.push(0);assert!(!eligible(&bad));
        let packet=query(0,1);
        MODE.store(Mode::Receive as usize,Relaxed);
        MATCHED.store(0,Relaxed);
        for _ in 0..1000 { entered(&packet); assert!(!selected(Mode::Receive,&packet)); }
        entered(&packet); assert!(selected(Mode::Receive,&packet));
        assert!(!selected(Mode::BeforeAnswer,&packet));
        MODE.store(Mode::Full as usize,Relaxed); MATCHED.store(0,Relaxed);
    }
}
