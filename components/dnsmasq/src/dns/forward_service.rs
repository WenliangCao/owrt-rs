//! Socket-independent upstream DNS dispatch.
//!
//! This is the boundary between a transport/event loop and the forwarding
//! state in [`super::forward`].  It deliberately does not open sockets,
//! select interfaces, parse UCI server rules, or process/cache upstream
//! answers.  The caller owns those policies and calls this module after it has
//! selected a [`ServerGroup`].
//!
//! The EDNS work here follows `forward.c::receive_query()` and
//! `edns0.c::add_pseudoheader()`: discover the last OPT, derive the client's
//! reply limit and flags, and advertise the configured upstream limit unless
//! the request is signed.  Option-specific EDNS decoration and reply-side
//! filtering remain explicit caller work.

use super::forward::{
    Client, Flags, ForwardTable, GroupId, QueryId, Random, ReplyAction, Scope, SendPlan,
    SendReason, ServerGroup, ServerId, SocketToken, SubmissionKind, SubmitError,
};
use super::wire::{find_pseudoheader, Header, Message, WireError};
use std::collections::HashMap;
use std::net::SocketAddr;

const DNS_DEFAULT_UDP_SIZE: u16 = 512;
const OPT_RECORD_LEN: usize = 11;

#[derive(Debug)]
pub enum DispatchError {
    Wire(WireError),
    Submit(SubmitError),
    UnknownGroup(GroupId),
}

impl From<WireError> for DispatchError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<SubmitError> for DispatchError {
    fn from(value: SubmitError) -> Self {
        Self::Submit(value)
    }
}

/// Metadata extracted from the client query before it is submitted to the
/// forwarding table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryMetadata {
    pub udp_limit: u16,
    pub had_opt: bool,
    pub signed: bool,
    pub flags: Flags,
}

/// A submission and, when the C path would send now, its candidate servers.
/// `packet` is absent for a duplicate which is intentionally coalesced with a
/// query sent less than two seconds earlier.
#[derive(Debug)]
pub struct DispatchSubmission {
    pub id: QueryId,
    pub kind: SubmissionKind,
    pub packet: Option<Vec<u8>>,
    pub send_plan: Option<SendPlan>,
    pub metadata: QueryMetadata,
}

#[derive(Debug)]
pub struct RetryDispatch {
    pub id: QueryId,
    pub packet: Vec<u8>,
    pub send_plan: SendPlan,
}

/// A response copy ready for one client recipient.  The caller still owns
/// transport delivery and may use `client.listener`/`client.destination` to
/// select its socket and source address.
#[derive(Debug)]
pub struct ClientReply {
    pub client: Client,
    pub original_id: u16,
    /// Forwarding flags from the original query. `flags.had_opt` tells the
    /// reply filter whether an upstream-only empty OPT must be removed.
    pub flags: Flags,
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchedReply {
    pub id: QueryId,
    pub server: ServerId,
    pub rcode: u8,
}

/// A small forwarding dispatcher.  Group selection and all network I/O remain
/// in the caller, while this type makes the state-machine call order explicit.
pub struct ForwardDispatcher {
    table: ForwardTable,
    groups: HashMap<GroupId, ServerGroup>,
    edns_packet_max: u16,
}

impl ForwardDispatcher {
    pub fn new(
        options: super::forward::Options,
        groups: impl IntoIterator<Item = ServerGroup>,
        edns_packet_max: u16,
    ) -> Self {
        let groups = groups.into_iter().map(|group| (group.id, group)).collect();
        Self {
            table: ForwardTable::new(options),
            groups,
            // dnsmasq validates this option to at least the DNS default.  Keep
            // the boundary safe even when a unit-test caller bypasses config.
            edns_packet_max: edns_packet_max.max(DNS_DEFAULT_UDP_SIZE),
        }
    }

    pub fn table(&self) -> &ForwardTable {
        &self.table
    }

    /// dnsmasq.c's packet_buff_sz: advertised EDNS maximum plus room for one
    /// maximum wire name and the fixed resource-record fields.
    pub fn udp_receive_capacity(&self) -> usize {
        usize::from(self.edns_packet_max) + super::wire::MAX_NAME_LEN + 10
    }

    pub fn table_mut(&mut self) -> &mut ForwardTable {
        &mut self.table
    }

    pub fn group(&self, id: GroupId) -> Option<&ServerGroup> {
        self.groups.get(&id)
    }

    pub fn group_mut(&mut self, id: GroupId) -> Option<&mut ServerGroup> {
        self.groups.get_mut(&id)
    }

    /// Parse and submit one client query.  The caller supplies the already
    /// selected server group and socket-independent client identity.
    pub fn submit(
        &mut self,
        packet: &[u8],
        mut client: Client,
        group: GroupId,
        scope: Scope,
        now: i64,
        random: &mut impl Random,
    ) -> Result<DispatchSubmission, DispatchError> {
        if !self.groups.contains_key(&group) {
            return Err(DispatchError::UnknownGroup(group));
        }
        let (_, metadata) = prepare_query(packet, self.edns_packet_max)?;
        client.udp_limit = metadata.udp_limit;
        let submission =
            self.table
                .submit(packet, client, group, metadata.flags, scope, now, random)?;

        let reason = match submission.kind {
            SubmissionKind::New => Some(SendReason::New),
            SubmissionKind::ClientRetry => Some(SendReason::ClientRetry),
            SubmissionKind::LateDuplicate => Some(SendReason::LateDuplicate),
            SubmissionKind::Coalesced => None,
        };
        let send_plan = if let Some(reason) = reason {
            // C finds duplicates before lookup_domain. A duplicate retains
            // the first query's group even if configuration selection changes.
            let retained_group = self.table.get(submission.id).unwrap().group;
            let selected = self
                .groups
                .get_mut(&retained_group)
                .expect("group checked before submit");
            Some(
                self.table
                    .plan(submission.id, selected, reason, now)
                    .expect("submitted query belongs to selected group"),
            )
        } else {
            None
        };
        let upstream_packet = if send_plan.is_some() {
            self.upstream_packet(submission.id)?
        } else {
            None
        };
        Ok(DispatchSubmission {
            id: submission.id,
            kind: submission.kind,
            packet: upstream_packet,
            send_plan,
            metadata,
        })
    }

    pub fn note_sent(
        &mut self,
        id: QueryId,
        server: ServerId,
        socket: SocketToken,
        now_ms: u32,
    ) -> bool {
        self.table.note_sent(id, server, socket, now_ms)
    }

    pub fn note_forwarded_action(&mut self) {
        self.table.note_forwarded_action();
    }

    /// Plan the next server set after a syntactically valid upstream error
    /// (SERVFAIL/REFUSED).  `complete_reply` must be called first so the
    /// table's `forward_all` counter follows the C reply path.
    pub fn plan_after_error(&mut self, id: QueryId, now: i64) -> Option<SendPlan> {
        let group_id = self.table.get(id)?.group;
        let group = self.groups.get_mut(&group_id)?;
        self.table.plan(id, group, SendReason::UpstreamError, now)
    }

    pub fn upstream_packet(&self, id: QueryId) -> Result<Option<Vec<u8>>, WireError> {
        self.table
            .get(id)
            .map(|pending| prepare_query(&pending.packet, self.edns_packet_max).map(|p| p.0))
            .transpose()
    }

    /// Restore the original ID and question case for every coalesced client.
    /// The upstream response is copied once per recipient so callers can send
    /// it independently or apply client-specific EDNS filtering.  No state is
    /// removed; call [`Self::finish`] after all copies have been handled.
    pub fn restore_recipients(
        &self,
        id: QueryId,
        packet: &[u8],
    ) -> Result<Option<Vec<ClientReply>>, WireError> {
        let Some(pending) = self.table.get(id) else {
            return Ok(None);
        };
        let mut replies = Vec::with_capacity(pending.recipients.len());
        for recipient in &pending.recipients {
            let mut restored = packet.to_vec();
            recipient.restore_question(&mut restored)?;
            replies.push(ClientReply {
                client: recipient.client.clone(),
                original_id: recipient.original_id,
                flags: pending.flags,
                packet: restored,
            });
        }
        Ok(Some(replies))
    }

    /// Match a response without mutating the pending query.  The caller may
    /// inspect/process the packet and then call [`Self::complete_reply`].
    pub fn accept_reply(
        &self,
        packet: &[u8],
        source: SocketAddr,
        socket: SocketToken,
        group: GroupId,
        now: i64,
    ) -> Option<MatchedReply> {
        let selected = self.groups.get(&group)?;
        let (id, server) = self
            .table
            .accept_reply(packet, source, socket, selected, now)?;
        Some(MatchedReply {
            id,
            server,
            rcode: Header::parse(packet).ok()?.rcode(),
        })
    }

    pub fn complete_reply(&mut self, reply: MatchedReply) -> Option<ReplyAction> {
        let group_id = self.table.get(reply.id)?.group;
        let action = self.table.on_reply(reply.id, reply.server, reply.rcode)?;
        if let Some(group) = self.groups.get_mut(&group_id) {
            group.note_reply(reply.server, reply.rcode);
        }
        Some(action)
    }

    /// Return retry plans due at `now_ms`; the actual send must be followed by
    /// [`Self::note_sent`] and [`Self::retry_finished`] by the event loop.
    pub fn plan_retries(&mut self, now: i64, now_ms: u32) -> Result<Vec<RetryDispatch>, WireError> {
        let schedule = self.table.fast_retries(now, now_ms);
        let mut result = Vec::with_capacity(schedule.due.len());
        for id in schedule.due {
            let Some(group_id) = self.table.get(id).map(|pending| pending.group) else {
                continue;
            };
            let Some(group) = self.groups.get_mut(&group_id) else {
                continue;
            };
            let Some(send_plan) = self.table.plan(id, group, SendReason::FastRetry, now) else {
                continue;
            };
            let Some(packet) = self.upstream_packet(id)? else {
                continue;
            };
            result.push(RetryDispatch {
                id,
                packet,
                send_plan,
            });
        }
        Ok(result)
    }

    pub fn retry_finished(&mut self, id: QueryId) {
        self.table.retry_finished(id);
    }

    pub fn finish(&mut self, id: QueryId) -> Option<super::forward::Pending> {
        self.table.finish(id)
    }

    pub fn cancel(&mut self, id: QueryId) -> Option<super::forward::Pending> {
        self.table.cancel(id)
    }

    pub fn take_released(&mut self) -> Vec<super::forward::Released> {
        self.table.take_released()
    }
}

/// Prepare the packet sent to an upstream server and derive the state needed
/// for the client reply.  This function does not add option-specific EDNS
/// data and does not alter signed TKEY/TSIG queries.
pub fn prepare_query(
    packet: &[u8],
    configured_max: u16,
) -> Result<(Vec<u8>, QueryMetadata), WireError> {
    let header = Header::parse(packet)?;
    let scan = find_pseudoheader(packet, true)?;
    let configured_max = configured_max.max(DNS_DEFAULT_UDP_SIZE);
    let (udp_limit, had_opt, dnssec_ok) = match scan.opt.as_ref() {
        Some(opt) => (opt.udp_size(configured_max), true, opt.dnssec_ok()),
        None => (DNS_DEFAULT_UDP_SIZE, false, false),
    };
    let flags = Flags::from_header(header, had_opt, dnssec_ok, true);
    let metadata = QueryMetadata {
        udp_limit,
        had_opt,
        signed: scan.signed,
        flags,
    };
    if scan.signed {
        return Ok((packet.to_vec(), metadata));
    }

    let mut prepared = packet.to_vec();
    if let Some(opt) = scan.opt {
        // RecordRef::fixed points immediately after the owner name; class is
        // the advertised UDP size. Message::parse in find_pseudoheader has
        // already checked this offset and the complete record bounds.
        prepared[opt.record.fixed + 2..opt.record.fixed + 4]
            .copy_from_slice(&configured_max.to_be_bytes());
    } else {
        // add_pseudoheader() appends an empty OPT after all existing records.
        // Respect the same output envelope: if it cannot fit, retain the
        // original query and let the caller apply its normal send policy.
        let message = Message::parse(packet)?;
        let can_write_opt = message
            .end
            .checked_add(OPT_RECORD_LEN)
            .is_some_and(|len| len <= configured_max as usize);
        if can_write_opt {
            let mut updated = message.header;
            let original_len = prepared.len();
            let opt_end = message.end + OPT_RECORD_LEN;
            prepared.resize(original_len.max(opt_end), 0);
            prepared[message.end..message.end + 3].copy_from_slice(&[0, 0, 41]);
            prepared[message.end + 3..message.end + 5]
                .copy_from_slice(&configured_max.to_be_bytes());
            prepared[message.end + 5..opt_end].fill(0);
            // C writes the empty OPT first, then only increments arcount when
            // four bytes remain for a possible option TLV. On failure it
            // returns the original plen, not opt_end. Any original trailing
            // bytes overwritten by that write remain changed in the result.
            if message
                .end
                .checked_add(OPT_RECORD_LEN + 4)
                .is_some_and(|len| len <= configured_max as usize)
            {
                prepared.truncate(opt_end);
                updated.additionals = updated.additionals.checked_add(1).ok_or(WireError::Full)?;
                updated.write(&mut prepared)?;
            } else {
                prepared.truncate(original_len);
            }
        }
    }
    Ok((prepared, metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::forward::{Options, Server};
    use crate::dns::wire::Name;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};

    struct Counter(u32);
    impl Random for Counter {
        fn next_u32(&mut self) -> io::Result<u32> {
            self.0 += 1;
            Ok(self.0)
        }
    }

    fn query(name: &str, id: u16) -> Vec<u8> {
        let name = Name::from_ascii(name).unwrap();
        let mut packet = vec![0; 12];
        Header {
            id,
            flags: 0x100,
            questions: 1,
            ..Header::default()
        }
        .write(&mut packet)
        .unwrap();
        packet.extend_from_slice(name.as_wire());
        packet.extend_from_slice(&[0, 1, 0, 1]);
        packet
    }

    fn group() -> ServerGroup {
        ServerGroup::new(
            GroupId(1),
            vec![
                Server {
                    id: ServerId(7),
                    address: SocketAddr::from(([192, 0, 2, 53], 53)),
                    bound_socket: None,
                },
                Server {
                    id: ServerId(8),
                    address: SocketAddr::from(([192, 0, 2, 54], 53)),
                    bound_socket: None,
                },
            ],
            true,
            false,
        )
    }

    fn client(port: u16) -> Client {
        Client {
            source: SocketAddr::from(([192, 0, 2, 1], port)),
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            interface: 1,
            listener: Some(SocketToken(4)),
            reply_requested: true,
            udp_limit: 512,
            log_id: 1,
        }
    }

    #[test]
    fn prepare_adds_opt_and_clamps_existing_opt() {
        let plain = query("example.test", 9);
        let (prepared, metadata) = prepare_query(&plain, 1232).unwrap();
        assert!(!metadata.had_opt);
        assert_eq!(prepared.len(), plain.len() + OPT_RECORD_LEN);
        assert_eq!(Header::parse(&prepared).unwrap().additionals, 1);
        let opt = find_pseudoheader(&prepared, false).unwrap().opt.unwrap();
        assert_eq!(opt.udp_size(4096), 1232);

        let mut with_opt = plain;
        with_opt.extend_from_slice(&[0, 0, 41, 0x04, 0xd2, 0, 0, 0, 0, 0, 0]);
        let mut header = Header::parse(&with_opt).unwrap();
        header.additionals = 1;
        header.write(&mut with_opt).unwrap();
        let (prepared, metadata) = prepare_query(&with_opt, 1400).unwrap();
        assert!(metadata.had_opt);
        let opt = find_pseudoheader(&prepared, false).unwrap().opt.unwrap();
        assert_eq!(opt.udp_size(4096), 1400);
    }

    #[test]
    fn prepare_preserves_c_tight_envelope_opt_boundary() {
        // Build a valid query whose declared additional section ends at 501
        // bytes. C writes an empty OPT when byte 512 fits, but has fewer than
        // four bytes left for a TLV, leaving arcount and returned length
        // unchanged. Its in-buffer write still overwrites existing tails.
        let mut packet = query("example.test", 9);
        packet.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 0, 1, 204]);
        packet.extend(std::iter::repeat_n(0xaa, 460));
        let mut header = Header::parse(&packet).unwrap();
        header.additionals = 1;
        header.write(&mut packet).unwrap();
        assert_eq!(Message::parse(&packet).unwrap().end, 501);
        for tail in [0, 1, 4, 10, 11, 17] {
            let mut input = packet.clone();
            input.extend(std::iter::repeat_n(0xbb, tail));
            let (prepared, _) = prepare_query(&input, 512).unwrap();
            assert_eq!(prepared.len(), input.len());
            assert_eq!(&prepared[..501], &packet);
            assert_eq!(Header::parse(&prepared).unwrap().additionals, 1);
            let mut expected = vec![0xbb; tail];
            let opt = [0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 0];
            expected[..tail.min(11)].copy_from_slice(&opt[..tail.min(11)]);
            assert_eq!(&prepared[501..], expected);
        }
    }

    #[test]
    fn signed_tkey_is_not_decorated() {
        let name = Name::from_ascii("gss.test").unwrap();
        let mut packet = vec![0; 12];
        Header {
            id: 1,
            flags: 0x100,
            questions: 1,
            ..Header::default()
        }
        .write(&mut packet)
        .unwrap();
        packet.extend_from_slice(name.as_wire());
        packet.extend_from_slice(&249u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        let (prepared, metadata) = prepare_query(&packet, 1232).unwrap();
        assert!(metadata.signed);
        assert_eq!(prepared, packet);
    }

    #[test]
    fn dispatcher_coalesces_and_matches_reply() {
        let mut dispatcher = ForwardDispatcher::new(Options::default(), [group()], 1232);
        let mut random = Counter(0);
        let first = dispatcher
            .submit(
                &query("example.test", 10),
                client(1000),
                GroupId(1),
                Scope::Shared,
                100,
                &mut random,
            )
            .unwrap();
        assert_eq!(first.kind, SubmissionKind::New);
        let plan = first.send_plan.unwrap();
        assert_eq!(plan.candidates, [ServerId(7), ServerId(8)]);
        assert!(!plan.send_all);
        dispatcher.note_sent(first.id, ServerId(7), SocketToken(9), 10);
        let duplicate = dispatcher
            .submit(
                &query("EXAMPLE.TEST", 11),
                client(1001),
                GroupId(1),
                Scope::Shared,
                101,
                &mut random,
            )
            .unwrap();
        assert_eq!(duplicate.kind, SubmissionKind::Coalesced);
        assert!(duplicate.packet.is_none());

        let mut reply = dispatcher.upstream_packet(first.id).unwrap().unwrap();
        let mut header = Header::parse(&reply).unwrap();
        header.flags |= 0x8000 | 0x0080;
        header.write(&mut reply).unwrap();
        let matched = dispatcher
            .accept_reply(
                &reply,
                SocketAddr::from(([192, 0, 2, 53], 53)),
                SocketToken(9),
                GroupId(1),
                101,
            )
            .unwrap();
        assert_eq!(matched.id, first.id);
        let restored = dispatcher
            .restore_recipients(first.id, &reply)
            .unwrap()
            .unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].original_id, 10);
        assert_eq!(restored[1].original_id, 11);
        assert_eq!(restored[1].packet[0..2], 11u16.to_be_bytes());
        assert_eq!(
            dispatcher.complete_reply(matched),
            Some(ReplyAction::Deliver)
        );
    }

    #[test]
    fn servfail_uses_next_strict_server_after_match() {
        let mut dispatcher = ForwardDispatcher::new(Options::default(), [group()], 1232);
        let mut random = Counter(0);
        let submission = dispatcher
            .submit(
                &query("error.test", 3),
                client(1000),
                GroupId(1),
                Scope::Shared,
                100,
                &mut random,
            )
            .unwrap();
        dispatcher.note_sent(submission.id, ServerId(7), SocketToken(9), 1);
        let mut response = dispatcher.upstream_packet(submission.id).unwrap().unwrap();
        let mut header = Header::parse(&response).unwrap();
        header.flags |= 0x8000 | 0x0082;
        header.write(&mut response).unwrap();
        let matched = dispatcher
            .accept_reply(
                &response,
                SocketAddr::from(([192, 0, 2, 53], 53)),
                SocketToken(9),
                GroupId(1),
                101,
            )
            .unwrap();
        assert_eq!(dispatcher.complete_reply(matched), Some(ReplyAction::Retry));
        assert_eq!(
            dispatcher
                .plan_after_error(submission.id, 101)
                .unwrap()
                .candidates,
            [ServerId(8)]
        );
    }

    #[test]
    fn malformed_question_is_rejected_before_state_creation() {
        let mut dispatcher = ForwardDispatcher::new(Options::default(), [group()], 1232);
        let mut random = Counter(0);
        let error = dispatcher
            .submit(
                &[0; 11],
                client(1000),
                GroupId(1),
                Scope::Shared,
                100,
                &mut random,
            )
            .unwrap_err();
        assert!(matches!(error, DispatchError::Wire(WireError::Truncated)));
        assert!(dispatcher.table().is_empty());
    }
}
