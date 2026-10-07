// Appended to main.rs only in the ignored diagnostic companion.
impl SinglePoll {
    fn m6b_resource_sample(&self) -> io::Result<()> {
        use dnsmasq_rs::dns::cache::Cache;
        use dnsmasq_rs::m6b_resource_diag as meter;
        let mut work_count = 0;
        let mut views = 0;
        let mut tcp_pending = 0;
        let mut input = 0;
        let mut framer = 0;
        let mut writing = 0;
        let mut waiting_mac = 0;
        let mut query_events = 0;
        let mut stale = 0;
        let mut mac = 0;
        let mut upstream = 0;
        let mut lru = 0;
        let mut cache_pending = 0;
        let mut pending_capacity = 0;
        let mut reverse_capacity = 0;
        for client in &self.clients {
            if let Some(work) = &client.dns_work {
                work_count += 1;
                views += usize::from(work.cache_view.is_some());
                tcp_pending += usize::from(work.forward.m6b_pending());
            }
        }
        let parent = self.service.try_borrow().map_err(|_| io::Error::other("diagnostic parent borrowed"))?;
        let udp_forward_pending = parent.daemon.as_ref().map_or(0, DnsDaemon::pending_count);
        let udp_owner_pending = self.pending_edns_udp.len() + usize::from(self.pending_interface_udp.is_some());
        let tcp_accept_pending = usize::from(self.pending_interface_tcp.is_some());
        let udp_pending = udp_forward_pending + udp_owner_pending;
        let full_drained = self.clients.is_empty() && work_count == 0 && views == 0
            && tcp_pending == 0 && tcp_accept_pending == 0 && udp_pending == 0;
        let Some(stamp) = meter::sample(full_drained)? else { return Ok(()); };
        Cache::m6b_begin_root_sample();
        if let Some(daemon) = &parent.daemon { daemon.m6b_observe_parent_cache(); }
        for client in &self.clients {
            if let Some(work) = &client.dns_work {
                input += work.input.capacity(); framer += work.framer.m6b_capacity();
                stale += work.stale_query.as_ref().map_or(0, Vec::capacity);
                mac += work.mac.as_ref().map_or(0, Vec::capacity);
                upstream += work.forward.m6b_bytes();
                query_events += work.query_events.capacity() * std::mem::size_of::<(
                    dnsmasq_rs::query_logging::QueryContext, dnsmasq_rs::query_logging::QueryEvent)>();
                if let TcpClientPhase::Writing { frame, .. } = &work.phase { writing += frame.capacity(); }
                if let TcpClientPhase::WaitingMac { query } = &work.phase { waiting_mac += query.capacity(); }
                if let Some(cache) = &work.cache_view {
                    cache.m6b_observe_roots(false);
                    let (bytes, pending, capacity, reverse) = cache.m6b_owner_capacities();
                    lru += bytes; cache_pending += pending; pending_capacity += capacity; reverse_capacity += reverse;
                }
            }
        }
        let roots = Cache::m6b_finish_root_sample();
        let g = self.parent_events.try_borrow().map_err(|_| io::Error::other("diagnostic G borrowed"))?.tcp_active;
        let mut log_payload = 0;
        let mut log_queue = 0;
        #[cfg(target_os = "linux")]
        for client in &self.clients {
            if let Some(context) = &client.log_context {
                let (bytes, capacity) = context.m6b_capacities(); log_payload += bytes; log_queue += capacity;
            }
        }
        // Registry pruning is finished before this snapshot. Formatting uses
        // write_fmt directly, without building a JSON String or root arrays.
        let alloc = meter::allocation();
        let nominal = stamp.nominal_drain_second.map_or(-1, |n| n as i64);
        let actual = stamp.actual_drain_ns.map_or(-1, |n| n.min(i64::MAX as u128) as i64);
        meter::emit(format_args!(concat!(
            "{{\"diagnostic_only\":true,\"product_qualification\":false,\"extra_trace_fd\":1,",
            "\"elapsed_ns\":{},\"drain_epoch\":{},\"nominal_drain_second\":{},\"actual_drain_ns\":{},",
            "\"clients\":{},\"G\":{},\"dns_work\":{},\"views\":{},\"tcp_pending\":{},\"tcp_accept_pending\":{},",
            "\"udp_pending\":{},\"udp_forward_pending\":{},\"udp_owner_pending\":{},\"typed_transfer_inflight\":0,\"full_drained\":{},",
            "\"content_versions\":{},\"index_versions\":{},\"old_pinned_content\":{},\"old_pinned_index\":{},",
            "\"private_content\":{},\"private_index\":{},\"registry_len\":{},\"registry_capacity\":{},\"missing_hooks\":{},",
            "\"balance_qualification\":\"unproven\",\"live_requested_including_diagnostic\":{},\"observer_registry_requested\":{},",
            "\"peak_requested_including_diagnostic\":{},\"live_objects\":{},",
            "\"alloc\":{},\"zeroed\":{},\"realloc\":{},\"free\":{},\"alloc_failed\":{},\"balance_errors\":{},",
            "\"client_vector_bytes\":{},\"view_lru_bytes\":{},\"cache_pending\":{},\"pending_capacity\":{},\"reverse_capacity\":{},",
            "\"input_capacity\":{},\"framer_capacity\":{},\"writing_capacity\":{},\"waiting_mac_capacity\":{},\"query_event_descriptors\":{},\"stale_capacity\":{},",
            "\"mac_capacity\":{},\"upstream_capacity\":{},\"log_payload_capacity\":{},\"log_queue_capacity\":{}}}"),
            stamp.elapsed_ns, stamp.epoch, nominal, actual, self.clients.len(), g, work_count, views,
            tcp_pending, tcp_accept_pending, udp_pending, udp_forward_pending, udp_owner_pending, full_drained,
            roots.content, roots.index, roots.old_content, roots.old_index,
            roots.private_content, roots.private_index, roots.registry_len, roots.registry_capacity, roots.missing_creation_hooks,
            alloc.live, alloc.observer_live, alloc.peak, alloc.objects, alloc.alloc, alloc.zeroed, alloc.realloc, alloc.free,
            alloc.failed, alloc.balance_errors, self.clients.capacity() * std::mem::size_of::<PollTcpClient>(),
            lru, cache_pending, pending_capacity, reverse_capacity, input, framer, writing, waiting_mac, query_events, stale, mac, upstream,
            log_payload, log_queue))
    }
}
