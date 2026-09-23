    #[cfg(target_os = "linux")]
    #[test]
    fn independent_monitors_keep_wrapping_sequences_and_queued_bytes() {
        const CALLER: u32 = 2000;
        const FAST: u32 = 2001;
        const SLOW: u32 = 2002;
        let mut s = Server::new(String::new()).unwrap();
        let (caller, mut caller_peer) = lookup_client();
        let (fast, mut fast_peer) = lookup_client();
        let (slow, mut slow_peer) = lookup_client();
        s.clients.insert(CALLER, Box::new(caller));
        s.clients.insert(FAST, Box::new(fast));
        s.clients.insert(SLOW, Box::new(slow));
        // Exercise the actual add handler, including replacing an existing
        // registration. The repeated FAST add must leave SLOW first.
        for id in [FAST, SLOW, FAST] {
            let mut request = BlobBuf::new();
            request.put_u32(attr::OBJID, SYSTEM_OBJECT_MONITOR);
            request.put_string(attr::METHOD, "add");
            assert!(s.receive(id, InMsg {
                header: Header { ty: ty::INVOKE, seq: 10, peer: 0 },
                blob: request.as_bytes().to_vec().into(), fd: None,
            }));
            drain_lookup(&mut s, FAST, &mut fast_peer);
            drain_lookup(&mut s, SLOW, &mut slow_peer);
        }
        assert_eq!(s.monitors, [(SLOW, 3), (FAST, 1)]);
        s.monitors[0].1 = u16::MAX - 1;
        s.monitors[1].1 = 41;
        let mut filler = BlobBuf::new();
        filler.put(attr::DATA, &[0x5a; 32768]);
        let filler = filler.as_bytes().to_vec();
        s.clients.get_mut(&SLOW).unwrap().send(OutMsg::new(ty::DATA, 0, 0, filler.clone()));
        assert!(!s.clients[&SLOW].tx_empty(), "slow fixture must already be queued");

        let mut expected_slow = vec![(Header { ty: ty::DATA, seq: 0, peer: 0 }, filler)];
        let mut counts = 0u16;
        for (round, size) in [511, 3, 1023, 1].into_iter().enumerate() {
            let mut request = BlobBuf::new();
            request.put(attr::DATA, &vec![round as u8 + 1; size]);
            let request = request.as_bytes().to_vec();
            let header = Header { ty: ty::PING, seq: 100 + round as u16, peer: 9 };
            s.touched.clear();
            assert!(s.receive(CALLER, InMsg { header, blob: request.clone().into(), fd: None }));
            assert!(s.clients[&FAST].tx_empty(), "fast monitor must complete direct writes");
            assert!(!s.clients[&SLOW].tx_empty());
            assert_eq!(s.touched, [SLOW, FAST, SLOW, FAST, CALLER, SLOW, FAST, CALLER]);
            let mut ok = BlobBuf::new();
            ok.put_u32(attr::STATUS, status::OK as u32);
            let ok = ok.as_bytes().to_vec();
            let replies = lookup_frames(&drain_lookup(&mut s, CALLER, &mut caller_peer));
            assert_eq!(replies, [(Header { ty: ty::DATA, ..header }, request.clone()),
                                (Header { ty: ty::STATUS, ..header }, ok.clone())]);
            let mut expected_fast = Vec::new();
            for (send, original, body) in [
                (false, header, request.as_slice()),
                (true, Header { ty: ty::DATA, ..header }, request.as_slice()),
                (true, Header { ty: ty::STATUS, ..header }, ok.as_slice()),
            ] {
                counts += 1;
                let mut mirror = BlobBuf::new();
                mirror.put_u32(0, CALLER);
                mirror.put_u32(1, original.peer);
                mirror.put_u32(3, original.seq as u32);
                mirror.put_u32(4, original.ty as u32);
                mirror.put_u8(2, u8::from(send));
                mirror.put(5, &body[4..]);
                let bytes = mirror.as_bytes().to_vec();
                expected_fast.push((Header { ty: ty::MONITOR, seq: 41 + counts, peer: 0 }, bytes.clone()));
                expected_slow.push((Header { ty: ty::MONITOR, seq: (u16::MAX - 1).wrapping_add(counts), peer: 0 }, bytes));
            }
            assert_eq!(lookup_frames(&drain_lookup(&mut s, FAST, &mut fast_peer)), expected_fast);
        }
        // All slow frames survived later large/small scratch rewrites, while
        // FAST drained after each request with its own independent sequence.
        assert_eq!(lookup_frames(&drain_lookup(&mut s, SLOW, &mut slow_peer)), expected_slow);
        assert_eq!(s.monitors, [(SLOW, 10), (FAST, 53)]);
    }
