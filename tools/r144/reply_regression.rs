    #[test]
    fn matched_replies_preserve_pending_bytes_and_descriptor_ownership() {
        let (mut client, mut server) = pair();
        let mut small = BlobBuf::new();
        small.put(attr::DATA, b"first\xff");
        let mut large = BlobBuf::new();
        large.put(attr::DATA, &vec![0xa5; INCOMING_BUFFER_SIZE + 7]);
        let mut last = BlobBuf::new();
        last.put(attr::DATA, b"z");
        let expected = vec![small.payload().to_vec(), large.payload().to_vec(), last.payload().to_vec()];
        let wrong_peer = small.as_bytes().to_vec();
        let other = last.as_bytes().to_vec();
        let (discarded, mut discarded_observer) = UnixStream::pair().unwrap();
        let (pending_fd, mut pending_observer) = UnixStream::pair().unwrap();
        let (status_fd, mut status_observer) = UnixStream::pair().unwrap();
        for stream in [&discarded_observer, &pending_observer, &status_observer] {
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        }
        // A previously queued frame is not consumed by a new request, even
        // if sequence wrap could make its identifiers match again.
        let mut stale = BlobBuf::new();
        stale.put_u32(attr::STATUS, 99);
        client.pending.push_back(Message { header: Header { ty: ty::STATUS, seq: 1, peer: 77 },
            blob: stale.as_bytes().to_vec(), fd: None });
        let producer = std::thread::spawn(move || {
            let req = server.recv().unwrap();
            assert_eq!((req.header.seq, req.header.peer), (1, 77));
            server.send(Header { ty: ty::DATA, seq: req.header.seq, peer: 78 }, &mut small, None).unwrap();
            let mut asynchronous = BlobBuf::new();
            asynchronous.put_u32(attr::OBJID, 42).put_string(attr::METHOD, "async").put(attr::DATA, b"owned");
            server.send(Header { ty: ty::INVOKE, seq: 2, peer: 77 }, &mut asynchronous, Some(pending_fd.as_raw_fd())).unwrap();
            drop(pending_fd);
            server.send(Header { ty: ty::DATA, ..req.header }, &mut small, Some(discarded.as_raw_fd())).unwrap();
            drop(discarded);
            // DATA descriptors must be closed before waiting for STATUS.
            assert_eq!(discarded_observer.read(&mut [0]).unwrap(), 0);
            server.send(Header { ty: ty::DATA, ..req.header }, &mut large, None).unwrap();
            // Coalesce a later DATA and an unexpected matching message.
            let mut wire = Vec::new();
            for ty in [ty::DATA, ty::NOTIFY] {
                wire.extend_from_slice(&Header { ty, ..req.header }.encode());
                wire.extend_from_slice(last.as_bytes());
            }
            server.stream.write_all(&wire).unwrap();
            let mut status_blob = BlobBuf::new();
            status_blob.put_u32(attr::STATUS, 0).put_u32(attr::STATUS, (-7i32) as u32);
            server.send(Header { ty: ty::STATUS, ..req.header }, &mut status_blob, Some(status_fd.as_raw_fd())).unwrap();
            drop(status_fd);
        });
        let reply = client.request(ty::LOOKUP, 77, &mut BlobBuf::new(), None, 2000).unwrap();
        assert_eq!(reply.status, -7, "last duplicate STATUS wins, including signed values");
        assert_eq!(reply.data, expected, "large and later small frames must not overwrite earlier DATA");
        UnixStream::from(reply.fd.unwrap()).write_all(b"s").unwrap();
        let mut byte = [0];
        status_observer.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"s");
        let Incoming::Other(stale) = client.read_incoming().unwrap() else { panic!("stale STATUS") };
        assert_eq!(stale.status(), Some(99));
        let Incoming::Other(wrong) = client.read_incoming().unwrap() else { panic!("wrong peer DATA") };
        assert_eq!((wrong.header.seq, wrong.header.peer, wrong.blob), (1, 78, wrong_peer));
        let Incoming::Invoke(pending) = client.read_incoming().unwrap() else { panic!("pending INVOKE") };
        assert_eq!((pending.seq, pending.objid, pending.method.as_str(), pending.data.as_slice()), (2, 42, "async", &b"owned"[..]));
        UnixStream::from(pending.fd.unwrap()).write_all(b"p").unwrap();
        pending_observer.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"p");
        let Incoming::Other(unexpected) = client.read_incoming().unwrap() else { panic!("unexpected matching frame") };
        assert_eq!((unexpected.header.ty, unexpected.blob), (ty::NOTIFY, other));
        assert!(client.pending.is_empty());
        producer.join().unwrap();
    }

    #[test]
    fn request_status_keeps_missing_invalid_and_short_scalar_rules() {
        for (value, expected) in [
            (None, status::INVALID_ARGUMENT),
            (Some(vec![7]), 7),
            (Some(vec![0, 8]), 8),
            (Some(vec![0xff, 0xff, 0xff, 0xf9]), -7),
            (Some(vec![1, 2, 3]), status::INVALID_ARGUMENT),
        ] {
            let (mut client, mut server) = pair();
            let producer = std::thread::spawn(move || {
                let request = server.recv().unwrap();
                let mut blob = BlobBuf::new();
                if let Some(value) = value {
                    blob.put_u32(attr::STATUS, 0).put(attr::STATUS, &value);
                }
                server.send(Header { ty: ty::STATUS, ..request.header }, &mut blob, None).unwrap();
            });
            let reply = client.request(ty::LOOKUP, 0, &mut BlobBuf::new(), None, 2000).unwrap();
            assert_eq!(reply.status, expected);
            assert!(reply.data.is_empty() && reply.fd.is_none());
            producer.join().unwrap();
        }
    }

    #[test]
    fn complete_data_before_timeout_keeps_pending_fd_and_late_status_boundary() {
        let (mut client, mut server) = pair();
        let (passed, mut observer) = UnixStream::pair().unwrap();
        observer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let producer = std::thread::spawn(move || {
            let first = server.recv().unwrap();
            let mut blob = BlobBuf::new();
            blob.put(attr::DATA, b"discarded partial reply");
            server.send(Header { ty: ty::DATA, ..first.header }, &mut blob, None).unwrap();
            blob.reset();
            blob.put_u32(attr::OBJID, 42).put_string(attr::METHOD, "pending");
            server.send(Header { ty: ty::INVOKE, seq: 9, peer: 7 }, &mut blob, Some(passed.as_raw_fd())).unwrap();
            drop(passed);
            std::thread::sleep(Duration::from_millis(120));
            blob.reset();
            blob.put_u32(attr::STATUS, 0);
            server.send(Header { ty: ty::STATUS, ..first.header }, &mut blob, None).unwrap();
            let second = server.recv().unwrap();
            server.send(Header { ty: ty::STATUS, ..second.header }, &mut blob, None).unwrap();
        });
        let error = client.request(ty::LOOKUP, 0, &mut BlobBuf::new(), None, 40).unwrap_err();
        assert_eq!(error_status(&error), Some(status::TIMEOUT));
        let second = client.request(ty::LOOKUP, 0, &mut BlobBuf::new(), None, 2000).unwrap();
        assert_eq!(second.status, 0);
        assert!(second.data.is_empty(), "DATA from the timed-out request cannot leak into the next reply");
        let Incoming::Invoke(pending) = client.read_incoming().unwrap() else { panic!("pending FD") };
        UnixStream::from(pending.fd.unwrap()).write_all(b"x").unwrap();
        observer.read_exact(&mut [0]).unwrap();
        let Incoming::Other(late) = client.read_incoming().unwrap() else { panic!("late STATUS") };
        assert_eq!((late.header.ty, late.header.seq, late.status()), (ty::STATUS, 1, Some(0)));
        assert!(client.pending.is_empty());
        producer.join().unwrap();
    }

