use super::*;
use std::sync::mpsc;
use std::thread;

fn fixture() -> (Arc<Server>, Arc<Parking>) {
    let server = Arc::new(connection_tests::server(100));
    let (parking, _reader) = connection_tests::listener(&server);
    (server, parking)
}

fn work(server: &Arc<Server>, parking: &Arc<Parking>) -> (Work, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (transport, remote) = listener.accept().unwrap();
    let conn = Conn { local: transport.local_addr().unwrap(), remote, tls: false, fd: transport.as_raw_fd() };
    server.connections.fetch_add(1, Ordering::Relaxed);
    (Work { server: Arc::clone(server), parking: Arc::clone(parking),
            transport: Transport::Plain(transport), conn, resume: None }, peer)
}

fn discard(work: Work) {
    work.server.release_connection();
    drop(work);
}

#[test]
fn assignment_before_timeout_is_received_once_even_after_deadline() {
    let (server, parking) = fixture();
    let idle = Arc::new(IdleWorker::default());
    assert!(idle.publish(&server));
    let (job, _peer) = work(&server, &parking);
    let fd = job.conn.fd;
    let dispatch = thread::spawn({
        let server = Arc::clone(&server);
        move || dispatch_work(&server, job, |_| panic!("published worker must receive the job"))
    });
    dispatch.join().unwrap().unwrap();
    // This forces the exact ordering: dispatcher committed the work before
    // the worker obtains its mutex, but the worker observes an expired timer.
    let accepted = idle.wait(Instant::now()).expect("accepted work was lost to timeout");
    assert_eq!(accepted.conn.fd, fd);
    discard(accepted);
    assert!(idle.wait(Instant::now()).is_none(), "job delivered twice");
    assert_eq!(server.connections.load(Ordering::Relaxed), 0);
}

#[test]
fn timeout_before_assignment_rejects_stale_slot_and_dispatches_once() {
    let (server, parking) = fixture();
    let idle = Arc::new(IdleWorker::default());
    assert!(idle.publish(&server));
    thread::spawn({ let idle = Arc::clone(&idle); move || assert!(idle.wait(Instant::now()).is_none()) })
        .join().unwrap();
    let (job, _peer) = work(&server, &parking);
    let fd = job.conn.fd;
    let mut starts = 0;
    dispatch_work(&server, job, |job| {
        starts += 1;
        assert_eq!(job.conn.fd, fd);
        discard(job);
        Ok(())
    }).unwrap();
    assert_eq!(starts, 1);
    assert!(idle.wait(Instant::now()).is_none());
    assert!(server.idle_workers.lock().unwrap().is_empty());
    assert_eq!(server.connections.load(Ordering::Relaxed), 0);
}

#[test]
fn assigned_slot_rejects_a_second_job_without_overwriting_the_first() {
    let (server, parking) = fixture();
    let idle = Arc::new(IdleWorker::default());
    assert!(idle.publish(&server));
    let (first, _peer1) = work(&server, &parking);
    let (second, _peer2) = work(&server, &parking);
    let first_fd = first.conn.fd;
    assert!(idle.assign(first).is_none());
    discard(idle.assign(second).expect("second assignment replaced the pending job"));
    let accepted = idle.wait(Instant::now()).unwrap();
    assert_eq!(accepted.conn.fd, first_fd);
    discard(accepted);
    assert!(idle.wait(Instant::now()).is_none());
    assert_eq!(server.connections.load(Ordering::Relaxed), 0);
}

#[test]
fn failed_spawn_after_expired_slots_releases_one_permit_and_socket() {
    let (server, parking) = fixture();
    for _ in 0..MAX_IDLE_WORKERS {
        let idle = Arc::new(IdleWorker::default());
        assert!(idle.publish(&server));
        assert!(idle.wait(Instant::now()).is_none());
    }
    let (job, mut peer) = work(&server, &parking);
    let error = dispatch_work(&server, job, |job| {
        // Builder::spawn consumes its closure on failure too. Inject that
        // ownership boundary without changing process-wide RLIMIT_AS.
        drop(job);
        Err(io::Error::new(io::ErrorKind::WouldBlock, "injected spawn failure"))
    }).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(server.connections.load(Ordering::Relaxed), 0);
    assert!(server.idle_workers.lock().unwrap().is_empty());
    assert_eq!(peer.read(&mut [0]).unwrap(), 0, "failed spawn retained the socket");
}

#[test]
fn at_most_four_idle_workers_and_every_waiter_exits() {
    assert_eq!(MAX_IDLE_WORKERS, 4);
    let (server, _parking) = fixture();
    let barrier = Arc::new(std::sync::Barrier::new(9));
    let handles: Vec<_> = (0..8).map(|_| {
        let server = Arc::clone(&server);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let idle = Arc::new(IdleWorker::default());
            barrier.wait();
            let published = idle.publish(&server);
            barrier.wait();
            if published { assert!(idle.wait(Instant::now()).is_none()); }
            published
        })
    }).collect();
    barrier.wait();
    barrier.wait();
    assert_eq!(server.idle_workers.lock().unwrap().len(), MAX_IDLE_WORKERS);
    assert_eq!(handles.into_iter().map(|h| h.join().unwrap()).filter(|v| *v).count(), MAX_IDLE_WORKERS);
    assert!(server.idle_workers.lock().unwrap().iter().all(|slot|
        !slot.state.lock().unwrap().available));
}

#[test]
fn spurious_notification_does_not_extend_absolute_idle_deadline() {
    let (server, _parking) = fixture();
    let idle = Arc::new(IdleWorker::default());
    assert!(idle.publish(&server));
    let start = Instant::now();
    let deadline = start + Duration::from_millis(80);
    let (done, finished) = mpsc::channel();
    let waiter = thread::spawn({
        let idle = Arc::clone(&idle);
        move || { assert!(idle.wait(deadline).is_none()); done.send(()).unwrap(); }
    });
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let notifier = thread::spawn({
        let idle = Arc::clone(&idle);
        let stop = Arc::clone(&stop);
        move || {
            while !stop.load(Ordering::Relaxed) {
                idle.ready.notify_one();
                thread::sleep(Duration::from_millis(5));
            }
        }
    });
    let result = finished.recv_timeout(Duration::from_millis(300));
    stop.store(true, Ordering::Relaxed);
    notifier.join().unwrap();
    result.expect("notifications extended the absolute timeout");
    waiter.join().unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(!idle.state.lock().unwrap().available);
}

#[test]
fn real_worker_reuses_for_two_http_requests_and_exits_after_idle() {
    let (server, parking) = fixture();
    let request = b"GET /r93-nonexistent-file HTTP/1.0\r\nHost: localhost\r\n\r\n";
    let (first, mut peer1) = work(&server, &parking);
    let handle = thread::spawn(move || run_worker(first));
    peer1.write_all(request).unwrap();
    let mut response1 = Vec::new();
    peer1.read_to_end(&mut response1).unwrap();
    assert!(response1.starts_with(b"HTTP/1.0 404 "));
    let deadline = Instant::now() + Duration::from_secs(1);
    while server.idle_workers.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "worker did not publish idle slot");
        thread::yield_now();
    }
    let (second, mut peer2) = work(&server, &parking);
    dispatch_work(&server, second, |_| panic!("second request should reuse the worker")).unwrap();
    peer2.write_all(request).unwrap();
    let mut response2 = Vec::new();
    peer2.read_to_end(&mut response2).unwrap();
    assert!(response2.starts_with(b"HTTP/1.0 404 "));
    for response in [&response1, &response2] {
        assert_eq!(response.windows(b"HTTP/1.0".len()).filter(|part| *part == b"HTTP/1.0").count(), 1);
    }
    // Date may cross a second; the bodies and response counts must match.
    let body = |response: &[u8]| response.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(&response1[body(&response1)..], &response2[body(&response2)..]);
    assert_eq!(server.connections.load(Ordering::Relaxed), 0);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !handle.is_finished() {
        assert!(Instant::now() < deadline, "cached worker did not exit");
        thread::sleep(Duration::from_millis(5));
    }
    handle.join().unwrap();
    assert!(server.idle_workers.lock().unwrap().iter().all(|slot|
        !slot.state.lock().unwrap().available));
}
