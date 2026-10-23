//! Fixed worker registration shared by the daemon and sole-thread test entries.

pub(super) fn workers() {
    use dnsmasq_platform::process::{AuditedWorker, StartupCallbacks};
    use dnsmasq_rs::{config::dns::lookup, helper, startup::daemonize};

    // SAFETY: HelperStartup has only owned paths/bytes and scalar settings.
    // The fixed entry uses its own IPC descriptors and standard streams. This
    // executable has no application atfork hooks or shared writable mappings;
    // its signal handlers use only atomic flags and the platform wake pipe.
    // The platform verifies the current thread condition on every fork and
    // replaces the child's inherited panic hook before abandoning descriptors.
    let helper: helper::HelperWorker = unsafe { AuditedWorker::new(helper::worker_entry) };
    helper::install_worker(helper).expect("helper worker is registered once");

    // SAFETY: LookupInput contains only owned rules, addresses and scalars.
    // The fixed resolver entry accesses these values and its result writer,
    // under the same executable-wide atfork/mapping/handler policy above.
    let lookup: lookup::LookupWorker = unsafe { AuditedWorker::new(lookup::worker_entry) };
    lookup::install_worker(lookup).expect("resolver worker is registered once");

    // SAFETY: both fixed startup callbacks consume only their supplied pipe,
    // private diagnostic buffers and standard streams. They do not access the
    // abandoned service graph and cannot return through it after the fork.
    let startup: StartupCallbacks =
        unsafe { AuditedWorker::new((daemonize::parent_report, daemonize::fork_failed)) };
    daemonize::install_worker(startup).expect("startup callbacks are registered once");
}
