# R103: borrow user event fields before dispatch

The R100 lazy event path already deferred internal/object event encoding, but `event_send` still copied the user event ID and data into two vectors before dispatch. This happened even when no event pattern could receive the event. The R103 candidate keeps both slices borrowed from the request and passes a one-shot builder to the existing lazy dispatcher. The frame is allocated only after the first eligible receiver is found.

The change preserves ACL checks, reserved `ubus.` rejection, event round advancement, per-receiver object ID patching, monitor mirroring, queue ownership and wire bytes. It adds no fields and changes no event matching algorithm.

Build-host tests pass 35/35. On the physical router the candidate passed all seven C/before/candidate wire differentials and its unit binary passed 35/35. Boot/configuration/production identity and cleanup passed. Six host gates are still running; no performance result exists yet.

The failed initial compile against the old pre-lazy source was discarded and not measured; it correctly caught a mixed-base mistake. The accepted candidate was rebuilt from the full R100 source and only this change was applied.
