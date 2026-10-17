// Only launched in the private chroot/socket by driver.sh.
import { connect } from 'ubus';
import { readfile, writefile } from 'fs';
import { init, run } from 'uloop';

init();
let bus = connect();
if (!bus) die('private ubus unavailable');
let inputs = [json(readfile('/tmp/bin/network-a.json')), json(readfile('/tmp/bin/network-b.json'))];
let active = 0;
if (!bus.publish('network.interface', { dump: { call: () => inputs[active] } }) ||
    !bus.publish('service', { get_data: { args: { type: '' }, call: () => ({}) } }) ||
    !bus.publish('fixture', { select: { args: { variant: 0 }, call: request => {
        let variant = request.args.variant;
        if (variant != 0 && variant != 1) return 2;
        active = variant;
        return { active };
    } } })) die('private fixture registration failed');
writefile('/tmp/out/fixture.ready', 'ready\n');
run();
