// Private netifd-shaped provider. Changes only synthetic DNS configuration;
// every update is a real network.interface subscription notification.
import { connect } from 'ubus';
import { writefile } from 'fs';
import { init, run } from 'uloop';

init();
let bus = connect();
if (!bus) die('private ubus unavailable');
let sequence = 0, dumps = 0, notifications = 0;
let state = {
    interface: [{
        interface: 'lan', up: true, l3_device: 'br-lan',
        'ipv6-address': [{address: '2001:db8:1::1', mask: 64},
                         {address: 'fd12:3456:789a::1', mask: 60}],
        'ipv6-prefix': [], data: {}
    }]
};
let network = bus.publish('network.interface', {
    dump: {call: () => { dumps++; return state; }}
});
bus.publish('fixture', {
    change: {args: {sequence: 0}, call: req => {
        let next = req.args.sequence;
        if (next != sequence + 1 || next < 1 || next > 8)
            die('invalid or repeated update sequence');
        sequence = next;
        state.interface[0].data = {dns: [sprintf('2001:db8:53::%x', sequence)]};
        network.notify('update', {interface: 'lan'});
        notifications++;
        return {sequence, notifications, subscribed: network.subscribed()};
    }},
    stats: {call: () => ({sequence, dumps, notifications, subscribed: network.subscribed()})}
});
writefile('/tmp/provider.ready', 'ready\n');
run();
