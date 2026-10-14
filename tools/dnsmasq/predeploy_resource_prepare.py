#!/usr/bin/env python3
"""Prepare audit-only clients from the established checked M6a wire clients.

The DHCP relay variant uses 127.0.0.2:15467 -> 127.0.0.1:15467 only.
No broadcast packets, real MACs, client leases, or product edits are involved.
"""
import argparse
from pathlib import Path


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'expected one source anchor: {old!r}')
    return text.replace(old, new, 1)


def prepare(out):
    source = Path(__file__).resolve().parent
    out.mkdir(parents=True, exist_ok=True)
    text = (source / 'm6a_loadgen.c').read_text()
    text = replace_once(text, 'memcpy(p+236,"\\x63\\x82\\x53\\x63",4); size_t n=240;',
                        'memset(p+24,255,4); /* audit: dnsmasq local relay-source extension */\n'
                        '  memcpy(p+236,"\\x63\\x82\\x53\\x63",4); size_t n=240;')
    text = replace_once(text, 'if (kind==1 || (kind==3 && c->dhcp_stage==1)) target.sin_addr.s_addr=INADDR_BROADCAST;',
                        '/* audit: every DHCP request stays unicast on loopback. */')
    text = replace_once(text, 'local.sin_port=htons((uint16_t)opt.client_port);',
                        'local.sin_port=htons((uint16_t)opt.client_port);\n'
                        '    local.sin_addr.s_addr=htonl(0x7f000002u);')
    # DNS client sockets also explicitly bind loopback, including ephemeral ports.
    text = replace_once(text, 'if (connect(c->fd,(struct sockaddr *)&destination,sizeof(destination))) return false;',
                        'struct sockaddr_in local={.sin_family=AF_INET};\n'
                        '  local.sin_addr.s_addr=htonl(0x7f000001u);\n'
                        '  if (bind(c->fd,(struct sockaddr *)&local,sizeof local)) return false;\n'
                        '  if (connect(c->fd,(struct sockaddr *)&destination,sizeof(destination))) return false;')
    text = text.replace('{192,0,2,1}', '{93,184,215,14}')
    text = text.replace('{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}', '{0x26,6,0x47,0,0x47,0,0,0,0,0,0,0,0,0,0x11,0x11}')
    (out / 'loadgen.c').write_text(text)
    text = (source / 'm6a_upstream.c').read_text()
    text = replace_once(text, '#include <string.h>', '#include <string.h>\n#include <strings.h>')
    text = replace_once(text, '!strncmp(host,"cname-",6)', '!strncasecmp(host,"cname-",6)')
    text = text.replace('{192,0,2,1}', '{93,184,215,14}')
    text = text.replace('{0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}', '{0x26,6,0x47,0,0x47,0,0,0,0,0,0,0,0,0,0x11,0x11}')
    (out / 'upstream.c').write_text(text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    prepare(parser.parse_args().output)
