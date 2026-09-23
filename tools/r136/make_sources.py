#!/usr/bin/env python3
"""Freeze three independent allocation/probe ablations and their combination."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

BASE = 'db6a6b6'


def replace(path, old, new):
    data = path.read_text()
    if data.count(old) != 1:
        raise RuntimeError(f'expected one match in {path}: {old[:60]}')
    path.write_text(data.replace(old, new))


def path_borrow(root):
    obj = root / 'ubusd/src/obj.rs'
    server = root / 'ubusd/src/server.rs'
    replace(obj, 'path: Vec<u8>) -> bool', 'path: &[u8]) -> bool')
    replace(obj, 'self.paths.contains_key(path.as_slice())', 'self.paths.contains_key(path)')
    replace(server, 'let path = obj::cstr_bytes(p.payload).to_vec();',
            'let path = obj::cstr_bytes(p.payload);')
    # Tests use the same borrowed interface, including binary/non-UTF8 paths.
    replace(obj, 'r.set_path(id, p.to_vec())', 'r.set_path(id, p)')
    replace(obj, 'r.set_path(3000, b"network".to_vec())', 'r.set_path(3000, b"network")')
    data = server.read_text()
    data = data.replace('format!("lookup.{i:04}").into_bytes()', '&format!("lookup.{i:04}").into_bytes()')
    data = data.replace('format!("lookup.{i:02}").into_bytes()', '&format!("lookup.{i:02}").into_bytes()')
    data = data.replace('set_path(9000, next)', 'set_path(9000, &next)')
    data = data.replace('set_path(9001, b"lookup.00a".to_vec())', 'set_path(9001, b"lookup.00a")')
    data = data.replace('set_path(9002, b"outside".to_vec())', 'set_path(9002, b"outside")')
    data = data.replace('set_path(id, path.to_vec())', 'set_path(id, path)')
    server.write_text(data)
    replace(root / 'ubusd/examples/registry_memory.rs',
            'set_path(4096 + i, path(i, len))', 'set_path(4096 + i, &path(i, len))')
    replace(root / 'ubusd/examples/profile.rs',
            'set_path(id, format!("bench.object{i:04}").into_bytes())',
            'set_path(id, &format!("bench.object{i:04}").into_bytes())')


def event_strings(root):
    server = root / 'ubusd/src/server.rs'
    replace(server, 'b.put(attr::METHOD, &with_nul(name));', 'b.put_string_bytes(attr::METHOD, name);')
    replace(server, 'b.msg_field(MsgType::String as u32, "path", &with_nul(&path));',
            'b.msg_string_bytes("path", &path);')
    # Registered paths are canonical C strings, so no embedded NUL is lost.


def registry_entry(root):
    obj = root / 'ubusd/src/obj.rs'
    replace(obj, 'use std::collections::HashMap;',
            'use std::collections::{HashMap, hash_map::Entry};')
    replace(obj, '''        let id = Self::alloc_id(|id| self.types.contains_key(&id))?;
        self.types.insert(id, ObjType { refcount: 1, methods });
        Ok(id)''', '''        loop {
            let id = crate::sys::random_id(SYSTEM_OBJECT_MAX)?;
            if let Entry::Vacant(slot) = self.types.entry(id) {
                slot.insert(ObjType { refcount: 1, methods });
                return Ok(id);
            }
        }''')
    replace(obj, '''        if let Some(t) = self.types.get_mut(&id) {
            t.refcount -= 1;
            if t.refcount == 0 {
                self.types.remove(&id);
            }
        }''', '''        if let Entry::Occupied(mut slot) = self.types.entry(id) {
            let t = slot.get_mut();
            t.refcount -= 1;
            if t.refcount == 0 {
                slot.remove();
            }
        }''')
    replace(obj, '''        let id = match fixed_id {
            Some(id) => id,
            None => Self::alloc_id(|id| self.objects.contains_key(&id))?,
        };
        if self.objects.contains_key(&id) {
            return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "object id in use"));
        }
        if let Some(t) = type_id.and_then(|t| self.types.get_mut(&t)) {
            t.refcount += 1;
        }
        self.objects.insert(id, Object::new(type_id));
        Ok(id)''', '''        loop {
            let id = match fixed_id {
                Some(id) => id,
                None => crate::sys::random_id(SYSTEM_OBJECT_MAX)?,
            };
            match self.objects.entry(id) {
                Entry::Occupied(_) if fixed_id.is_some() => {
                    return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "object id in use"));
                }
                Entry::Occupied(_) => continue,
                Entry::Vacant(slot) => {
                    if let Some(t) = type_id.and_then(|t| self.types.get_mut(&t)) {
                        t.refcount += 1;
                    }
                    slot.insert(Object::new(type_id));
                    return Ok(id);
                }
            }
        }''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[2]
    archive = subprocess.check_output(['git', '-C', str(repo), 'archive', BASE,
                                       'components/ubusd', 'components/ubus'])
    subprocess.run(['tar', '-xf', '-', '-C', str(args.out)], input=archive, check=True)
    variants = [('base', []), ('path', [path_borrow]), ('entry', [registry_entry]),
                ('strings', [event_strings]), ('combined', [path_borrow, registry_entry, event_strings])]
    records = []
    for label, mutations in variants:
        dest = args.out / label / 'components'
        shutil.copytree(args.out / 'components', dest)
        for mutation in mutations:
            mutation(dest)
        sources = {str(p.relative_to(dest)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted(dest.rglob('*')) if p.is_file()}
        records.append(dict(label=label, mutations=[f.__name__ for f in mutations], source_sha256=sources))
    shutil.rmtree(args.out / 'components')
    (args.out / 'sources.json').write_text(json.dumps(dict(base_commit=BASE, variants=records), indent=2) + '\n')


if __name__ == '__main__':
    main()
