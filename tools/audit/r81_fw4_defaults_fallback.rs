//! R81 fw4 audit: an invalid option in `config defaults` must degrade to ucode's
//! own defaults (R25 §3.1 claims it does); instead `parse_defaults` stores an
//! all-`None` `Defaults` and the renderer prints `policy null;` / `reject with
//! icmpx type ` which nft rejects.  NOT RUN (no cargo on the audit host).
//! To run: copy into components/fw4/tests/ (deps owrt-ubus/owrt-uci resolve
//! there) and `cargo test r81_defaults_fallback`.
#![allow(dead_code)]

#[path = "../../components/fw4/src/emit.rs"]
mod emit;
#[path = "../../components/fw4/src/input.rs"]
mod input;
#[path = "../../components/fw4/src/ip.rs"]
mod ip;
#[path = "../../components/fw4/src/parse.rs"]
mod parse;
#[path = "../../components/fw4/src/render.rs"]
mod render;
#[path = "../../components/fw4/src/sections.rs"]
mod sections;
#[path = "../../components/fw4/src/state.rs"]
mod state;
#[path = "../../components/fw4/src/statefile.rs"]
mod statefile;
#[path = "../../components/fw4/src/uci.rs"]
mod uci;
#[path = "../../components/fw4/src/val.rs"]
mod val;

#[test]
fn r81_defaults_fallback() {
    // `option input 'ACEPT'` (typo) is what a user would hit; every other
    // option is the device's real defaults section.
    let cfg = owrt_ubus::json::parse(
        r#"{"defaults":{"input":"ACEPT","output":"ACCEPT","forward":"REJECT","syn_flood":"1"},
            "zone":[{"name":"lan","device":"br-lan","input":"ACCEPT","output":"ACCEPT","forward":"ACCEPT"}]}"#,
    )
    .unwrap();
    let mut fw = parse::Fw4 {
        inputs: input::Inputs::mock(vec![], false),
        firewall: uci::Config::from_mock(&cfg),
        helpers_cfg: uci::Config::empty(),
        state: state::State::default(),
        kernel: 0x060600,
        quiet: true,
        tty: false,
    };
    let d = fw.firewall.of_type("defaults").next().cloned().unwrap();
    fw.parse_defaults(&d);
    // fw4.uc: parse_options() returned false; the only non-crashing reading of
    // "degrade to ucode defaults" is what load() does when no defaults section
    // exists at all: parse_defaults({}) -> drop/drop/drop, tcp-reset, ...
    let z = fw.firewall.of_type("zone").next().cloned().unwrap();
    fw.parse_zone(&z);
    let out = fw.render_ruleset();
    assert!(!out.contains("policy null"), "renderer emitted `policy null;`:\n{out}");
    assert!(!out.contains("icmpx type  "), "renderer emitted an empty reject code:\n{out}");
    assert!(out.contains("type filter hook input priority filter; policy drop;"), "{out}");
    assert!(out.contains("reject with icmpx type port-unreachable"), "{out}");
}
