# owrt-switch

`owrt-switch status` prints one line per Rust component (reload-config, logd,
httpd, fw4, rpcd): switch state, boot-enable, daemon pid, package version.
`enable-all` / `disable-all` run the per-component switches in dependency
order (reverse for disable); `boot-enable on|off|status` applies to all five.
Nothing is changed by the script itself; every action is one of the existing
`owrt-<name>-switch` commands.
