//! The `luci` object: placeholder until the ucode plugin port lands.
use crate::Ctx;
use owrt_ubus::json::Json;
use owrt_ubus::MsgType;

pub fn signature() -> Vec<(&'static str, Vec<(&'static str, MsgType)>)> {
    vec![("getVersion", vec![])]
}

pub fn call(_ctx: &Ctx, _method: &str, _args: &Json) -> Result<Option<Json>, i32> {
    Err(owrt_ubus::status::METHOD_NOT_FOUND)
}
