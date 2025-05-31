use wasm_bindgen::prelude::*;
use crate::crypto::{generate_keypair_generic, sign_generic, verify_generic, CryptoError};
use crate::params::{Mayo1, Mayo2, Mayo3, Mayo5};

// Helper to convert CryptoError to JsValue
fn to_js_error(err: CryptoError) -> JsValue {
    JsValue::from_str(&format!("CryptoError: {}", err))
}

#[wasm_bindgen]
pub fn generate_mayo_keypair(param_set_name: &str) -> Result<JsValue, JsValue> {
    match param_set_name {
        "MAYO1" => {
            let (sk, pk) = generate_keypair_generic::<Mayo1>().map_err(to_js_error)?;
            Ok(js_sys::Array::of2(&js_sys::Uint8Array::from(sk.as_slice()), &js_sys::Uint8Array::from(pk.as_slice())).into())
        }
        "MAYO2" => {
            let (sk, pk) = generate_keypair_generic::<Mayo2>().map_err(to_js_error)?;
            Ok(js_sys::Array::of2(&js_sys::Uint8Array::from(sk.as_slice()), &js_sys::Uint8Array::from(pk.as_slice())).into())
        }
        "MAYO3" => {
            let (sk, pk) = generate_keypair_generic::<Mayo3>().map_err(to_js_error)?;
            Ok(js_sys::Array::of2(&js_sys::Uint8Array::from(sk.as_slice()), &js_sys::Uint8Array::from(pk.as_slice())).into())
        }
        "MAYO5" => {
            let (sk, pk) = generate_keypair_generic::<Mayo5>().map_err(to_js_error)?;
            Ok(js_sys::Array::of2(&js_sys::Uint8Array::from(sk.as_slice()), &js_sys::Uint8Array::from(pk.as_slice())).into())
        }
        _ => Err(JsValue::from_str("Invalid MAYO parameter set name"))
    }
}

#[wasm_bindgen]
pub fn sign_with_mayo(param_set_name: &str, secret_key: &[u8], message: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    match param_set_name {
        "MAYO1" => sign_generic::<Mayo1>(secret_key, message).map_err(to_js_error).map(|sig| js_sys::Uint8Array::from(sig.as_slice())),
        "MAYO2" => sign_generic::<Mayo2>(secret_key, message).map_err(to_js_error).map(|sig| js_sys::Uint8Array::from(sig.as_slice())),
        "MAYO3" => sign_generic::<Mayo3>(secret_key, message).map_err(to_js_error).map(|sig| js_sys::Uint8Array::from(sig.as_slice())),
        "MAYO5" => sign_generic::<Mayo5>(secret_key, message).map_err(to_js_error).map(|sig| js_sys::Uint8Array::from(sig.as_slice())),
        _ => Err(JsValue::from_str("Invalid MAYO parameter set name"))
    }
}

#[wasm_bindgen]
pub fn verify_with_mayo(param_set_name: &str, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    match param_set_name {
        "MAYO1" => verify_generic::<Mayo1>(public_key, message, signature).map_err(to_js_error),
        "MAYO2" => verify_generic::<Mayo2>(public_key, message, signature).map_err(to_js_error),
        "MAYO3" => verify_generic::<Mayo3>(public_key, message, signature).map_err(to_js_error),
        "MAYO5" => verify_generic::<Mayo5>(public_key, message, signature).map_err(to_js_error),
        _ => Err(JsValue::from_str("Invalid MAYO parameter set name"))
    }
}
