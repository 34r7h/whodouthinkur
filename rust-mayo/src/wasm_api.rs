use wasm_bindgen::prelude::*;
use crate::crypto::{generate_keypair_generic, sign_generic, verify_generic, CryptoError};
use crate::params::{Mayo1, Mayo2, Mayo3, Mayo5};

// Helper to convert CryptoError to JsValue
fn to_js_error(err: CryptoError) -> JsValue {
    JsValue::from_str(&format!("CryptoError: {}", err))
}

#[wasm_bindgen]
pub fn generate_keypair_wasm(param_set_name: &str) -> Result<JsValue, JsValue> {
    web_sys::console::log_1(&format!("[WASM] generate_keypair_wasm called: param={}", param_set_name).into());
    
    let result = match param_set_name {
        "MAYO1" => generate_keypair_generic::<Mayo1>().map_err(to_js_error)?,
        "MAYO2" => generate_keypair_generic::<Mayo2>().map_err(to_js_error)?,
        "MAYO3" => generate_keypair_generic::<Mayo3>().map_err(to_js_error)?,
        "MAYO5" => generate_keypair_generic::<Mayo5>().map_err(to_js_error)?,
        _ => return Err(JsValue::from_str("Invalid MAYO parameter set name"))
    };
    
    let (sk, pk) = result;
    
    // Create a JavaScript object with the keys
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"secret_key".into(), &js_sys::Uint8Array::from(sk.as_slice()))?;
    js_sys::Reflect::set(&obj, &"public_key".into(), &js_sys::Uint8Array::from(pk.as_slice()))?;
    
    web_sys::console::log_1(&format!("[WASM] Keys generated: SK={} bytes, PK={} bytes", sk.len(), pk.len()).into());
    
    Ok(obj.into())
}

#[wasm_bindgen]
pub fn generate_mayo_keypair(param_set_name: &str) -> Result<JsValue, JsValue> {
    generate_keypair_wasm(param_set_name)
}

#[wasm_bindgen]
pub fn sign_with_mayo(param_set_name: &str, secret_key: &[u8], message: &[u8]) -> Result<js_sys::Uint8Array, JsValue> {
    web_sys::console::log_1(&format!("[WASM] sign_with_mayo called: param={}, sk_len={}, msg_len={}", param_set_name, secret_key.len(), message.len()).into());
    
    match param_set_name {
        "MAYO1" => {
            web_sys::console::log_1(&"[WASM] Calling sign_generic for MAYO1".into());
            match sign_generic::<Mayo1>(secret_key, message) {
                Ok(sig) => {
                    web_sys::console::log_1(&format!("[WASM] Signing SUCCESS: {} bytes", sig.len()).into());
                    Ok(js_sys::Uint8Array::from(sig.as_slice()))
                }
                Err(e) => {
                    web_sys::console::log_1(&format!("[WASM] Signing FAILED: {}", e).into());
                    Err(to_js_error(e))
                }
            }
        }
        "MAYO2" => sign_generic::<Mayo2>(secret_key, message).map_err(to_js_error).map(|sig| js_sys::Uint8Array::from(sig.as_slice())),
        "MAYO3" => sign_generic::<Mayo3>(secret_key, message).map_err(to_js_error).map(|sig| js_sys::Uint8Array::from(sig.as_slice())),
        "MAYO5" => sign_generic::<Mayo5>(secret_key, message).map_err(to_js_error).map(|sig| js_sys::Uint8Array::from(sig.as_slice())),
        _ => Err(JsValue::from_str("Invalid MAYO parameter set name"))
    }
}

#[wasm_bindgen]
pub fn verify_with_mayo(param_set_name: &str, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    web_sys::console::log_1(&format!("[WASM] verify_with_mayo called: param={}, pk_len={}, msg_len={}, sig_len={}", param_set_name, public_key.len(), message.len(), signature.len()).into());
    
    match param_set_name {
        "MAYO1" => {
            web_sys::console::log_1(&"[WASM] Calling verify_generic for MAYO1".into());
            match verify_generic::<Mayo1>(public_key, message, signature) {
                Ok(result) => {
                    web_sys::console::log_1(&format!("[WASM] Verification RESULT: {}", result).into());
                    Ok(result)
                }
                Err(e) => {
                    web_sys::console::log_1(&format!("[WASM] Verification FAILED: {}", e).into());
                    Err(to_js_error(e))
                }
            }
        }
        "MAYO2" => verify_generic::<Mayo2>(public_key, message, signature).map_err(to_js_error),
        "MAYO3" => verify_generic::<Mayo3>(public_key, message, signature).map_err(to_js_error),
        "MAYO5" => verify_generic::<Mayo5>(public_key, message, signature).map_err(to_js_error),
        _ => Err(JsValue::from_str("Invalid MAYO parameter set name"))
    }
}
