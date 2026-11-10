//! SigV4 signing key derivation and policy signing.

use base64::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;

use crate::context::SigningContext;

type HmacSha256 = Hmac<Sha256>;

pub(crate) const AWS4_REQUEST: &str = "aws4_request";
const AWS4: &str = "AWS4";

#[derive(Serialize, Debug, Clone)]
pub struct SignedPolicy {
    pub base64_encoding: String,
    pub signature: String,
}

// Utility function to chain hmac steps
fn hmac_step(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// enum Method {
//     POST,
//     PUT,
//     DELETE,
//     PATCH,
// }
//
// impl From<Method> for String {
//     fn from(value: Method) -> Self {
//         match value {
//             Method::POST => "POST",
//             Method::PUT => "PUT",
//             Method::DELETE => "DELETE",
//             Method::PATCH => "PATCH",
//         }
//         .to_string()
//     }
// }

/// This function derives signing key by taking a SigningContext. The
/// date is in YYYYMMDD format and the region is lower case for more info see https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-post-example.html
pub fn derive_signing_key(
    signing_context: &SigningContext
) -> [u8; 32] {
    let first_input = format!("{}{}",AWS4,signing_context.secret_access_key);

    let date_key = hmac_step(first_input.as_bytes(), signing_context.date.as_bytes());
    let date_region_key = hmac_step(&date_key, signing_context.region.as_str().as_bytes());
    let date_region_service_key = hmac_step(&date_region_key, signing_context.service.as_str().as_bytes());
    let final_key = hmac_step(&date_region_service_key, AWS4_REQUEST.as_bytes());

    final_key
}

/// This function generates a signature using a provided policy and signing key. The policy can be written
/// manually or constructed with the Policy struct
pub fn get_policy_signature(policy: &str, signing_key: &[u8]) -> SignedPolicy {
    let base64_policy = BASE64_STANDARD.encode(policy);

    let mut sig_mac =
        HmacSha256::new_from_slice(signing_key).expect("HMAC can take key of any size");
    sig_mac.update(base64_policy.as_bytes());
    let result = sig_mac.finalize();
    SignedPolicy {
        base64_encoding: base64_policy,
        signature: hex::encode(result.into_bytes()),
    }
}
