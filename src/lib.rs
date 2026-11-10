use base64::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use jiff::{Timestamp, ToSpan, Unit};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const AWS4_REQUEST: &str = "aws4_request";
const AWS4: &str = "AWS4";

#[derive(Serialize, Debug, Clone)]
pub struct Policy {
    expiration: Timestamp,
    conditions: Vec<Value>,
}

#[derive(Serialize, Debug, Clone)]
pub struct SignedPolicy {
    pub base64_encoding: String,
    pub signature: String,
}

impl Policy {
    pub fn sign(&self, signing_key: &[u8]) -> SignedPolicy {
        let policy: String = serde_json::to_string(&self).unwrap();
        get_policy_signature(&policy, signing_key)
    }

    fn get_default_conditions(x_amz_credential: &str, x_amz_date: &str) -> Vec<Value> {
        let alg = json!({"x-amz-algorithm":"AWS4-HMAC-SHA256"});
        let credential = json!({"x-amz-credential": x_amz_credential});
        let date = json!({"x-amz-date": x_amz_date});

        vec![credential, alg, date]
    }

    /// Create a policy which expire in X minutes
    pub fn new_with_expiration_in_minutes(
        minutes: i64,
        x_amz_credential: &str,
        x_amz_date: &str,
    ) -> Self {
        let expiration = Timestamp::now()
            .round(Unit::Millisecond)
            .unwrap()
            .checked_add(minutes.minutes())
            .unwrap();

        let conditions = Policy::get_default_conditions(x_amz_credential, x_amz_date);

        Self {
            expiration,
            conditions,
        }
    }

    /// Create a policy with an exact expiration date
    pub fn new_with_exact_expiration(
        expiration: Timestamp,
        x_amz_credential: &str,
        x_amz_date: &str,
    ) -> Self {
        let conditions = Policy::get_default_conditions(x_amz_credential, x_amz_date);

        Self {
            expiration,
            conditions,
        }
    }

    /// Specifies the exact bucket the user must upload to
    pub fn bucket(mut self, bucket: &str) -> Self {
        let map = json!({"bucket":bucket});
        self.conditions.push(map);
        self
    }

    /// Specifies the content length range in bytes e.g. 1048576 for a mb
    pub fn content_length_range(mut self, lower: usize, upper: usize) -> Self {
        let value = json!(["content-length-range", lower, upper]);
        self.conditions.push(value);
        self
    }

    /// Specifies the exact content type the user must upload with
    pub fn content_type(mut self, content_type: &str) -> Self {
        let value = json!({"content-type":content_type});
        self.conditions.push(value);
        self
    }

    /// Specifies the prefix the content type must start with (e.g. "image/")
    pub fn starts_with_content_type(mut self, content_type: &str) -> Self {
        let value = json!(["starts-with", "$content-type", content_type]);
        self.conditions.push(value);
        self
    }

    /// Specifies the exact key the user must upload with
    pub fn key(mut self, key: &str) -> Self {
        let value = json!({"key":key});
        self.conditions.push(value);
        self
    }

    /// Specifies the prefix the key must start with (e.g. "user/user1/")
    pub fn starts_with_key(mut self, key: &str) -> Self {
        let value = json!(["starts-with", "$key", key]);
        self.conditions.push(value);
        self
    }

    /// Adds a custom condition to the policy
    pub fn condition(mut self, condition: Value) -> Self {
        self.conditions.push(condition);
        self
    }
}

// Utility function to chain hmac steps
fn hmac_step(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data); // <--- Feeds data into the message, not the key
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

/// This function derives signing key by taking a secret_access_key, date, region and service. The
/// date is in YYYYMMDD format and the region is lower case for more info see https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-post-example.html
pub fn derive_signing_key(
    secret_access_key: &str,
    date: &str,
    region: &str,
    service: &str,
) -> [u8; 32] {
    let first_input = format!("{AWS4}{secret_access_key}");

    let date_key = hmac_step(first_input.as_bytes(), date.as_bytes());
    let date_region_key = hmac_step(&date_key, region.as_bytes());
    let date_region_service_key = hmac_step(&date_region_key, service.as_bytes());
    let final_key = hmac_step(&date_region_service_key, AWS4_REQUEST.as_bytes());

    final_key
}

/// This function generates a signature with a policy and a signing key. The policy can be written
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

#[cfg(test)]
mod tests;
