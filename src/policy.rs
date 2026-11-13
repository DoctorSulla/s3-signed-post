//! POST policy construction.

use jiff::{Timestamp, ToSpan, Unit};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

use crate::context::SigningContext;
use crate::derive_signing_key;
use crate::signing::{AWS4_HMAC_SHA256, SignedPolicy, get_policy_signature};

#[derive(Serialize, Debug, Clone)]
pub struct Policy {
    expiration: Timestamp,
    conditions: Vec<Value>,
    #[serde(skip_serializing)]
    post_fields: BTreeMap<String, String>,
}

impl Policy {
    /// Returns the form fields to send with the upload, including the signed policy
    pub fn get_post_fields(&self, signing_context: &SigningContext) -> BTreeMap<String, String> {
        let mut post_fields = self.post_fields.clone();

        let signed_policy = self.sign(&derive_signing_key(signing_context));

        post_fields.insert("policy".to_string(), signed_policy.base64_encoding);
        post_fields.insert("x-amz-signature".to_string(), signed_policy.signature);
        for (name, value) in Policy::get_default_fields(signing_context) {
            post_fields.insert(name.to_string(), value);
        }

        post_fields
    }

    /// Base64-encodes the policy JSON and signs it with the given signing key
    pub fn sign(&self, signing_key: &[u8]) -> SignedPolicy {
        let policy: String = serde_json::to_string(&self).unwrap();
        get_policy_signature(&policy, signing_key)
    }

    /// The x-amz-* fields shared by the policy conditions and the form fields
    fn get_default_fields(signing_context: &SigningContext) -> [(&'static str, String); 3] {
        [
            ("x-amz-credential", signing_context.get_credential()),
            ("x-amz-algorithm", AWS4_HMAC_SHA256.to_string()),
            ("x-amz-date", signing_context.get_x_amz_date()),
        ]
    }

    fn get_default_conditions(signing_context: &SigningContext) -> Vec<Value> {
        Policy::get_default_fields(signing_context)
            .into_iter()
            .map(|(name, value)| json!({ name: value }))
            .collect()
    }

    /// Create a policy which expire in X minutes
    ///
    /// # Panics
    ///
    /// Panics if `minutes` is so large that the expiration falls outside the range of `Timestamp`.
    pub fn new_with_expiration_in_minutes(minutes: i64, signing_context: &SigningContext) -> Self {
        let expiration = Timestamp::now()
            .round(Unit::Millisecond)
            .unwrap()
            .checked_add(minutes.minutes())
            .unwrap();

        Self::new_with_exact_expiration(expiration, signing_context)
    }

    /// Create a policy with an exact expiration date
    pub fn new_with_exact_expiration(
        expiration: Timestamp,
        signing_context: &SigningContext,
    ) -> Self {
        Self {
            expiration,
            conditions: Policy::get_default_conditions(signing_context),
            post_fields: BTreeMap::new(),
        }
    }

    /// Specifies the exact bucket the user must upload to
    pub fn bucket(mut self, bucket: &str) -> Self {
        self.conditions.push(json!({"bucket": bucket}));
        self
    }

    /// Specifies the content length range in bytes e.g. 1048576 for a mb
    pub fn content_length_range(mut self, lower: usize, upper: usize) -> Self {
        self.conditions
            .push(json!(["content-length-range", lower, upper]));
        self
    }

    /// Specifies the exact content type the user must upload with
    pub fn content_type(mut self, content_type: &str) -> Self {
        self.conditions.push(json!({"content-type": content_type}));
        self
    }

    /// Specifies the prefix the content type must start with (e.g. "image/")
    pub fn starts_with_content_type(mut self, content_type: &str) -> Self {
        self.conditions
            .push(json!(["starts-with", "$content-type", content_type]));
        self
    }

    /// Specifies the exact key the user must upload with
    pub fn key(mut self, key: &str) -> Self {
        self.conditions.push(json!({"key": key}));
        self.post_fields
            .insert("key".to_string(), format!("{key}${{filename}}"));
        self
    }

    /// Specifies the prefix the key must start with (e.g. "user/user1/")
    pub fn starts_with_key(mut self, key: &str) -> Self {
        self.conditions.push(json!(["starts-with", "$key", key]));
        self.post_fields
            .insert("key".to_string(), format!("{key}${{filename}}"));
        self
    }

    /// Adds a custom condition to the policy
    pub fn condition(mut self, condition: Value) -> Self {
        self.conditions.push(condition);
        self
    }
}
