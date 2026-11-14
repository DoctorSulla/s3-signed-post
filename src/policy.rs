//! POST policy construction.

use jiff::{Timestamp, ToSpan, Unit};
use serde::Serialize;
use serde::ser::SerializeStruct;
use serde_json::{Value, json};
use std::collections::BTreeMap;

use crate::context::SigningContext;
use crate::derive_signing_key;
use crate::signing::{AWS4_HMAC_SHA256, SignedPolicy, get_policy_signature};

const AES_256: &str = "AES256";

/// How a form field must match a value in the policy
#[derive(Debug, Clone, PartialEq, Eq)]
enum Match {
    /// The field must equal the value exactly
    Exact(String),
    /// The field must start with the given prefix
    StartsWith(String),
}

impl Match {
    fn to_condition(&self, field: &str) -> Value {
        match self {
            Match::Exact(value) => json!({ field: value }),
            Match::StartsWith(prefix) => json!(["starts-with", format!("${field}"), prefix]),
        }
    }
}

/// A browser-based POST upload policy.
///
/// The well-known conditions (bucket, key, content type, content length range) are stored
/// once each, so calling a setter again replaces the previous value rather than adding a
/// conflicting condition. Anything else can be added with [`Policy::condition`].
#[derive(Debug, Clone)]
pub struct Policy {
    expiration: Timestamp,
    defaults: Vec<(&'static str, String)>,
    bucket: Option<String>,
    key: Option<Match>,
    content_type: Option<Match>,
    content_length_range: Option<(usize, usize)>,
    custom: Vec<Value>,
}

impl Serialize for Policy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Policy", 2)?;
        state.serialize_field("expiration", &self.expiration)?;
        state.serialize_field("conditions", &self.conditions())?;
        state.end()
    }
}

impl Policy {
    /// Returns the form fields to send with the upload, including the signed policy
    pub fn get_post_fields(&self, signing_context: &SigningContext) -> BTreeMap<String, String> {
        let mut post_fields: BTreeMap<String, String> = self
            .defaults
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone()))
            .collect();

        match &self.key {
            Some(Match::Exact(key)) => {
                post_fields.insert("key".to_string(), key.clone());
            }
            Some(Match::StartsWith(prefix)) => {
                post_fields.insert("key".to_string(), format!("{prefix}${{filename}}"));
            }
            None => {}
        }

        // A prefix match leaves the actual Content-Type for the client to supply
        if let Some(Match::Exact(content_type)) = &self.content_type {
            post_fields.insert("Content-Type".to_string(), content_type.clone());
        }

        let signed_policy = self.sign(&derive_signing_key(signing_context));
        post_fields.insert("policy".to_string(), signed_policy.base64_encoding);
        post_fields.insert("x-amz-signature".to_string(), signed_policy.signature);

        post_fields
    }

    /// Base64-encodes the policy JSON and signs it with the given signing key
    pub fn sign(&self, signing_key: &[u8]) -> SignedPolicy {
        let policy: String = serde_json::to_string(&self).unwrap();
        get_policy_signature(&policy, signing_key)
    }

    /// Builds the policy's conditions array in a fixed order: the x-amz-* defaults,
    /// bucket, key, content type, content length range, then any custom conditions
    fn conditions(&self) -> Vec<Value> {
        let mut conditions: Vec<Value> = self
            .defaults
            .iter()
            .map(|(name, value)| json!({ *name: value }))
            .collect();

        conditions.extend(
            self.bucket
                .as_ref()
                .map(|bucket| json!({ "bucket": bucket })),
        );
        conditions.extend(self.key.as_ref().map(|m| m.to_condition("key")));
        conditions.extend(
            self.content_type
                .as_ref()
                .map(|m| m.to_condition("content-type")),
        );
        conditions.extend(
            self.content_length_range
                .map(|(lower, upper)| json!(["content-length-range", lower, upper])),
        );
        conditions.extend(self.custom.iter().cloned());

        conditions
    }

    /// The x-amz-* fields shared by the policy conditions and the form fields
    fn get_default_fields(signing_context: &SigningContext) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("x-amz-credential", signing_context.get_credential()),
            ("x-amz-algorithm", AWS4_HMAC_SHA256.to_string()),
            ("x-amz-date", signing_context.get_x_amz_date()),
            ("x-amz-server-side-encryption", AES_256.to_string()),
        ];
        if let Some(token) = &signing_context.session_token {
            fields.push(("x-amz-security-token", token.clone()));
        }
        fields
    }

    /// Creates a policy that expires in `minutes` minutes.
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
            defaults: Policy::get_default_fields(signing_context),
            bucket: None,
            key: None,
            content_type: None,
            content_length_range: None,
            custom: Vec::new(),
        }
    }

    /// Specifies the exact bucket the user must upload to. Replaces any previous bucket.
    pub fn bucket(mut self, bucket: &str) -> Self {
        self.bucket = Some(bucket.to_string());
        self
    }

    /// Specifies the content length range in bytes (e.g. `1_048_576` for 1 MiB). Replaces any
    /// previous range.
    pub fn content_length_range(mut self, lower: usize, upper: usize) -> Self {
        self.content_length_range = Some((lower, upper));
        self
    }

    /// Specifies the exact content type the user must upload with. The matching
    /// `Content-Type` form field is set as well. Replaces any previous content type condition.
    pub fn content_type(mut self, content_type: &str) -> Self {
        self.content_type = Some(Match::Exact(content_type.to_string()));
        self
    }

    /// Specifies the prefix the content type must start with (e.g. "image/"). The client
    /// must send its own `Content-Type` form field matching this prefix. Replaces any
    /// previous content type condition.
    pub fn starts_with_content_type(mut self, content_type: &str) -> Self {
        self.content_type = Some(Match::StartsWith(content_type.to_string()));
        self
    }

    /// Specifies the exact key the user must upload with. Replaces any previous key condition.
    pub fn key(mut self, key: &str) -> Self {
        self.key = Some(Match::Exact(key.to_string()));
        self
    }

    /// Specifies the prefix the key must start with (e.g. "user/user1/"). The `key` form
    /// field is set to `{prefix}${filename}`. Replaces any previous key condition.
    pub fn starts_with_key(mut self, key: &str) -> Self {
        self.key = Some(Match::StartsWith(key.to_string()));
        self
    }

    /// Adds a custom condition to the policy.
    ///
    /// Use this for conditions without a dedicated method (e.g. `acl`, `x-amz-meta-*`).
    /// Conditions on bucket, key, content type or content length range should use their
    /// dedicated methods; adding them here as well can produce a policy no upload satisfies.
    pub fn condition(mut self, condition: Value) -> Self {
        self.custom.push(condition);
        self
    }

    /// A convenience method for getting the upload url which can then be provided alongside the
    /// form fields. Will return None if no bucket has been set
    pub fn get_s3_upload_url(&self, signing_context: &SigningContext) -> Option<String> {
        let region = signing_context.region.to_string();
        let bucket_name = self.bucket.as_ref()?;

        Some(format!("https://{bucket_name}.s3.{region}.amazonaws.com/"))
    }
}
