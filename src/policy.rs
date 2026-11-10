//! POST policy construction.

use jiff::{Timestamp, ToSpan, Unit};
use serde::Serialize;
use serde_json::{Value, json};

use crate::context::SigningContext;
use crate::signing::{SignedPolicy, get_policy_signature};

#[derive(Serialize, Debug, Clone)]
pub struct Policy {
    expiration: Timestamp,
    conditions: Vec<Value>,
}

impl Policy {
    pub fn sign(&self, signing_key: &[u8]) -> SignedPolicy {
        let policy: String = serde_json::to_string(&self).unwrap();
        get_policy_signature(&policy, signing_key)
    }

        fn get_default_conditions(signing_context: &SigningContext) -> Vec<Value> {
        let alg = json!({"x-amz-algorithm":"AWS4-HMAC-SHA256"});
        let credential = json!({"x-amz-credential": signing_context.get_credential()});
        let date = json!({"x-amz-date": signing_context.get_x_amz_date()});

        vec![credential, alg, date]
    }

    /// Create a policy which expire in X minutes
    pub fn new_with_expiration_in_minutes(
        minutes: i64,
        signing_context: &SigningContext,
    ) -> Self {
        let expiration = Timestamp::now()
            .round(Unit::Millisecond)
            .unwrap()
            .checked_add(minutes.minutes())
            .unwrap();

        let conditions = Policy::get_default_conditions(&signing_context);

        Self {
            expiration,
            conditions,
        }
    }

    /// Create a policy with an exact expiration date
    pub fn new_with_exact_expiration(
        expiration: Timestamp,
        signing_context: &SigningContext,
    ) -> Self {
        let conditions = Policy::get_default_conditions(&signing_context);

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
