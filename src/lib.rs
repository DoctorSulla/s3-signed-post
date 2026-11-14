//! An ergonomic library for building and signing AWS SigV4 POST upload policies for Amazon S3
//! (and S3-compatible object stores).
//!
//! # Quick Start
//!
//! ```
//! use jiff::Timestamp;
//! use s3_signed_post::{Policy, Region, Service, SigningContext};
//!
//! let ctx = SigningContext::new(
//!     Region::UsEast1,
//!     Timestamp::now(),
//!     Service::S3,
//!     "AKIAIOSFODNN7EXAMPLE",
//!     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
//! );
//!
//! let policy = Policy::new_with_expiration_in_minutes(15, &ctx)
//!     .bucket("my-bucket")
//!     .starts_with_key("uploads/user-1/")
//!     .content_length_range(1, 10 * 1024 * 1024)
//!     .starts_with_content_type("image/");
//!
//! let fields = policy.get_post_fields(&ctx);
//! assert!(fields.contains_key("policy"));
//! assert!(fields.contains_key("x-amz-signature"));
//! ```

#![warn(missing_docs)]

mod context;
mod policy;
mod scope;
mod signing;

pub use context::SigningContext;
pub use policy::Policy;
pub use scope::{Region, Service};
pub use signing::{SignedPolicy, derive_signing_key, get_policy_signature};

#[cfg(test)]
mod tests;
