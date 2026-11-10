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
