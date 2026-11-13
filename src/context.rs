//! The signing context holding credentials and credential scope information.

use serde::Serialize;
use serde::ser::SerializeStruct;

use crate::scope::{Region, Service};
use crate::signing::AWS4_REQUEST;
use jiff::Timestamp;

/// Signing Context is used as a wrapper to hold the various pieces of information used for building
/// requests.
#[derive(Debug, Clone)]
pub struct SigningContext {
    pub(crate) region: Region,
    pub(crate) date: Timestamp,
    pub(crate) service: Service,
    pub(crate) access_key: String,
    pub(crate) secret_access_key: String,
}

impl Serialize for SigningContext {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SigningContext", 5)?;
        state.serialize_field("region", &self.region)?;
        state.serialize_field("date", &self.date)?;
        state.serialize_field("service", &self.service)?;
        state.serialize_field("access_key", &self.access_key)?;
        state.serialize_field("secret_access_key", "**MASKED**")?;
        state.end()
    }
}

impl SigningContext {
    /// Creates a new signing context
    pub fn new(
        region: Region,
        date: impl Into<Timestamp>,
        service: Service,
        access_key: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        Self {
            region,
            date: date.into(),
            service,
            access_key: access_key.into(),
            secret_access_key: secret_access_key.into(),
        }
    }

    pub fn get_credential(&self) -> String {
        format!("{}/{}/{}/{}/{}", self.access_key, self.date.strftime("%Y%m%d"), self.region, self.service, AWS4_REQUEST)
    }

    /// Formats the date in the ISO 8601 basic format required by SigV4 (e.g. 20151229T000000Z)
    pub fn get_x_amz_date(&self) -> String {
        self.date.strftime("%Y%m%dT%H%M%SZ").to_string()
    }
}
