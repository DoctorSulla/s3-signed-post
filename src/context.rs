//! The signing context holding credentials and credential scope information.

use serde::Serialize;

use crate::scope::{Region, Service};
use crate::signing::AWS4_REQUEST;
use jiff::{Timestamp, Unit};

/// Signing Context is used as a wrapper to hold the various pieces of information used for building
/// requests. Date should be in YYYYMMDD format
#[derive(Serialize, Debug, Clone)]
pub struct SigningContext {
    pub(crate) region: Region,
    pub(crate) date: Timestamp,
    pub(crate) service: Service,
    pub(crate) access_key: String,
    pub(crate) secret_access_key: String,
}

impl SigningContext {
    /// Creates a new signing context. Date should be in YYYYMMDD format
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
        format!("{}/{}/{}/{}/{}",self.access_key,self.date.strftime("%Y%m%d").to_string(),self.region,self.service,AWS4_REQUEST)
    }
    pub fn get_x_amz_date(&self) -> String {
        //format!("{}T000000Z",self.date)
        self.date.round(Unit::Second).expect("Failed to generate x_amz_date").to_string()
  }

}
