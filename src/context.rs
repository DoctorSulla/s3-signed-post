//! The signing context holding credentials and credential scope information.

use serde::Serialize;

use crate::scope::{Region, Service};
use crate::signing::AWS4_REQUEST;

/// Signing Context is used as a wrapper to hold the various pieces of information used for building
/// requests. Date should be in YYYYMMDD format
#[derive(Serialize, Debug, Clone)]
pub struct SigningContext {
    pub(crate) region: Region,
    pub(crate) date: String,
    pub(crate) service: Service,
    pub(crate) access_key: String,
    pub(crate) secret_access_key: String,
}

impl SigningContext {
    pub fn get_credential(&self) -> String {
        format!("{}/{}/{}/{}/{}",self.access_key,self.date,self.region,self.service,AWS4_REQUEST)
    }
    pub fn get_x_amz_date(&self) -> String {
        format!("{}T000000Z",self.date)
    }
}
