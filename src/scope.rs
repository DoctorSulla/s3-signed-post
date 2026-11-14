//! Credential scope components: AWS region and service.

use serde::Serialize;

/// Defines an enum with a string representation for each variant, used both for
/// serialization and for building signing keys / credential scopes.
/// A `Custom(String)` variant is always included for values not covered by the
/// predefined variants (e.g. new regions or S3-compatible providers).
macro_rules! string_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                #[doc = concat!("`", $value, "`")]
                $variant,
            )+
            /// Any value not covered by the predefined variants.
            Custom(String),
        }

        impl $name {
            /// Returns the string form used in credential scopes and signing keys
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $value,)+
                    Self::Custom(value) => value,
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

string_enum! {
    /// AWS region used in the credential scope.
    Region {
        UsEast1 => "us-east-1",
        UsEast2 => "us-east-2",
        UsWest1 => "us-west-1",
        UsWest2 => "us-west-2",
        AfSouth1 => "af-south-1",
        ApEast1 => "ap-east-1",
        ApSouth1 => "ap-south-1",
        ApSouth2 => "ap-south-2",
        ApSoutheast1 => "ap-southeast-1",
        ApSoutheast2 => "ap-southeast-2",
        ApSoutheast3 => "ap-southeast-3",
        ApSoutheast4 => "ap-southeast-4",
        ApNortheast1 => "ap-northeast-1",
        ApNortheast2 => "ap-northeast-2",
        ApNortheast3 => "ap-northeast-3",
        CaCentral1 => "ca-central-1",
        CaWest1 => "ca-west-1",
        EuCentral1 => "eu-central-1",
        EuCentral2 => "eu-central-2",
        EuWest1 => "eu-west-1",
        EuWest2 => "eu-west-2",
        EuWest3 => "eu-west-3",
        EuSouth1 => "eu-south-1",
        EuSouth2 => "eu-south-2",
        EuNorth1 => "eu-north-1",
        IlCentral1 => "il-central-1",
        MeSouth1 => "me-south-1",
        MeCentral1 => "me-central-1",
        SaEast1 => "sa-east-1",
        UsGovEast1 => "us-gov-east-1",
        UsGovWest1 => "us-gov-west-1",
    }
}

string_enum! {
    /// AWS service used in the credential scope.
    Service {
        S3 => "s3",
    }
}
