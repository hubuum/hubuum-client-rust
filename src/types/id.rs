macro_rules! define_id {
    ($name:ident, $inner:ty) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name($inner);

        impl $name {
            pub const fn new(value: $inner) -> Result<Self, crate::ApiError> {
                if value > 0 {
                    Ok(Self(value))
                } else {
                    Err(crate::ApiError::InvalidResourceId {
                        kind: stringify!($name),
                    })
                }
            }

            pub const fn get(self) -> $inner {
                self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = crate::ApiError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(
                    value
                        .parse()
                        .map_err(|_| crate::ApiError::InvalidResourceId {
                            kind: stringify!($name),
                        })?,
                )
            }
        }

        impl TryFrom<$inner> for $name {
            type Error = crate::ApiError;
            fn try_from(value: $inner) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(<$inner as serde::Deserialize>::deserialize(deserializer)?)
                    .map_err(serde::de::Error::custom)
            }
        }

        impl From<&$name> for $name {
            fn from(value: &$name) -> Self {
                *value
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl PartialEq<$inner> for $name {
            fn eq(&self, other: &$inner) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<$name> for $inner {
            fn eq(&self, other: &$name) -> bool {
                *self == other.0
            }
        }
    };
}

define_id!(PrincipalId, i32);
define_id!(CredentialApprovalId, i32);
define_id!(TokenId, i32);
define_id!(TaskId, i32);
define_id!(TaskEventId, i32);
define_id!(ImportResultId, i32);
define_id!(EventSubscriptionId, i32);
define_id!(EventDeliveryId, i64);
define_id!(RemoteCallResultId, i32);
define_id!(HistoryId, i64);
define_id!(PermissionId, i32);
define_id!(ComputedFieldDefinitionId, i32);
define_id!(RestoreId, i64);

pub(crate) use define_id;

impl From<crate::UserId> for PrincipalId {
    fn from(value: crate::UserId) -> Self {
        Self(value.get())
    }
}
impl From<crate::ServiceAccountId> for PrincipalId {
    fn from(value: crate::ServiceAccountId) -> Self {
        Self(value.get())
    }
}
