macro_rules! define_id {
    ($name:ident, $inner:ty) => {
        #[derive(
            Debug,
            Default,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name($inner);

        impl $name {
            pub const fn new(value: $inner) -> Self {
                Self(value)
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
            type Err = <$inner as std::str::FromStr>::Err;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                value.parse().map(Self)
            }
        }

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
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
define_id!(TokenId, i32);
define_id!(TaskId, i32);
define_id!(TaskEventId, i32);
define_id!(ImportResultId, i32);
define_id!(EventSubscriptionId, i32);
define_id!(EventDeliveryId, i64);
define_id!(RemoteCallResultId, i32);
define_id!(HistoryId, i64);
define_id!(PermissionId, i32);
