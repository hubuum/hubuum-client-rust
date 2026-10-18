/// Identity scope used when a request omits an explicit scope.
pub const LOCAL_IDENTITY_SCOPE: &str = "local";

/// Provider kind for identities managed directly by Hubuum.
pub const LOCAL_PROVIDER_KIND: &str = "local";

/// Provider kind currently used by directory-backed identity scopes.
pub const LDAP_PROVIDER_KIND: &str = "ldap";

pub(crate) fn default_local_identity_value() -> String {
    LOCAL_IDENTITY_SCOPE.to_string()
}

/// Principal kind captured by the server's event-time identity snapshot.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    ServiceAccount,
    #[serde(other)]
    Unknown,
}
