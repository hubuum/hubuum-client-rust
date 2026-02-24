//! A hubuum API client library.
//!
//! async:
//! ```no_run
//! use hubuum_client::{AsyncClient, BaseUrl};
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let base_url = BaseUrl::from_str("https://api.example.com")?;
//!     let client = AsyncClient::new(base_url);
//!     // ... rest of the code
//!     Ok(())
//! }
//! ```
//!
//! sync:
//! ```no_run
//! use hubuum_client::{SyncClient, BaseUrl};
//! use std::str::FromStr;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!    let base_url = BaseUrl::from_str("https://api.example.com")?;
//!    let client = SyncClient::new(base_url);
//!    // ... rest of the code
//!    Ok(())
//! }
//! ```
pub mod client;
pub mod errors;
pub mod resources;
pub mod types;

mod endpoints;

// Re-export commonly used items
pub use client::{AsyncClient, Authenticated, IntoResourceFilter, SyncClient, Unauthenticated};
pub use errors::ApiError;
pub use resources::*;
pub use types::{
    BaseUrl, ClassParams, CountsResponse, Credentials, DbStateResponse, Token, UserParams,
};
