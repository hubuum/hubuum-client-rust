#![cfg(feature = "integration-tests")]

mod container_integration {
    mod library;
    mod probes;
    pub(crate) mod support;
}

pub(crate) use container_integration::support;
