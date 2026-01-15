use crate::inspector::{ConnectionMeta, Inspector};
use std::path::Path;

#[derive(Debug)]
pub struct EbpfInspector {
    pub interface: Option<String>,
}

#[derive(Debug)]
pub enum EbpfError {
    Unsupported(String),
}

impl EbpfInspector {
    pub fn try_new(interface: Option<String>) -> Result<Self, EbpfError> {
        if !Self::is_supported() {
            return Err(EbpfError::Unsupported(
                "ebpf not supported on this system".to_string(),
            ));
        }
        Ok(Self { interface })
    }

    pub fn is_supported() -> bool {
        Path::new("/sys/fs/bpf").exists()
    }
}

impl Inspector for EbpfInspector {
    fn inspect(&self) -> ConnectionMeta {
        ConnectionMeta::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebpf_support_check_returns_bool() {
        let _ = EbpfInspector::is_supported();
    }
}
