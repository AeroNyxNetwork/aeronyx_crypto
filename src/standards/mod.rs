//! Cryptographic standards compliance module
//! Implements NIST, FIPS, and other standard requirements

pub mod fips;
pub mod nist;
pub mod solana;

use crate::errors::CryptoError;

/// Trait for standard compliance validation
pub trait StandardCompliance {
    /// Validate key material against standard requirements
    fn validate_key(&self, key: &[u8], algorithm: &str) -> Result<(), CryptoError>;
    
    /// Validate algorithm parameters
    fn validate_parameters(&self, params: &dyn std::any::Any) -> Result<(), CryptoError>;
    
    /// Get approved algorithms list
    fn approved_algorithms(&self) -> Vec<&'static str>;
}

/// Compliance checker aggregating multiple standards
pub struct ComplianceChecker {
    standards: Vec<Box<dyn StandardCompliance>>,
}

impl ComplianceChecker {
    pub fn new() -> Self {
        Self {
            standards: vec![
                Box::new(fips::Fips140_3),
                Box::new(nist::NistSP800_57),
                Box::new(solana::SolanaStandard),
            ],
        }
    }
    
    /// Check key compliance across all standards
    pub fn check_key(&self, key: &[u8], algorithm: &str) -> Result<(), CryptoError> {
        for standard in &self.standards {
            standard.validate_key(key, algorithm)?;
        }
        Ok(())
    }
}
