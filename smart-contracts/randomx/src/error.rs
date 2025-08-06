use std::fmt;

#[derive(Debug)]
pub enum RandomXError {
    /// Memory allocation failed
    MemoryAlloc(String),
    
    /// Cache initialization failed
    CacheInit(String),
    
    /// Dataset initialization failed
    DatasetInit(String),
    
    /// VM initialization failed
    VmInit(String),
    
    /// No cache available when required
    NoCache,
    
    /// No dataset available when required
    NoDataset,
    
    /// JIT compilation failed
    JitError(String),
    
    /// Invalid configuration
    Config(String),
    
    /// Hardware feature not available
    HardwareNotSupported(String),
}

impl fmt::Display for RandomXError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RandomXError::MemoryAlloc(msg) => write!(f, "Memory allocation failed: {}", msg),
            RandomXError::CacheInit(msg) => write!(f, "Cache initialization failed: {}", msg),
            RandomXError::DatasetInit(msg) => write!(f, "Dataset initialization failed: {}", msg),
            RandomXError::VmInit(msg) => write!(f, "VM initialization failed: {}", msg),
            RandomXError::NoCache => write!(f, "Cache required but not available"),
            RandomXError::NoDataset => write!(f, "Dataset required but not available"),
            RandomXError::JitError(msg) => write!(f, "JIT compilation failed: {}", msg),
            RandomXError::Config(msg) => write!(f, "Invalid configuration: {}", msg),
            RandomXError::HardwareNotSupported(msg) => write!(f, "Hardware feature not supported: {}", msg),
        }
    }
}

impl std::error::Error for RandomXError {}
