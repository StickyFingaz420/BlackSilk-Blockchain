// ============================================================================
// RandomX Instruction - VM instruction definitions and execution
// 
// Implements all RandomX VM instructions including integer arithmetic,
// floating-point operations, and SIMD instructions
// ============================================================================

/// RandomX Instruction opcodes
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum Opcode {
    // Integer instructions
    IaddRs = 0,
    IaddM = 1,
    IsubR = 2,
    IsubM = 3,
    ImulR = 4,
    ImulM = 5,
    ImulhR = 6,
    ImulhM = 7,
    IsmulhR = 8,
    IsmulhM = 9,
    ImulRcp = 10,
    InegR = 11,
    IxorR = 12,
    IxorM = 13,
    IrorR = 14,
    IrolR = 15,
    
    // Floating-point instructions
    FaddR = 16,
    FaddM = 17,
    FsubR = 18,
    FsubM = 19,
    FscalR = 20,
    FmulR = 21,
    FdivR = 22,
    FsqrtR = 23,
    
    // Conditional instructions
    CbranchZ = 24,
    CbranchNz = 25,
    
    // Store instructions
    IstoreL1 = 26,
    IstoreL2 = 27,
    IstoreL3 = 28,
    
    // SIMD instructions (CPU-only)
    SimdAddPd = 29,
    SimdSubPd = 30,
    SimdMulPd = 31,
    SimdDivPd = 32,
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        match value & 0x1f {
            0 => Opcode::IaddRs,
            1 => Opcode::IaddM,
            2 => Opcode::IsubR,
            3 => Opcode::IsubM,
            4 => Opcode::ImulR,
            5 => Opcode::ImulM,
            6 => Opcode::ImulhR,
            7 => Opcode::ImulhM,
            8 => Opcode::IsmulhR,
            9 => Opcode::IsmulhM,
            10 => Opcode::ImulRcp,
            11 => Opcode::InegR,
            12 => Opcode::IxorR,
            13 => Opcode::IxorM,
            14 => Opcode::IrorR,
            15 => Opcode::IrolR,
            16 => Opcode::FaddR,
            17 => Opcode::FaddM,
            18 => Opcode::FsubR,
            19 => Opcode::FsubM,
            20 => Opcode::FscalR,
            21 => Opcode::FmulR,
            22 => Opcode::FdivR,
            23 => Opcode::FsqrtR,
            24 => Opcode::CbranchZ,
            25 => Opcode::CbranchNz,
            26 => Opcode::IstoreL1,
            27 => Opcode::IstoreL2,
            28 => Opcode::IstoreL3,
            29 => Opcode::SimdAddPd,
            30 => Opcode::SimdSubPd,
            31 => Opcode::SimdMulPd,
            _ => Opcode::SimdDivPd,
        }
    }
}

/// RandomX VM Instruction
#[derive(Clone, Debug)]
pub struct Instruction {
    pub opcode: Opcode,
    pub dst: u8,
    pub src: u8,
    pub mod_: u8,
    pub imm: u32,
    pub mem_mask: u32,
}

impl Instruction {
    /// Create instruction from raw bytes
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        let opcode = Opcode::from(bytes[0]);
        let dst = bytes[1] & 7;
        let src = bytes[2] & 7;
        let mod_ = bytes[3];
        let imm = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        
        // Calculate memory mask based on instruction type
        let mem_mask = match opcode {
            Opcode::IaddM | Opcode::IsubM | Opcode::ImulM | 
            Opcode::ImulhM | Opcode::IsmulhM | Opcode::IxorM => {
                // L1 cache mask (16KB - 1)
                0x3FFF
            },
            Opcode::FaddM | Opcode::FsubM => {
                // L2 cache mask (256KB - 1)  
                0x3FFFF
            },
            Opcode::IstoreL1 => 0x3FFF,    // L1: 16KB
            Opcode::IstoreL2 => 0x3FFFF,   // L2: 256KB
            Opcode::IstoreL3 => 0x1FFFFF,  // L3: 2MB
            _ => 0xFFFFFFFF,
        };
        
        Instruction {
            opcode,
            dst,
            src,
            mod_,
            imm,
            mem_mask,
        }
    }

    /// Get effective address for memory operations (ultra-optimized)
    #[inline(always)]
    pub fn get_memory_address(&self, src_value: u64, imm_value: u64) -> u32 {
        // PERFORMANCE OPTIMIZATION: Fast address calculation with wrapping add
        let address = src_value.wrapping_add(imm_value);
        (address as u32) & self.mem_mask
    }

    /// Check if instruction modifies register
    pub fn modifies_register(&self) -> bool {
        !matches!(self.opcode, 
            Opcode::IstoreL1 | Opcode::IstoreL2 | Opcode::IstoreL3 |
            Opcode::CbranchZ | Opcode::CbranchNz
        )
    }

    /// Check if instruction is a branch
    pub fn is_branch(&self) -> bool {
        matches!(self.opcode, Opcode::CbranchZ | Opcode::CbranchNz)
    }

    /// Check if instruction is floating-point
    pub fn is_floating_point(&self) -> bool {
        matches!(self.opcode,
            Opcode::FaddR | Opcode::FaddM | Opcode::FsubR | Opcode::FsubM |
            Opcode::FscalR | Opcode::FmulR | Opcode::FdivR | Opcode::FsqrtR
        )
    }

    /// Check if instruction uses memory
    pub fn uses_memory(&self) -> bool {
        matches!(self.opcode,
            Opcode::IaddM | Opcode::IsubM | Opcode::ImulM | Opcode::ImulhM |
            Opcode::IsmulhM | Opcode::IxorM | Opcode::FaddM | Opcode::FsubM |
            Opcode::IstoreL1 | Opcode::IstoreL2 | Opcode::IstoreL3
        )
    }

    /// Get instruction execution weight (for CPU timing enforcement)
    pub fn execution_weight(&self) -> u32 {
        match self.opcode {
            // Fast integer operations
            Opcode::IaddRs | Opcode::IsubR | Opcode::IxorR | 
            Opcode::IrorR | Opcode::IrolR | Opcode::InegR => 1,
            
            // Memory operations
            Opcode::IaddM | Opcode::IsubM | Opcode::IxorM => 2,
            
            // Multiplication operations
            Opcode::ImulR | Opcode::ImulM => 4,
            Opcode::ImulhR | Opcode::ImulhM | Opcode::IsmulhR | Opcode::IsmulhM => 8,
            Opcode::ImulRcp => 12,
            
            // Floating-point operations
            Opcode::FaddR | Opcode::FaddM | Opcode::FsubR | Opcode::FsubM => 3,
            Opcode::FmulR => 4,
            Opcode::FdivR => 16,
            Opcode::FsqrtR => 20,
            Opcode::FscalR => 2,
            
            // SIMD operations (CPU-intensive)
            Opcode::SimdAddPd | Opcode::SimdSubPd => 6,
            Opcode::SimdMulPd => 8,
            Opcode::SimdDivPd => 24,
            
            // Branch and store operations
            Opcode::CbranchZ | Opcode::CbranchNz => 2,
            Opcode::IstoreL1 | Opcode::IstoreL2 | Opcode::IstoreL3 => 2,
        }
    }
}
