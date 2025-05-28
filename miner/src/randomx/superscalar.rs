// ============================================================================
// SuperscalarHash - Dataset expansion using SuperscalarHash function
// 
// Implements the SuperscalarHash function for expanding the 2MB cache into
// a 2.08 GB dataset as specified in the RandomX documentation
// ============================================================================

use crate::randomx::cache::RandomXCache;
use crate::randomx::aes_generator::AesGenerator;
use crate::randomx::{RANDOMX_DATASET_ITEM_SIZE, RANDOMX_DATASET_ITEM_COUNT};

/// Superscalar hash instruction types
#[derive(Clone, Copy, Debug)]
enum SuperscalarInstr {
    Add,
    Sub,
    Mul,
    Ror,
    And,
    Xor,
}

/// Superscalar hash program
struct SuperscalarProgram {
    instructions: Vec<(SuperscalarInstr, usize, usize, u64)>, // (instr, dst, src, imm)
}

/// SuperscalarHash implementation for dataset generation
pub struct SuperscalarHash {
    program: SuperscalarProgram,
}

impl SuperscalarHash {
    /// Create new SuperscalarHash instance
    pub fn new(seed: &[u8]) -> Self {
        let mut generator = AesGenerator::new(seed);
        let program = Self::generate_program(&mut generator);
        
        SuperscalarHash { program }
    }

    /// Generate superscalar program from seed
    fn generate_program(generator: &mut AesGenerator) -> SuperscalarProgram {
        let mut instructions = Vec::new();
        
        // Generate random superscalar program
        for _ in 0..128 {
            let instr_type = match generator.generate_u32() % 6 {
                0 => SuperscalarInstr::Add,
                1 => SuperscalarInstr::Sub,
                2 => SuperscalarInstr::Mul,
                3 => SuperscalarInstr::Ror,
                4 => SuperscalarInstr::And,
                _ => SuperscalarInstr::Xor,
            };
            
            let dst = (generator.generate_u32() % 8) as usize;
            let src = (generator.generate_u32() % 8) as usize;
            let imm = generator.generate_u64();
            
            instructions.push((instr_type, dst, src, imm));
        }
        
        SuperscalarProgram { instructions }
    }

    /// Execute superscalar hash on input data
    pub fn hash(&self, input: &[u8]) -> [u8; 64] {
        let mut registers = [0u64; 8];
        
        // Initialize registers with input data
        for (i, chunk) in input.chunks(8).enumerate() {
            if i >= 8 { break; }
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            registers[i] = u64::from_le_bytes(bytes);
        }
        
        // Execute superscalar program
        for &(instr, dst, src, imm) in &self.program.instructions {
            let src_val = if src < 8 { registers[src] } else { imm };
            
            registers[dst] = match instr {
                SuperscalarInstr::Add => registers[dst].wrapping_add(src_val),
                SuperscalarInstr::Sub => registers[dst].wrapping_sub(src_val),
                SuperscalarInstr::Mul => registers[dst].wrapping_mul(src_val),
                SuperscalarInstr::Ror => registers[dst].rotate_right((src_val & 63) as u32),
                SuperscalarInstr::And => registers[dst] & src_val,
                SuperscalarInstr::Xor => registers[dst] ^ src_val,
            };
        }
        
        // Convert registers to output
        let mut output = [0u8; 64];
        for (i, &reg) in registers.iter().enumerate() {
            let offset = i * 8;
            output[offset..offset + 8].copy_from_slice(&reg.to_le_bytes());
        }
        
        output
    }

    /// Generate dataset item using SuperscalarHash
    pub fn generate_dataset_item(cache: &RandomXCache, item_number: usize) -> [u8; 64] {
        let mut input = vec![0u8; 72];
        
        // Item number as input
        input[..8].copy_from_slice(&(item_number as u64).to_le_bytes());
        
        // Add cache data dependency
        let cache_offset = (item_number * 64) % cache.memory.len();
        let cache_data = cache.get_data(cache_offset, 64);
        input[8..8+cache_data.len()].copy_from_slice(cache_data);
        
        // Create SuperscalarHash from cache-derived seed
        let seed_offset = (item_number * 32) % cache.memory.len();
        let seed = cache.get_data(seed_offset, 32);
        let superscalar = SuperscalarHash::new(seed);
        
        superscalar.hash(&input)
    }
}
