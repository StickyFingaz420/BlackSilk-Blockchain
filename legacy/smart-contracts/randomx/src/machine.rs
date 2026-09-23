//! RandomX virtual machine implementation

use crate::{
    config::*,
    error::RandomXError,
    vm::state::{VmState, Instruction, RegisterFile},
    aes::AesContext,
    blake::{blake2b_512, blake2b_256},
    cache::Cache,
    dataset::Dataset,
};

use std::sync::Arc;

/// The main RandomX virtual machine
pub struct Machine {
    /// Current VM state
    state: VmState,
    /// Cache reference
    cache: Option<Arc<Cache>>,
    /// Dataset reference
    dataset: Option<Arc<Dataset>>,
    /// Configuration flags
    flags: crate::Flags,
    /// Temporary hash buffer
    temp_hash: [u8; 64],
}

impl Machine {
    /// Create a new RandomX machine
    pub fn new(
        flags: crate::Flags,
        cache: Option<&Cache>,
        dataset: Option<&Dataset>,
    ) -> Result<Self, RandomXError> {
        let cache = cache.map(|c| Arc::new(c.clone()));
        let dataset = dataset.map(|d| Arc::new(d.clone()));

        Ok(Self {
            state: VmState::new()?,
            cache,
            dataset,
            flags,
            temp_hash: [0; 64],
        })
    }

    /// Calculate a RandomX hash
    pub fn calculate_hash(&mut self, input: &[u8]) -> Result<[u8; 32], RandomXError> {
        // Step 1: Generate initial hash with Blake2b
        self.temp_hash = blake2b_512(input);
        
        // Step 2: Initialize scratchpad
        self.init_scratchpad()?;
        
        // Step 3: Execute programs
        for program in 0..PROGRAM_COUNT {
            // Generate and execute program
            let program_bytes = self.generate_program(program)?;
            self.execute_program(&program_bytes)?;
            
            if program < PROGRAM_COUNT - 1 {
                // Calculate intermediate hash
                let reg_hash = blake2b_512(self.state.registers.as_bytes());
                self.temp_hash = reg_hash;
            }
        }

        // Step 4: Calculate final hash
        let mut final_result = [0u8; 32];
        blake2b_256_into(self.state.registers.as_bytes(), &mut final_result);
        Ok(final_result)
    }

    /// Initialize the scratchpad for a new hash
    fn init_scratchpad(&mut self) -> Result<(), RandomXError> {
        let mut aes = AesContext::new((&self.temp_hash[..32]).try_into().unwrap())?;
        
        // Fill scratchpad using AES
        for chunk in self.state.scratchpad.l3.chunks_mut(16) {
            aes.encrypt_block(chunk.try_into().unwrap());
        }

        Ok(())
    }

    /// Generate a program from the current state
    fn generate_program(&mut self, program_id: usize) -> Result<Vec<u8>, RandomXError> {
        let mut program = vec![0u8; PROGRAM_SIZE * 8];
        
        // Use dataset/cache to generate program
        if let Some(dataset) = &self.dataset {
            dataset.generate_program(
                &self.temp_hash,
                program_id,
                &mut program,
            )?;
        } else if let Some(cache) = &self.cache {
            cache.generate_program(
                &self.temp_hash,
                program_id,
                &mut program,
            )?;
        } else {
            return Err(RandomXError::Config("Neither dataset nor cache available".into()));
        }

        Ok(program)
    }

    /// Execute a RandomX program
    fn execute_program(&mut self, program: &[u8]) -> Result<(), RandomXError> {
        self.state.reset();

        for _ in 0..PROGRAM_ITERATIONS {
            while self.state.program_counter < PROGRAM_SIZE {
                let instr = self.decode_instruction(
                    &program[self.state.program_counter * 8..(self.state.program_counter + 1) * 8]
                )?;
                
                self.state.execute_instruction(&instr)?;
                self.state.program_counter += 1;
            }

            self.state.program_counter = 0;
        }

        Ok(())
    }

    /// Decode a single instruction from bytes
    fn decode_instruction(&self, bytes: &[u8]) -> Result<Instruction, RandomXError> {
        if bytes.len() != 8 {
            return Err(RandomXError::Config("Invalid instruction bytes".into()));
        }

        let opcode = bytes[0] & 0x1f;
        let dst = (bytes[0] >> 5) | ((bytes[1] & 0x07) << 3);
        let src = (bytes[1] >> 3);
        let imm = i32::from_le_bytes(bytes[4..8].try_into().unwrap());

        Ok(Instruction::new(
            opcode.try_into().map_err(|_| RandomXError::Config("Invalid opcode".into()))?,
            dst,
            src,
            imm,
        ))
    }
}

impl RegisterFile {
    /// Get a byte slice representation of the register file
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const _ as *const u8,
                std::mem::size_of::<RegisterFile>(),
            )
        }
    }
}

// Helper function to calculate Blake2b-256 directly into an output buffer
fn blake2b_256_into(input: &[u8], output: &mut [u8; 32]) {
    use blake2::digest::Update;
    let mut hasher = blake2::Blake2b256::new();
    hasher.update(input);
    output.copy_from_slice(&hasher.finalize());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_basic() {
        let cache = Cache::new(crate::Flags::DEFAULT).unwrap();
        let mut machine = Machine::new(
            crate::Flags::DEFAULT,
            Some(&cache),
            None,
        ).unwrap();

        // Initialize cache
        cache.init(b"test key").unwrap();

        // Calculate hash
        let input = b"test input";
        let hash = machine.calculate_hash(input).unwrap();
        assert_eq!(hash.len(), 32);

        // Same input should produce same hash
        let hash2 = machine.calculate_hash(input).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_instruction_decoding() {
        let cache = Cache::new(crate::Flags::DEFAULT).unwrap();
        let machine = Machine::new(
            crate::Flags::DEFAULT,
            Some(&cache),
            None,
        ).unwrap();

        // Test instruction decoding
        let bytes = [
            0b00100_101,  // opcode 4 (IMUL_R), dst bits 0-2
            0b10110_111,  // dst bits 3-5, src
            0x00, 0x00,   // padding
            0x42, 0x00, 0x00, 0x00, // immediate
        ];

        let instr = machine.decode_instruction(&bytes).unwrap();
        assert_eq!(instr.opcode as u8, 4);
        assert_eq!(instr.dst, 0b10110101);
        assert_eq!(instr.src, 0b10110);
        assert_eq!(instr.imm, 0x42);
    }
}
