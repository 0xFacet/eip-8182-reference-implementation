mod tests;
mod oracle_tests;
mod benchmarks;

use std::hash::keccakf1600;
use std::runtime::is_unconstrained;

global BLOCK_SIZE_IN_BYTES: u32 = 136; //(1600 - BITS * 2) / WORD_SIZE;
global WORD_SIZE: u32 = 8; // Limbs are made up of u64s so 8 bytes each.
global LIMBS_PER_BLOCK: u32 = BLOCK_SIZE_IN_BYTES / WORD_SIZE;
global NUM_KECCAK_LANES: u32 = 25;

#[no_predicates]
pub fn keccak256<let N: u32>(input: [u8; N], message_size: u32) -> [u8; 32] {
    assert(N >= message_size);

    // Copy input to block bytes. For that we'll need at least input bytes (N)
    // but we want it to be padded to a multiple of BLOCK_SIZE_IN_BYTES.
    let mut block_bytes = [0; ((N / BLOCK_SIZE_IN_BYTES) + 1) * BLOCK_SIZE_IN_BYTES];
    if is_unconstrained() {
        for i in 0..message_size {
            block_bytes[i] = input[i];
        }
    } else {
        for i in 0..N {
            if i < message_size {
                block_bytes[i] = input[i];
            }
        }
    }

    //1. format_input_lanes and apply padding
    let max_blocks = (N + BLOCK_SIZE_IN_BYTES) / BLOCK_SIZE_IN_BYTES;
    let real_max_blocks = (message_size + BLOCK_SIZE_IN_BYTES) / BLOCK_SIZE_IN_BYTES;

    // Apply Keccak padding (0x01 after message, 0x80 at block end)
    apply_keccak_padding(&mut block_bytes, message_size, real_max_blocks);

    // populate a vector of 64-bit limbs from our byte array
    let mut sliced_buffer =
        [0; (((N / BLOCK_SIZE_IN_BYTES) + 1) * BLOCK_SIZE_IN_BYTES) / WORD_SIZE];
    for i in 0..sliced_buffer.len() {
        let limb_start = WORD_SIZE * i;

        let mut sliced = 0;
        let mut v = 1;
        for k in 0..WORD_SIZE {
            sliced += v * (block_bytes[limb_start + k] as Field);
            v *= 256;
        }

        sliced_buffer[i] = sliced as u64;
    }

    //2. sponge_absorb
    let mut state: [u64; NUM_KECCAK_LANES] = [0; NUM_KECCAK_LANES];
    // `real_max_blocks` is guaranteed to at least be `1`
    // We peel out the first block as to avoid a conditional inside of the loop.
    // Otherwise, a dynamic predicate can cause a blowup in a constrained runtime.
    for j in 0..LIMBS_PER_BLOCK {
        state[j] = sliced_buffer[j];
    }
    state = keccakf1600(state);

    let state = if is_unconstrained() {
        // When in an unconstrained runtime we can take advantage of runtime loop bounds,
        // thus allowing us to simplify the loop body.
        for i in 1..real_max_blocks {
            for j in 0..LIMBS_PER_BLOCK {
                state[j] = state[j] ^ sliced_buffer[i * LIMBS_PER_BLOCK + j];
            }
            state = keccakf1600(state);
        }

        state
    } else {
        // We store the intermediate states in an array to avoid having a dynamic predicate
        // inside the loop, which can cause a blowup in a constrained runtime.
        let mut intermediate_states = [state; (N + BLOCK_SIZE_IN_BYTES) / BLOCK_SIZE_IN_BYTES + 1];
        for i in 1..max_blocks {
            let mut previous_state = intermediate_states[i - 1];
            for j in 0..LIMBS_PER_BLOCK {
                previous_state[j] = previous_state[j] ^ sliced_buffer[i * LIMBS_PER_BLOCK + j];
            }
            intermediate_states[i] = keccakf1600(previous_state);
        }

        // We can then take the state as of `real_max_blocks`, ignoring later permutations.
        intermediate_states[real_max_blocks - 1]
    };

    //3. sponge_squeeze
    let mut result = [0; 32];
    for i in 0..4 {
        let lane = state[i] as Field;
        let lane_le: [u8; 8] = lane.to_le_bytes();
        for j in 0..8 {
            result[8 * i + j] = lane_le[j];
        }
    }
    result
}

// Apply Keccak padding to the block_bytes array
// Append 0x01 after message, then 0x80 at end of block
// If both padding bytes collide at the same byte, combine them as 0x81
pub(crate) fn apply_keccak_padding<let BLOCK_BYTES: u32>(
    block_bytes: &mut [u8; BLOCK_BYTES],
    message_size: u32,
    real_max_blocks: u32,
) {
    let real_blocks_bytes = real_max_blocks * BLOCK_SIZE_IN_BYTES;

    block_bytes[message_size] = 0x01;

    if message_size == real_blocks_bytes - 1 {
        // Combine both padding bits: 0x01 | 0x80 = 0x81
        block_bytes[message_size] = 0x81;
    } else {
        block_bytes[real_blocks_bytes - 1] = 0x80;
    }
}
