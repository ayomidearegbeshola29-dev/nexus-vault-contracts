use soroban_sdk::{contracttype, Env};

#[contracttype]
pub struct SlashingConfig {
    pub penalty_percentage: u32,
}

pub fn calculate_slashing_penalty(_env: &Env, amount: i128, penalty: u32) -> i128 {
    if penalty > 100 {
        return amount; // or throw error
    }
    (amount * penalty as i128) / 100
}
