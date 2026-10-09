use soroban_sdk::{contracttype, Env};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefundState {
    Active,
    GracePeriod,
    Cooldown,
    Expired,
}

pub fn determine_refund_state(
    _env: &Env,
    current_time: u64,
    start_time: u64,
    grace_period: u64,
    cooldown: u64,
) -> RefundState {
    if current_time < start_time {
        RefundState::Active
    } else if current_time < start_time + grace_period {
        RefundState::GracePeriod
    } else if current_time < start_time + grace_period + cooldown {
        RefundState::Cooldown
    } else {
        RefundState::Expired
    }
}
