use soroban_sdk::{contracttype, Address};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssetSupport {
    Native,
    Token(Address),
    Dual(Address, Address), // Native XLM and SEP-41
}

pub fn is_dual_asset_supported(asset: &AssetSupport) -> bool {
    matches!(asset, AssetSupport::Dual(_, _))
}
