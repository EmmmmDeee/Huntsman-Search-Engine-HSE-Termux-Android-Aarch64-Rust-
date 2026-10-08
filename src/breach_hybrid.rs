//! Free-then-keyed breach order. This module does not fetch and does not store a password.
//!
//! A count from Pwned Passwords is a lead. It is not `ClaimState::Verified`.

/// One leg of the hybrid. Order is the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreachLeg {
    /// `hibp password` / `password-range`. Keyless. Prefix only leaves the process.
    PwnedPasswords,
    /// `hibp breaches`. Keyless corpus catalog, not account membership.
    HibpCatalog,
    /// `hibp account`. Operator key required.
    HibpAccount,
    /// `recon stolen-tax`. Operator key required. Cleartext is not a field.
    StolenTax,
}

/// Free legs always. Keyed legs only when an operator key is present.
#[must_use]
pub fn exposure_order(has_operator_key: bool) -> Vec<BreachLeg> {
    let mut order = vec![BreachLeg::PwnedPasswords, BreachLeg::HibpCatalog];
    if has_operator_key {
        order.push(BreachLeg::HibpAccount);
        order.push(BreachLeg::StolenTax);
    }
    order
}

/// A password count is a lead. Do not admit it as verified.
#[must_use]
pub const fn count_is_lead(count: u64) -> bool {
    count > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_order_has_no_keyed_leg() {
        assert_eq!(
            exposure_order(false),
            vec![BreachLeg::PwnedPasswords, BreachLeg::HibpCatalog]
        );
    }

    #[test]
    fn keyed_order_appends_and_does_not_invert() {
        let order = exposure_order(true);
        assert_eq!(order[0], BreachLeg::PwnedPasswords);
        assert_eq!(order[1], BreachLeg::HibpCatalog);
        assert_eq!(
            &order[2..],
            &[BreachLeg::HibpAccount, BreachLeg::StolenTax]
        );
    }

    #[test]
    fn zero_count_is_not_a_lead() {
        assert!(!count_is_lead(0));
        assert!(count_is_lead(1));
    }
}
