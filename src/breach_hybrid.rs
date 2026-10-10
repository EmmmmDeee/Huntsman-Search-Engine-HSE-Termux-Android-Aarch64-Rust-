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

/// Hudson Rock v3 requires a key and can carry credential fields.
/// The only allowed path is the keyed `stolen.tax` cascade, which does not declare those fields.
#[must_use]
pub const fn keyless_hudson_rock() -> Option<BreachLeg> {
    None
}

/// `recon stolen-tax` is a keyed leg. No key means it is not in the order.
#[must_use]
pub fn stolen_tax_allowed(has_operator_key: bool) -> bool {
    exposure_order(has_operator_key).contains(&BreachLeg::StolenTax)
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
        assert_eq!(&order[2..], &[BreachLeg::HibpAccount, BreachLeg::StolenTax]);
    }

    #[test]
    fn zero_count_is_not_a_lead() {
        assert!(!count_is_lead(0));
        assert!(count_is_lead(1));
    }

    #[test]
    fn hudson_rock_is_not_a_free_leg() {
        assert_eq!(keyless_hudson_rock(), None);
        assert!(!exposure_order(false).contains(&BreachLeg::StolenTax));
    }

    #[test]
    fn keyed_leg_is_in_the_order_only_with_a_key() {
        assert!(exposure_order(false).contains(&BreachLeg::PwnedPasswords));
        assert!(exposure_order(false).contains(&BreachLeg::HibpCatalog));
        assert!(!exposure_order(false).contains(&BreachLeg::HibpAccount));
        assert!(exposure_order(true).contains(&BreachLeg::HibpAccount));
    }

    #[test]
    fn stolen_tax_follows_the_same_order() {
        assert!(!stolen_tax_allowed(false));
        assert!(stolen_tax_allowed(true));
    }
}
