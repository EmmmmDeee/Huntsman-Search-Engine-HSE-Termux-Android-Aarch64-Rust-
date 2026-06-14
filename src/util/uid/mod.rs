pub fn scan_id(kind: &str, value: &str) -> String {
    crate::core::entity::scan_id(kind, value)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
