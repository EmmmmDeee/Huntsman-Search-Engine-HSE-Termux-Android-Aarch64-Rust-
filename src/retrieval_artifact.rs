#[cfg(test)]
mod tests {
    use super::ArtifactId;

    #[test]
    fn artifact_id_round_trips_as_transparent_string() {
        let id = ArtifactId::from("sha256:abc");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"sha256:abc\"");
        assert_eq!(serde_json::from_str::<ArtifactId>(&json).unwrap(), id);
    }
}
