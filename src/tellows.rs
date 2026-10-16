    Ok(Score {
        number: api_leg::clean(t.number.as_deref()).unwrap_or_default(),
        score: t
            .score
            .as_deref()
            .ok_or_else(|| LegError::Decode("missing score".into()))?
            .parse()
            .map_err(|_| LegError::Decode("score is not a number".into()))?,
        searches: t.searches.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        comments: t.comments.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        location: api_leg::clean(t.location.as_deref()),
        country: api_leg::clean(t.country.as_deref()),
        caller_type,
        raw_answer: whole.to_string(),
    })
