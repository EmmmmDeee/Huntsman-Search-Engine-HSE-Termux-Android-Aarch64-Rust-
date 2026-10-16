    match api_leg::get(transport, &API, &Keys::default(), &url, now_unix) {
        Ok(Answer::Body(body)) => Ok(Some(decode(&body)?)),
        Ok(Answer::NotFound(_)) => Ok(None),
        Err(LegError::BadRequest(_)) => Ok(None),
        Err(err) => Err(err),
    }
