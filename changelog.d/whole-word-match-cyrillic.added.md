- The strict whole-word name matcher that the SEC EDGAR, ACNC and ASIC register legs use now
  matches across scripts: when either the subject or the register entry is written in Cyrillic,
  both are also compared in their romanised form, so "Владимир Путин" matches "PUTIN, Vladimir".
  Every word must still match. Text with no Cyrillic never takes the new path, so its result is
  unchanged, and the looser any-word matcher is left as it was.
