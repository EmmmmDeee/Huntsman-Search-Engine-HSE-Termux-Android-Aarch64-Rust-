- Name matching is now transliteration-aware across Cyrillic and Latin. A new offline `translit`
  romanisation (Cyrillic to Latin, plus ASCII diacritic folding) lets a name written in Cyrillic
  and its Latin transliteration reduce to the same match key. The sanctions (OFAC/UN/EU), ICIJ
  Offshore Leaks and FBI/Interpol notice matchers now compare these keys, so a query in Cyrillic
  reaches Latin-transliterated listings and the reverse. Matching stays precise: letters are
  romanised one fixed way and distinct names never collapse, so no new false positives.
