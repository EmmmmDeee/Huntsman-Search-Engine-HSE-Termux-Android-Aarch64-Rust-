- The DER certificate reader behind the Cert Spotter leg is now tested against 10,000 corrupted
  certificates, 5,000 from each of two real logged ones. Each is read or refused, and its subject,
  issuer and PEM form are written, without a panic. The test was checked by removing the reader's
  length guard, which it caught.
