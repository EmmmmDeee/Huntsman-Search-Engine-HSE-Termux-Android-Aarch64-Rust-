- Source classification has one authority. `src/source_profile.rs` holds one row per provenance
  source ID: the class the correlator counts it under and, where finer, the acquisition modality
  the orthogonal-coverage report names. It replaces the correlator's and the coverage report's
  separate match arms.
  - **Unchanged output.** The table was generated from those arms, and the classification
    snapshot still holds all 236 known IDs to the same class.
  - **Coverage guards.** Every collector constant and every registry row must have a row, so a
    new source is classified on purpose rather than by the words in its name. No legacy ID may
    be written by current code.
  - **Key-slot guard.** Every key slot the Settings page lists must have a provider row saying
    where the key comes from.
