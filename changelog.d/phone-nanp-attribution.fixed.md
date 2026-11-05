- A saved `phone` lookup now credits its North American numbering-plan rows (`phone_nanp`) to
  `src/phone_intl.rs`, which writes them. Before, they were credited to `src/phone_cli.rs`
  through the save policy's fallback.
- A guard now runs every lookup with every source answering and requires each record it writes
  to be credited to the file that made it. Only the records the lookup's own front-end makes
  are exempt: the seed, the e-mail's parts and the Australian number plan. A source added to a
  lookup without an attribution row now fails the build instead of being saved as the
  lookup's own work.
