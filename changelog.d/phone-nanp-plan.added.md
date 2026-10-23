- `phone` holds a `+1` number to the North American Numbering Plan, offline.
  - A number the plan cannot hold is refused, naming the rule it breaks: an area code or exchange
    beginning with 0 or 1, an N11 code, or a reserved area code (N9X, 37X, 96X). It was
    previously accepted as valid because it had E.164's shape.
  - Any other number gets:
    - its local `(416) 555-0199` and international `+1 416 555 0199` forms;
    - its class: geographic, toll-free, premium, or another service code;
    - the country or territory its area code belongs to, rather than just "NANP". Canada, the
      Caribbean countries and the US territories come from lists; anything else is the United
      States, and the evidence says so;
    - a `fictional` tag for 555-0100 to 555-0199.
