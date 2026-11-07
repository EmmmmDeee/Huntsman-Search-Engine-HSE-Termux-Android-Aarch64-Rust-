- One type per report shape, in `src/lookup_report.rs`. No output changes.
  - **`SourceReport`** is what one source found: its entities and its row. Twenty-nine collectors
    declared that struct, and nineteen of them repeated its empty form, `miss`. Each collector's
    `Report` is now an alias of it, and `SourceReport::miss` and `SourceReport::found` are the one
    empty and found form. `netblock_cli`'s sweep result is the same type.
  - **`LookupReport`** is what a lookup found from every source. The ASIC registers, `exif`,
    `docmeta`, `embedded_metadata::Inspected`, `indicator_legs::Legs`, `recursion::Step` and
    `seeknow_collector::LookupLeg` declared its shape again; each is now an alias. It gains
    `Serialize` for the inspect view, whose JSON is unchanged, and `asked`, which SeekNow's leg
    used.
  - **`Leg`** is one leg of a lookup that runs several; `mnemonic` and `rdap_legs` share it.
  - **What keeps it.** `tests/architecture_boundaries.rs` fails when any other module declares a
    struct of one of these shapes, whatever its name.
