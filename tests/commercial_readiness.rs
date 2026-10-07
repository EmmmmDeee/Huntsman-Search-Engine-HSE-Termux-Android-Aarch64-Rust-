use std::path::PathBuf;

use huntsman_recon::commercial_readiness::{benchmarks, manifest, readiness_markdown};

fn root()->PathBuf{PathBuf::from(env!("CARGO_MANIFEST_DIR"))}

#[test] fn declared_proof_paths_exist(){ let m=manifest().unwrap(); for c in m.capabilities { for p in c.implementation.iter().chain(c.proof.iter()){ assert!(root().join(p).is_file(),"{} references missing {}",c.id,p); } } }

#[test] fn benchmark_capabilities_exist(){ let m=manifest().unwrap(); let b=benchmarks().unwrap(); let ids:std::collections::BTreeSet<_>=m.capabilities.iter().map(|c|c.id.as_str()).collect(); for r in b.benchmarks { assert!(ids.contains(r.capability.as_str()),"benchmark {} references unknown capability {}",r.id,r.capability); } }

#[test] fn generated_report_is_current(){ let expected=readiness_markdown().unwrap(); let actual=std::fs::read_to_string(root().join("docs/COMMERCIAL_READINESS.generated.md")).unwrap(); assert_eq!(actual,expected,"regenerate docs/COMMERCIAL_READINESS.generated.md from manifests"); }
