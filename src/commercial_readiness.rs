//! Machine-checkable commercial capability and benchmark manifests.

use serde::{Deserialize, Serialize};

const CAPABILITIES_JSON: &str = include_str!("../capabilities.json");

const BENCHMARKS_JSON: &str = include_str!("../benchmarks.json");

#[derive(Debug,Clone,Deserialize,Serialize)] pub struct CapabilityManifest { pub schema_version:u32, pub product:String, pub capabilities:Vec<Capability> }

#[derive(Debug,Clone,Deserialize,Serialize)] pub struct Capability { pub id:String, pub name:String, pub status:CapabilityStatus, pub implementation:Vec<String>, pub proof:Vec<String>, pub interfaces:Vec<String>, pub platforms:Vec<String>, pub benchmark:Option<String>, pub limitations:Vec<String> }

#[derive(Debug,Clone,Copy,Deserialize,Serialize,PartialEq,Eq)] #[serde(rename_all="kebab-case")] pub enum CapabilityStatus { Demonstrated, Partial, Planned }

#[derive(Debug,Clone,Deserialize,Serialize)] pub struct BenchmarkManifest { pub schema_version:u32, pub policy:BenchmarkPolicy, pub benchmarks:Vec<BenchmarkReceipt> }

#[derive(Debug,Clone,Deserialize,Serialize)] pub struct BenchmarkPolicy { pub claim_rule:String, pub regression_gate:String }

#[derive(Debug,Clone,Deserialize,Serialize)] pub struct BenchmarkReceipt { pub id:String, pub capability:String, pub workload:String, pub platform:String, pub build_profile:String, pub repetitions:u32, pub metric:String, pub value:f64, pub unit:String }

pub fn manifest()->Result<CapabilityManifest,String>{ let p:CapabilityManifest=serde_json::from_str(CAPABILITIES_JSON).map_err(|e|format!("capabilities.json: {e}"))?; validate(&p)?; Ok(p) }

pub fn benchmarks()->Result<BenchmarkManifest,String>{ let p:BenchmarkManifest=serde_json::from_str(BENCHMARKS_JSON).map_err(|e|format!("benchmarks.json: {e}"))?; if p.schema_version!=1{return Err("benchmarks.json: unsupported schema_version".into())} for x in &p.benchmarks { if x.id.trim().is_empty()||x.capability.trim().is_empty()||x.workload.trim().is_empty()||x.platform.trim().is_empty()||x.build_profile.trim().is_empty()||x.metric.trim().is_empty()||x.unit.trim().is_empty()||x.repetitions==0||!x.value.is_finite(){return Err(format!("benchmarks.json: incomplete receipt {}",x.id))} } Ok(p) }

pub fn validate(p:&CapabilityManifest)->Result<(),String>{ if p.schema_version!=1||p.product!="huntsman-recon"{return Err("capabilities.json: unsupported schema or product".into())} let mut ids=std::collections::BTreeSet::new(); for c in &p.capabilities { if c.id.trim().is_empty()||c.name.trim().is_empty()||!ids.insert(c.id.as_str()){return Err(format!("capabilities.json: invalid/duplicate id {}",c.id))} if c.implementation.is_empty()||c.proof.is_empty(){return Err(format!("capability {} has no implementation/proof",c.id))} if c.interfaces.is_empty()||c.platforms.is_empty(){return Err(format!("capability {} has no interface/platform",c.id))} if c.status==CapabilityStatus::Demonstrated&&c.limitations.is_empty(){return Err(format!("demonstrated capability {} must state limitations",c.id))} } Ok(()) }

pub fn readiness_markdown()->Result<String,String>{ let p=manifest()?; let b=benchmarks()?; let d=p.capabilities.iter().filter(|c|c.status==CapabilityStatus::Demonstrated).count(); let q=p.capabilities.iter().filter(|c|c.status==CapabilityStatus::Partial).count(); let n=p.capabilities.iter().filter(|c|c.status==CapabilityStatus::Planned).count(); let mut out=format!("# Generated commercial-readiness report\n\nSchema: {}. Product: huntsman-recon.\n\nDemonstrated: **{d}**. Partial: **{q}**. Planned: **{n}**. Benchmark receipts: **{}**.\n\n| Capability | Status | Interfaces | Platforms | Benchmark |\n| --- | --- | --- | --- | --- |\n",p.schema_version,b.benchmarks.len()); for c in &p.capabilities { let s=match c.status{CapabilityStatus::Demonstrated=>"demonstrated",CapabilityStatus::Partial=>"partial",CapabilityStatus::Planned=>"planned"}; out.push_str(&format!("| {} | {} | {} | {} | {} |\n",c.name,s,c.interfaces.join(", "),c.platforms.join(", "),c.benchmark.as_deref().unwrap_or("not measured"))); } out.push_str("\nGenerated from capabilities.json and benchmarks.json; not a valuation or revenue claim.\n"); Ok(out) }
