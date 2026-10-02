EXECUTE REQUIREMENTS RECONSTRUCTION AND TRACEABILITY.
Inspect the entire authoritative codebase, documentation, tests, interfaces, CLI/API/UI surfaces, schemas, configuration, installers, workflows, examples, issues, and observable runtime behaviour.
Derive the actual required behaviours of the system.
Create a requirement ledger in which every material requirement has:

* unique ID;
* user/system behaviour;
* inputs;
* outputs;
* side effects;
* failure behaviour;
* implementation location;
* tests covering it;
* runtime verification evidence;
* status.

Classify every requirement:
VERIFIED | IMPLEMENTED_UNVERIFIED | PARTIAL | MISSING | BROKEN | UNREACHABLE | OBSOLETE | AMBIGUOUS
Do not infer completion from code presence.
Immediately resolve the highest-value MISSING, PARTIAL, BROKEN, or UNREACHABLE requirement that can be safely completed now.
After implementation:

* build;
* test;
* execute the affected workflow;
* update traceability;
* repeat.

Terminate only when every required behaviour is either VERIFIED or explicitly and defensibly removed from scope.
REQUIREMENT → IMPLEMENTATION → TEST → RUNTIME EVIDENCE → VERIFIED
