/**
 * Deterministic fixture prelude for the Gateway v2 evaluation program.
 *
 * Vendored verbatim from the spec: the §8.2 `migrateConfig` function followed
 * by the §13.1 fixture prelude, in that order, ported to TypeScript ESM.
 * The semantics are normative — do not "fix", extend, or reorder them.
 * All RFC 8032 keys and predictable tokens are public test material,
 * forbidden in production.
 */
import {createHash,createPrivateKey,createPublicKey,sign} from "node:crypto";
import type {KeyObject} from "node:crypto";

// ---------------------------------------------------------------------------
// §8.2 migrateConfig — verbatim.
// ---------------------------------------------------------------------------
export function migrateConfig(v1:any,workspace:string,instance:string) {
  if (v1.schema_version!==1) throw new Error("SCHEMA_UNSUPPORTED");
  const result=structuredClone(v1);
  result.$schema="https://latticeag.dev/schemas/latticeag-config/v2.json";
  result.schema_version=2;
  result.gateway={workspace_id:workspace,instance_id:instance,autostart:"on-demand",ui:{enabled:true,bind:"127.0.0.1",port:9848,ipv6:false,remote:false},mesh:{mode:"local",contract:null}};
  result.agents={access_ttl_s:900,refresh_ttl_s:2592000,allow_operator:false};
  result.products={instances:{}};
  result.catalog={channel:"stable",source:null,pins:[],allowlist:[],strict:false,max_age_s:604800};
  result.storage={root:".latticeag",segment_bytes:67108864,disk_bytes:"10737418240",retention_days:30};
  const stream=()=>({enabled:false,paused:false,profile:"metadata",include_objects:false,cohort:"private",from:"now"});
  result.sync={enabled:false,paused:v1.sync.enabled,cloud:null,streams:{runs:stream(),receipts:stream(),lineage:stream(),approvals:stream(),watch:stream(),mesh:stream()},legacy:structuredClone(v1.sync)};
  return result;
}

// ---------------------------------------------------------------------------
// §13.1 prelude — verbatim.
// ---------------------------------------------------------------------------

// J: sorted-keys strict canonicalizer over the fixture's scalar/safe-integer
// domain (arrays, objects by enumerable key, JSON.stringify scalars).
// Numbers outside the safe-integer domain and non-scalar leaf values throw;
// non-plain OBJECTS still serialize via their enumerable keys exactly as the
// spec's one-liner does — `agent.challenge` relies on J(KeyObject) === "{}".
export const J=(x:any):string=>{
  if (Array.isArray(x)) return "["+x.map(J).join(",")+"]";
  if (x!==null&&typeof x==="object") return "{"+Object.keys(x).sort().map(k=>JSON.stringify(k)+":"+J(x[k])).join(",")+"}";
  if (typeof x==="number"&&!Number.isSafeInteger(x)) throw new TypeError("J: number outside the safe-integer fixture domain");
  if (x===null||typeof x==="string"||typeof x==="number"||typeof x==="boolean") return JSON.stringify(x);
  throw new TypeError("J: value outside the scalar/safe-integer fixture domain");
};
export const H=(x:any):string=>createHash("sha256").update(x).digest("hex");
export const Z="0".repeat(64), now=1789257600000;
export const bytes=(x:any):Buffer=>Buffer.isBuffer(x)?x:Buffer.from(x);
export const blob=(x:any,media="application/json")=>({ref:{digest:H(bytes(x)),bytes:String(bytes(x).length),media},content:bytes(x).toString("base64url")});
export const artifact=(x:any)=>({profile:"bytes/1",digest:"sha256:"+H(bytes(x)),bytes:bytes(x).length});
export interface FixtureKey {secret:KeyObject;public:KeyObject;material:{id:string;public:string};sunlight:string;}
export function makeKey(seed:string,n:number):FixtureKey {
  const secret=createPrivateKey({key:Buffer.from("302e020100300506032b657004220420"+seed,"hex"),format:"der",type:"pkcs8"});
  const raw=createPublicKey(secret).export({format:"der",type:"spki"}).subarray(-32);
  return {secret,public:createPublicKey(secret),material:{id:H(raw),public:raw.toString("base64url")},sunlight:"slk_"+String(n).padStart(21,"0")};
}
export const origin=makeKey("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",1);
export const auditor=makeKey("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",2);
// NOTE (spec §13.1 ~line 1170): the fixture signs the J-hash decoded from its
// hex form — Buffer.from(H(J(body)),"hex") — kept verbatim even where the
// surrounding prose describes the domain separation differently.
export const signed=(domain:string,body:any,k:FixtureKey=origin)=>sign(null,Buffer.concat([Buffer.from(domain+"\0"),Buffer.from(H(J(body)),"hex")]),k.secret).toString("base64url");
export const ref=(e:any)=>({source:e.body.source,stream:e.body.stream,seq:e.body.seq,hash:e.hash});
export function sealProof(body:any,k:FixtureKey=origin) {
  const hash=H(Buffer.concat([Buffer.from("LAGI-PROOF-EVENT/v1\0"),Buffer.from(J(body))]));
  return {body,hash,signature:sign(null,Buffer.concat([Buffer.from("LAGI-PROOF-EVENT-SIGN/v1\0"),Buffer.from(hash,"hex")]),k.secret).toString("base64url")};
}
export const intent=blob("{}"), observation=blob("ok","text/plain");
export function history(run:string,input:any,output:any,workspace="ws1",source="src1",k:FixtureKey=origin,stream="main"):any[] {
  const result:any[]=[];
  const add=(data:any,parents:any[]=[])=>{const n=result.length;result.push(sealProof({v:1,workspace,source,stream,seq:String(n+1),prev:n?result[n-1].hash:Z,lamport:String(n+1),key:k.material.id,parents,data},k));};
  add({kind:"RunOpened",run,intent:input.ref,policy:null,hypothetical:false});
  add({kind:"StepOpened",run,step:"step1",operation:"compute",input:null});
  add({kind:"ObservationRecorded",run,step:"step1",value:output.ref});
  add({kind:"StepClosed",run,step:"step1",outcome:"SUCCEEDED",observation:ref(result[2])},[ref(result[2])]);
  add({kind:"RunClosed",run,outcome:"SUCCEEDED"});
  return result;
}
export function sunlight(b:any,k:FixtureKey,n:number) {
  const body={v:"sunlight.statement/1",id:"sls_"+String(n).padStart(21,"0"),ledger:"sll_"+"1".padStart(21,"0"),signer:k.sunlight,claimed_at_ms:now-604800000,capture:"posthoc",subject:{kind:"evidence",artifact:artifact(Buffer.from(b.content,"base64url"))},parents:[],details:{type:"creation"},evidence:[]};
  const hash="sha256:"+H(Buffer.concat([Buffer.from("sunlight.statement/1\n"),Buffer.from(J(body))]));
  return {body,hash,signature_hex:sign(null,Buffer.concat([Buffer.from("sunlight.statement.signature/1\n"),Buffer.from(hash.slice(7),"hex")]),k.secret).toString("hex")};
}
export const native=(s:any)=>({profile:"sunlight.statement/1",namespace:s.body.ledger,object_id:s.body.id,commitment:s.hash,raw_sha256:H(J(s)),bytes:String(Buffer.byteLength(J(s)))});
export function tar(files:Record<string,any>):Buffer {
  const out:Buffer[]=[];
  for (const path of Object.keys(files).sort()) {
    const data=bytes(files[path]), h=Buffer.alloc(512), oct=(n:number,width:number)=>n.toString(8).padStart(width-1,"0")+"\0";
    h.write(path,0,100,"ascii"); h.write(oct(420,8),100); h.write(oct(0,8),108); h.write(oct(0,8),116);
    h.write(oct(data.length,12),124); h.write(oct(0,12),136); h.fill(32,148,156); h[156]=48; h.write("ustar\0",257); h.write("00",263);
    h.write(Array.from(h).reduce((a,b)=>a+b,0).toString(8).padStart(6,"0")+"\0 ",148);
    out.push(h,data,Buffer.alloc((512-data.length%512)%512));
  }
  return Buffer.concat(out.concat([Buffer.alloc(1024)]));
}
export const schema=blob(J({$schema:"https://json-schema.org/draft/2020-12/schema",type:"object",properties:{},additionalProperties:false}));
export const adapterSource=[
  'import {createInterface} from "node:readline";',
  'let generation="1", running=false;',
  'for await (const line of createInterface({input:process.stdin})) {',
  'const q=JSON.parse(line); const handlers={describe:()=>({contract:"gateway-adapter/1",product:"lexverdict",config_schema_digest:"'+schema.ref.digest+'",profiles:["@latticeag/events@0.1.0"]}),configure:()=>{generation=q.params.generation;return {generation,accepted:true};},start:()=>{running=true;return {state:"RUNNING",generation};},health:()=>({liveness:running,readiness:running,dependencies:[],native:{status:"ok"}}),drain:()=>({in_flight:0,uncertain:[]}),snapshot:()=>({supported:false,objects:[]}),stop:()=>{running=false;return {state:"STOPPED",uncertain:[]};}};',
  'const reply=handlers[q.method]?{v:1,id:q.id,ok:true,result:handlers[q.method]()}:{v:1,id:q.id,ok:false,error:{code:"METHOD_UNKNOWN",retryable:false}};',
  'process.stdout.write(JSON.stringify(reply)+"\\n");',
  '}'
].join("\n")+"\n";
export function release(version:string,overrides:Record<string,any>={}) {
  const files=Object.assign({"package/package.json":J({name:"@latticeag/fixture-lexverdict",version,type:"module",license:"MIT"}),"package/adapter.mjs":adapterSource,"package/config.schema.json":Buffer.from(schema.content,"base64url"),"package/gateway-adapter.json":J({contract:"gateway-adapter/1",entry:"adapter.mjs",config_schema:"config.schema.json"})},overrides);
  const archive=tar(files), ar=artifact(archive), lockfile=artifact("lockfileVersion: '9.0'\nimporters: {}\n");
  const sbom=blob(J({schema:"gateway.sbom/1",packages:[{name:"@latticeag/fixture-lexverdict",version,license:"MIT",archive:ar.digest}]}));
  const provenance=blob(J({schema:"gateway.build/1",builder:"fixture-builder",repository:"LatticeAG/latticeag-gateway",commit:"1".repeat(40),command:"pnpm build",materials:[lockfile],sbom:sbom.ref,outputs:[ar]}));
  const offset=version==="0.1.1"?10:0;
  const ps=[sunlight(provenance,origin,offset+1),sunlight(provenance,auditor,offset+2)];
  const manifest={schema:"gateway.product/1",slug:"lexverdict",version,series:"lex",license:"MIT",package:{kind:"npm",name:"@latticeag/fixture-lexverdict",archive:ar},runtime:{os:["linux"],arch:["arm64","x64"],node:">=22.13 <25",sandbox:"linux-ns"},adapter:{contract:"gateway-adapter/1",entry:"adapter.mjs",config_schema:schema.ref,health_timeout_ms:2000,startup_timeout_ms:30000},provenance:{descriptor:provenance.ref,statements:ps.map(native),builder:"fixture-builder",repository:"LatticeAG/latticeag-gateway",commit:"1".repeat(40),lockfile,sbom:sbom.ref},dependencies:[],capabilities:{read_paths:[],write_paths:["data"],network_origins:[],emit:["telemetry"],consume:[],native_profiles:["@latticeag/events@0.1.0"]},interfaces:{profile:"interfaces/1",snapshot:"dde77234734cd0f9ba39d6ea3958e01215c9d33d502c93bc257131870d70fdf6",edges:[]},surfaces:{local:"free",hosted:false,tier:"oss",entitlement:null}};
  const m=blob(J(manifest));
  return {archive,files,sbom,manifest,wire:{manifest:m,signatures:[sunlight(m,origin,offset+3),sunlight(m,auditor,offset+4)],provenance,provenance_signatures:ps}};
}
export const config1={schema_version:1,project:{name:"demo",run_id_prefix:"run"},bus:{},ingest:{bind:"127.0.0.1",port:9847,path:"/v1/ingest"},adapters:{
  axion:{enabled:false,base_url:"http://127.0.0.1:9001",webhook_path:"/v1/ingest/axion"},visreplay:{enabled:false,session_dir:".latticeag/sessions"},lexverdict:{enabled:true,base_url_env:"LEXVERDICT_URL"},
  vekinbox:{enabled:false,base_url_env:"VEKINBOX_URL",api_key_env:"VEKINBOX_API_KEY",workspace_id_env:"VEKINBOX_WORKSPACE_ID",agent_id_env:"VEKINBOX_AGENT_ID"},viscompile:{enabled:false,bin:"lattice",baseline:"baseline.json"},lexshield:{enabled:false,bin:"lexshield"},polymesh:{enabled:false,gateway_url_env:"POLYMESH_GATEWAY_URL",mesh_id_env:"POLYMESH_MESH_ID",capability:"latticeag.events.relay"}},
  redaction:{keys:["authorization","api_key"],include_raw_text:false},sync:{enabled:false,gateway_url_env:"LEXGATEWAY_URL",token_env:"LEXGATEWAY_TOKEN",mode:"replicate",local_port:8788,polymesh:{enabled:false}},doctor:{}};
export const scopes=[{permission:"approvals.request",topics:[],runs:["self"],products:[]},{permission:"events.consume",topics:["approval.decision"],runs:["self"],products:[]},{permission:"events.emit",topics:["telemetry"],runs:["self"],products:[]},{permission:"lineage.read",topics:[],runs:["self"],products:[]}];
export const capability={name:"latticeag.events.relay",revision:1,profiles:["@latticeag/events@0.1.0","proof-evidence/1"],emit:["telemetry"],consume:["approval.decision"],request_approvals:true,lineage:"own"};
export const token=(n:number)=>Buffer.alloc(32,n).toString("base64url");
export const F:Record<string,any>={now,config1,config2:migrateConfig(config1,"ws1","gw1"),ulid:"01ARZ3NDEKTSV4RRFFQ69G5FAV",key:origin.material,code:"6J7K8M9N2P",clientNonce:token(1),serverNonce:token(2),access:token(3),refresh:token(4),access2:token(5),refresh2:token(6),bootstrap:token(7),csrf:token(8),scopes,schema,intent,events:history("run1",intent,observation),release1:release("0.1.0"),release2:release("0.1.1"),cursor:"c0000000000000001:7"};
F.eventBlob=blob(J(F.events[0])); F.pointer={workspace:"ws1",event:ref(F.events[3])};
F.nativeRef={profile:"gateway.fixture/1",namespace:"fixture",object_id:"action1",commitment:null,raw_sha256:intent.ref.digest,bytes:intent.ref.bytes};
F.inventory=[intent,observation].map(b=>({kind:"object",digest:b.ref.digest,bytes:b.ref.bytes,availability:"WITHHELD"})).sort((a,b)=>a.digest<b.digest?-1:1);
const rb={v:1,kind:"register",gateway:"gw1",workspace:"ws1",epoch:"1",pair:"pair1",challenge:"challenge1",client_nonce:F.clientNonce,server_nonce:F.serverNonce,key:F.key.id,profiles:capability.profiles,interfaces:"interfaces/1",capabilities:[capability]};
F.registration={pair:"pair1",code:F.code,key:F.key,challenge:"challenge1",client_nonce:F.clientNonce,server_nonce:F.serverNonce,epoch:"1",profiles:capability.profiles,interfaces:"interfaces/1",capabilities:[capability],proof:signed("LATTICEAG-GATEWAY-PAIR/1",rb)};
F.proposal=H(J({key:F.key,profiles:capability.profiles,interfaces:"interfaces/1",capabilities:[capability]}));
F.renewProof=signed("LATTICEAG-GATEWAY-RENEW/1",{v:1,kind:"renew",gateway:"gw1",workspace:"ws1",epoch:"1",peer:"peer1",refresh_hash:H(F.refresh),challenge:"challenge1",server_nonce:F.serverNonce});
F.archiveDigest=F.release1.manifest.package.archive.digest;
F.catalogEntry={slug:"lexverdict",series:"lex",version:"0.1.0",published_ms:now-604800000,manifest:F.release1.wire.manifest.ref,release_signatures:F.release1.wire.signatures.map(native),adapter_status:"available",surfaces:F.release1.manifest.surfaces};
F.index={schema:"gateway.catalog/1",revision:"1",issued_ms:now-86400000,expires_ms:now+604800000,channel:"stable",entries:[F.catalogEntry],revocations:[]};
F.pin={slug:"lexverdict",version:"0.1.0",digest:F.archiveDigest,index:artifact(J(F.index)).digest};
export function planFor(kind:string) {
  const from=kind==="install"?null:kind==="rollback"?"0.1.1":"0.1.0", to=kind==="uninstall"?null:kind==="update"?"0.1.1":"0.1.0";
  const target=kind==="update"?F.release2:F.release1;
  return {kind,slug:"lexverdict",from,to,manifest:target.wire.manifest.ref.digest,archive:target.manifest.package.archive.digest,dependencies:[],grants:target.manifest.capabilities,revisions:{config:"1",catalog:"1",registry:"1"},trust:H(J([origin.material,auditor.material])),keep_data:true,cascade:false};
}
F.planSummary=planFor("install"); F.plan=H(J(F.planSummary)); F.review=H(J({plan:F.plan,operator:"operator1",expires_ms:now+300000}));
F.syncCounts=Object.fromEntries(["runs","receipts","lineage","approvals","watch","mesh"].map(s=>[s,{pending:0,in_flight:0,blocked:0,acked:0}]));
export const scrub=(x:any):any=>Array.isArray(x)?x.map(scrub):x!==null&&typeof x==="object"?Object.fromEntries(Object.entries(x).map(([k,v])=>[k,/^(access|refresh|access2|refresh2|code|proof|csrf|bootstrap|client_nonce|server_nonce)$/.test(k)?"[redacted]":scrub(v)])):typeof x==="string"?x.replace(/#bootstrap=.*/,"#bootstrap=[redacted]"):x;
