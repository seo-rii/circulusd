import {
  decodeCanonicalCbor, encodeCanonicalCbor, normalizeProtocolValue,
} from "./cbor.ts";
import { digestBytes, digestStructuredValue, parseDigest } from "./digest.ts";
import { isCanonicalText } from "./text.ts";
import type { AgentCheckpoint, Digest, NormalizedValue } from "./types.ts";
import { PI_EXECUTION_CAPACITY as BUDGET } from "./execution-capacity.ts";

export const PI_CONVERSATION_CODEC = "pi-agent-messages-v2" as const;
export const PI_CONVERSATION_SNAPSHOT_DOMAIN = "circulusd.session.conversation-snapshot";
export const PI_CONVERSATION_HEAD_DOMAIN = "circulusd.session.conversation-head";
export const PI_CONVERSATION_ACTIVATION_DOMAIN = "circulusd.session.conversation-activation";
export interface ConversationScope {
  readonly tenantId: string; readonly workspaceId: string;
  readonly userId: string; readonly sessionId: string;
}
export interface ConversationPayloadRef {
  readonly encoding: "canonical-cbor-v1"; readonly digest: Digest;
  readonly encodedBytes: number; readonly encodedItems: number;
}
export interface ConversationGroup {
  readonly turnId: string; readonly turnSequence: number;
  readonly inputDigest: Digest; readonly checkpointDigest: Digest;
  readonly messages: readonly NormalizedValue[];
}
export interface ConversationSnapshot {
  readonly schemaVersion: 1; readonly codec: typeof PI_CONVERSATION_CODEC;
  readonly scope: ConversationScope; readonly groups: readonly ConversationGroup[];
}
// Undefined head is legacy/unrestored. Null is explicit Session-owned empty
// history. Only the durable Session decides which of those states is true.
export interface StoredConversationHead {
  readonly schemaVersion: 1; readonly scope: ConversationScope;
  readonly revision: number; readonly throughTurnSequence: number;
  readonly snapshotRef: ConversationPayloadRef;
  readonly snapshotDigest: Digest; readonly headDigest: Digest;
}
export interface StoredConversationActivation {
  readonly schemaVersion: 1; readonly scope: ConversationScope;
  readonly turnId: string; readonly turnSequence: number;
  readonly inputDigest: Digest; readonly runtimeRevisionDigest: Digest;
  readonly adapterAbiVersion: 2; readonly checkpointSchemaVersion: 2;
  readonly genesisCheckpointDigest: Digest; readonly activatedAt: number;
  readonly head: StoredConversationHead | null;
  readonly activationDigest: Digest;
}
// Durable receipt stores activation/ref; authorized Session materializer reads
// exactly the pinned owned snapshot blob and fills body. Hash validation is
// integrity only; no parser here replaces opaque grant/current Session authority.
export interface ConversationStart {
  readonly activation: StoredConversationActivation;
  readonly snapshot: ConversationSnapshot;
}
export class ConversationValidationError extends Error {
  constructor(message: string) { super(message); this.name = "ConversationValidationError"; }
}
function fail(message: string): never { throw new ConversationValidationError(message); }
function record(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || value instanceof Uint8Array) fail("invalid conversation record");
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail("invalid conversation prototype");
  const result = value as Record<string, unknown>;
  for (const key of Reflect.ownKeys(result)) {
    const d = Object.getOwnPropertyDescriptor(result,key);
    if (typeof key !== "string" || ![...required,...optional].includes(key) || d === undefined || !d.enumerable || !("value" in d)) fail("invalid conversation field");
  }
  if (required.some((key) => !Object.hasOwn(result,key))) fail("missing conversation field");
  return result;
}
function natural(value: unknown, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || Object.is(value,-0)) fail("invalid conversation integer");
  return value;
}
function text(value: unknown, nonempty = false): string {
  if (typeof value !== "string" || (nonempty && value.length === 0) || !isCanonicalText(value)) fail("invalid conversation string");
  // Existing canonical normalizer rejects non-scalar strings before any copy.
  return value;
}
function id(value: unknown, prefix: string): string {
  const result = text(value,true);
  if (!new RegExp(`^${prefix}_[A-Z2-7]{25}[AEIMQUY4]$`).test(result)) fail("invalid conversation identity");
  return result;
}
export function parseConversationScope(value: unknown): ConversationScope {
  const r = record(value,["tenantId","workspaceId","userId","sessionId"]);
  return {tenantId:id(r.tenantId,"tenant"),workspaceId:id(r.workspaceId,"ws"),userId:id(r.userId,"subject"),sessionId:id(r.sessionId,"sess")};
}
export function sameConversationScope(a: ConversationScope,b: ConversationScope): boolean {
  return a.tenantId === b.tenantId && a.workspaceId === b.workspaceId && a.userId === b.userId && a.sessionId === b.sessionId;
}
export function conversationItems(value: NormalizedValue): number {
  let count=0; const pending=[value];
  while(pending.length){const current=pending.pop()!;count+=1;
    if(Array.isArray(current))pending.push(...current);
    else if(current!==null&&typeof current==="object"&&!(current instanceof Uint8Array))for(const entry of Object.values(current)){count+=1;pending.push(entry);}
  }
  return count;
}
function contentBlocks(value: unknown, calls?: Map<string,string>): void {
  if (!Array.isArray(value)) fail("invalid portable message content");
  for(const block of value){
    const kind=(block as {type?:unknown})?.type;
    if(kind==="text"){const b=record(block,["type","text"],["textSignature"]);text(b.text);if(b.textSignature!==undefined)text(b.textSignature);}
    else if(kind==="image"){const b=record(block,["type","data","mimeType"]);text(b.data);text(b.mimeType,true);}
    else if(kind==="thinking"&&calls!==undefined){const b=record(block,["type","thinking"],["thinkingSignature","redacted"]);text(b.thinking);if(b.thinkingSignature!==undefined)text(b.thinkingSignature);if(b.redacted!==undefined&&typeof b.redacted!=="boolean")fail("invalid thinking flag");}
    else if(kind==="toolCall"&&calls!==undefined){const b=record(block,["type","id","name","arguments"],["thoughtSignature","namespace"]);const key=text(b.id,true),name=text(b.name,true);
      if(calls.has(key)||b.arguments===null||typeof b.arguments!=="object"||Array.isArray(b.arguments)||b.arguments instanceof Uint8Array)fail("invalid historic tool call");
      if(b.thoughtSignature!==undefined)text(b.thoughtSignature);if(b.namespace!==undefined)text(b.namespace);assertEncodedPiJson(b.arguments as NormalizedValue);calls.set(key,name);
    }else fail("unsupported portable content");
  }
}
// Preserve encoded fractional cost/tool JSON unchanged. Pi decoder remains the
// sole conversion to upstream Message; these validators never round numbers.
export function parsePortableConversationMessages(value: unknown, complete: boolean): NormalizedValue[] {
  const source=normalizeProtocolValue(value);
  if(!Array.isArray(source))fail("portable transcript must be an array");
  const pending=new Map<string,string>(); let assistantSeen=false;
  for(const entry of source){
    const role=(entry as {role?:unknown})?.role;
    if(role==="user"){
      if(pending.size)fail("user precedes unresolved historic tools");
      const m=record(entry,["role","content","timestamp"]);natural(m.timestamp);
      if(typeof m.content==="string")text(m.content);else contentBlocks(m.content);
    }else if(role==="assistant"){
      if(pending.size)fail("assistant precedes unresolved historic tools");
      const m=record(entry,["role","content","api","provider","model","usage","stopReason","timestamp"],["responseModel","responseId","errorMessage","rawStopReason","endTurn"]);
      for(const name of ["api","provider","model","stopReason"])text(m[name],true);natural(m.timestamp);contentBlocks(m.content,pending);
      const u=record(m.usage,["input","output","cacheRead","cacheWrite","totalTokens","cost"],["cacheWrite1h","reasoning"]);
      for(const name of ["input","output","cacheRead","cacheWrite","totalTokens","cacheWrite1h","reasoning"])if(u[name]!==undefined)natural(u[name]);
      const c=record(u.cost,["input","output","cacheRead","cacheWrite","total"],["encoding"]);
      if(c.encoding!==undefined&&c.encoding!=="pi-cost-decimal-v1")fail("unsupported portable cost codec");
      for(const name of ["input","output","cacheRead","cacheWrite","total"]){const number=c.encoding===undefined?c[name]:Number(c[name]);
        if(typeof number!=="number"||!Number.isFinite(number)||number<0||Object.is(number,-0)||(c.encoding!==undefined&&(typeof c[name]!=="string"||number.toString()!==c[name])))fail("invalid portable cost");
      }
      for(const name of ["responseModel","responseId","errorMessage","rawStopReason"])if(m[name]!==undefined)text(m[name]);
      if(m.endTurn!==undefined&&typeof m.endTurn!=="boolean")fail("invalid portable end-turn flag");
      if(!["stop","length","toolUse","error","aborted"].includes(m.stopReason as string)||(complete&&["error","aborted"].includes(m.stopReason as string)))fail("invalid completed assistant stop reason");
      if((pending.size>0)!==(m.stopReason==="toolUse"))fail("historic tool stop reason mismatch");
      assistantSeen=true;
    }else if(role==="toolResult"){
      const m=record(entry,["role","toolCallId","toolName","content","isError","timestamp"],["details","detailsEncoding"]);
      if(m.detailsEncoding!==undefined){
        if(m.detailsEncoding!=="pi-tool-details-json-v1"||!Object.hasOwn(m,"details"))fail("invalid portable tool details encoding");
        assertEncodedPiJson(m.details as NormalizedValue);
      }
      const key=text(m.toolCallId,true),name=text(m.toolName,true);natural(m.timestamp);contentBlocks(m.content);
      if(typeof m.isError!=="boolean"||pending.get(key)!==name)fail("unpaired historic tool result");pending.delete(key);
    }else fail("unsupported portable role");
  }
  if(complete&&(pending.size||(!assistantSeen&&source.length>0)||((source.at(-1) as {role?:unknown})?.role!=="assistant"&&source.length>0)))fail("transcript is not a completed turn");
  return source;
}
export function parseConversationSnapshot(value: unknown): ConversationSnapshot {
  const normalized=normalizeProtocolValue(value,{maxItems:BUDGET.maximumConversationItems,maxDepth:BUDGET.maximumConversationDepth});
  encodeCanonicalCbor(normalized,{maxBytes:BUDGET.maximumConversationBytes,maxDepth:BUDGET.maximumConversationDepth,maxItems:BUDGET.maximumConversationItems});
  const r=record(normalized,["schemaVersion","codec","scope","groups"]);
  if(r.schemaVersion!==1||r.codec!==PI_CONVERSATION_CODEC||!Array.isArray(r.groups)||r.groups.length>BUDGET.maximumConversationGroups)fail("unsupported conversation snapshot");
  const scope=parseConversationScope(r.scope);let previous=-1;const turnIds=new Set<string>();
  const groups=r.groups.map((entry)=>{const g=record(entry,["turnId","turnSequence","inputDigest","checkpointDigest","messages"]);const sequence=natural(g.turnSequence,0);
    if(sequence<=previous)fail("conversation group order changed");previous=sequence;const turnId=id(g.turnId,"turn");if(turnIds.has(turnId))fail("conversation turn appears twice");turnIds.add(turnId);
    return {turnId,turnSequence:sequence,inputDigest:parseDigest(g.inputDigest),checkpointDigest:parseDigest(g.checkpointDigest),messages:parsePortableConversationMessages(g.messages,true)};
  });
  return {schemaVersion:1,codec:PI_CONVERSATION_CODEC,scope,groups};
}
export function emptyConversationSnapshot(scope: ConversationScope): ConversationSnapshot {return {schemaVersion:1,codec:PI_CONVERSATION_CODEC,scope:parseConversationScope(scope),groups:[]};}
export function conversationMessages(snapshot: ConversationSnapshot): NormalizedValue[] {return snapshot.groups.flatMap((group)=>structuredClone(group.messages));}
export function parseStoredConversationHead(value: unknown): StoredConversationHead {
  const r=record(normalizeProtocolValue(value),["schemaVersion","scope","revision","throughTurnSequence","snapshotRef","snapshotDigest","headDigest"]);
  if(r.schemaVersion!==1)fail("unsupported conversation head");
  const p=record(r.snapshotRef,["encoding","digest","encodedBytes","encodedItems"]);
  const encodedBytes=natural(p.encodedBytes,1),encodedItems=natural(p.encodedItems,1);
  if(p.encoding!=="canonical-cbor-v1"||encodedBytes>BUDGET.maximumConversationBytes||encodedItems>BUDGET.maximumConversationItems||encodedItems>encodedBytes)fail("invalid conversation reference");
  return {schemaVersion:1,scope:parseConversationScope(r.scope),revision:natural(r.revision,1),throughTurnSequence:natural(r.throughTurnSequence,0),snapshotRef:{encoding:"canonical-cbor-v1",digest:parseDigest(p.digest),encodedBytes,encodedItems},snapshotDigest:parseDigest(r.snapshotDigest),headDigest:parseDigest(r.headDigest)};
}
export async function assertConversationHeadIntegrity(head: StoredConversationHead): Promise<void> {
  const {headDigest,...body}=parseStoredConversationHead(head);
  if(await digestStructuredValue(PI_CONVERSATION_HEAD_DOMAIN,1,body)!==headDigest)fail("conversation head digest mismatch");
}
export function parseStoredConversationActivation(value: unknown): StoredConversationActivation {
  const r=record(normalizeProtocolValue(value),["schemaVersion","scope","turnId","turnSequence","inputDigest","runtimeRevisionDigest","adapterAbiVersion","checkpointSchemaVersion","genesisCheckpointDigest","activatedAt","head","activationDigest"]);
  if(r.schemaVersion!==1||r.adapterAbiVersion!==2||r.checkpointSchemaVersion!==2)fail("unsupported conversation activation");
  const scope=parseConversationScope(r.scope),head=r.head===null?null:parseStoredConversationHead(r.head),turnSequence=natural(r.turnSequence,0);
  if(head!==null&&(!sameConversationScope(head.scope,scope)||head.throughTurnSequence>=turnSequence))fail("conversation activation source mismatch");
  return {schemaVersion:1,scope,turnId:id(r.turnId,"turn"),turnSequence,inputDigest:parseDigest(r.inputDigest),runtimeRevisionDigest:parseDigest(r.runtimeRevisionDigest),adapterAbiVersion:2,checkpointSchemaVersion:2,genesisCheckpointDigest:parseDigest(r.genesisCheckpointDigest),activatedAt:natural(r.activatedAt),head,activationDigest:parseDigest(r.activationDigest)};
}
export async function createConversationActivation(value: Omit<StoredConversationActivation,"schemaVersion"|"adapterAbiVersion"|"checkpointSchemaVersion"|"activationDigest">): Promise<StoredConversationActivation> {
  const body={schemaVersion:1 as const,...structuredClone(value),adapterAbiVersion:2 as const,checkpointSchemaVersion:2 as const};
  return parseStoredConversationActivation({...body,activationDigest:await digestStructuredValue(PI_CONVERSATION_ACTIVATION_DOMAIN,1,body)});
}
export async function materializeConversationStart(activation: StoredConversationActivation,readOwnedBlob:(digest:Digest)=>Promise<Uint8Array|undefined>): Promise<ConversationStart> {
  const parsed=parseStoredConversationActivation(activation);
  if(parsed.head===null)return validateConversationStart({activation:parsed,snapshot:emptyConversationSnapshot(parsed.scope)});
  const bytes=await readOwnedBlob(parsed.head.snapshotRef.digest);
  if(bytes===undefined||bytes.byteLength!==parsed.head.snapshotRef.encodedBytes||await digestBytes(bytes)!==parsed.head.snapshotRef.digest)fail("conversation snapshot unavailable");
  const snapshot=decodeCanonicalCbor(bytes,{maxBytes:BUDGET.maximumConversationBytes,maxDepth:BUDGET.maximumConversationDepth,maxItems:BUDGET.maximumConversationItems});
  return validateConversationStart({activation:parsed,snapshot});
}
export async function validateConversationStart(value: unknown): Promise<ConversationStart> {
  const r=record(value,["activation","snapshot"]),activation=parseStoredConversationActivation(r.activation),snapshot=parseConversationSnapshot(r.snapshot);
  const {activationDigest,...body}=activation;
  if(await digestStructuredValue(PI_CONVERSATION_ACTIVATION_DOMAIN,1,body)!==activationDigest||!sameConversationScope(activation.scope,snapshot.scope))fail("conversation activation digest or scope mismatch");
  const head=activation.head;
  if(head===null){if(snapshot.groups.length)fail("nonempty transcript for empty head");}
  else{await assertConversationHeadIntegrity(head);
    const bytes=encodeCanonicalCbor(snapshot,{maxBytes:BUDGET.maximumConversationBytes,maxDepth:BUDGET.maximumConversationDepth,maxItems:BUDGET.maximumConversationItems});
    if(await digestBytes(bytes)!==head.snapshotRef.digest||bytes.length!==head.snapshotRef.encodedBytes||conversationItems(snapshot as unknown as NormalizedValue)!==head.snapshotRef.encodedItems||await digestStructuredValue(PI_CONVERSATION_SNAPSHOT_DOMAIN,1,snapshot)!==head.snapshotDigest||snapshot.groups.at(-1)?.turnSequence!==head.throughTurnSequence)fail("conversation snapshot binding mismatch");
  }
  return {activation,snapshot};
}
export async function validateConversationStartForCheckpoint(value: unknown,checkpoint: AgentCheckpoint,input: NormalizedValue): Promise<ConversationStart> {
  const start=await validateConversationStart(value),a=start.activation;
  if(checkpoint.kind!=="genesis"||checkpoint.checkpointSequence!==0||checkpoint.predecessorDigest!==null||checkpoint.sessionId!==a.scope.sessionId||checkpoint.turnId!==a.turnId||checkpoint.runtimeRevisionDigest!==a.runtimeRevisionDigest||checkpoint.adapterAbiVersion!==2||checkpoint.checkpointSchemaVersion!==2||await digestStructuredValue("circulusd.session.agent-checkpoint",1,checkpoint)!==a.genesisCheckpointDigest||await digestStructuredValue("circulusd.session.turn-input",1,input)!==a.inputDigest)fail("conversation does not match fresh genesis/input/runtime");
  return start;
}
export function projectPiCheckpointMessages(checkpoint: AgentCheckpoint,complete=false): NormalizedValue[] {
  const state=record(decodeCanonicalCbor(checkpoint.payloadBytes,{maxBytes:BUDGET.maximumCheckpointBytes,maxDepth:64,maxItems:100000}),["version","status","coreState","turnInput","beforeTurnCompleted","awaiting","pendingTools","completedTools","terminalCode"]);
  const core=record(state.coreState,["version","phase","messages","pendingToolCalls"],["conversationBaseMessageCount"]);
  if(state.version!==1||core.version!==2||!Array.isArray(core.pendingToolCalls))fail("unsupported Pi checkpoint state");
  if(complete&&(state.status!=="terminal"||core.phase!=="complete"||core.pendingToolCalls.length||state.awaiting!==null||!Array.isArray(state.pendingTools)||state.pendingTools.length||state.terminalCode!=="TURN_COMPLETE"))fail("checkpoint does not contain a completed conversation");
  return parsePortableConversationMessages(core.messages,complete);
}
function sameValue(a: unknown,b: unknown): boolean {const left=encodeCanonicalCbor(a,{maxBytes:4<<20}),right=encodeCanonicalCbor(b,{maxBytes:4<<20});return left.length===right.length&&left.every((byte,i)=>byte===right[i]);}
export function assertConversationMessagePrefix(messages: readonly NormalizedValue[],snapshot: ConversationSnapshot,input: NormalizedValue): number {
  const prefix=conversationMessages(snapshot);
  const users=conversationInputMessages(input);
  if(!sameValue(messages.slice(0,prefix.length),prefix)||!sameValue(messages.slice(prefix.length,prefix.length+users.length),users))fail("conversation imported prefix/current input changed");
  return prefix.length;
}
export async function buildCompletedConversationSnapshot(start: ConversationStart,checkpoint: AgentCheckpoint,input: NormalizedValue): Promise<ConversationSnapshot> {
  const checked=await validateConversationStart(start),messages=projectPiCheckpointMessages(checkpoint,true),prefixLength=assertConversationMessagePrefix(messages,checked.snapshot,input);
  const group={turnId:checked.activation.turnId,turnSequence:checked.activation.turnSequence,inputDigest:checked.activation.inputDigest,checkpointDigest:await digestStructuredValue("circulusd.session.agent-checkpoint",1,checkpoint),messages:messages.slice(prefixLength)};
  if(checkpoint.sessionId!==checked.activation.scope.sessionId||checkpoint.turnId!==checked.activation.turnId||checkpoint.runtimeRevisionDigest!==checked.activation.runtimeRevisionDigest)fail("completed conversation checkpoint identity changed");
  assertConversationGroupCapacity(group.messages);
  const groups=[...structuredClone(checked.snapshot.groups),group];
  // Semantics were validated above; only a known encoding-capacity condition may
  // remove old groups. Never catch malformed/new/foreign transcript validation.
  while(groups.length>BUDGET.maximumConversationGroups)groups.shift();
  for(;;){const candidate={...checked.snapshot,groups};let fits=true;
    try{encodeCanonicalCbor(candidate,{maxBytes:BUDGET.maximumConversationBytes,maxDepth:BUDGET.maximumConversationDepth,maxItems:BUDGET.maximumConversationItems});}catch{fits=false;}
    if(fits)return parseConversationSnapshot(candidate);
    if(groups.length===1)fail("completed conversation group exceeds its window");groups.shift();
  }
}
export async function encodeConversationHead(snapshot: ConversationSnapshot,revision:number): Promise<{head:StoredConversationHead;bytes:Uint8Array}> {
  const checked=parseConversationSnapshot(snapshot),last=checked.groups.at(-1);if(last===undefined)fail("empty history is not a completed head");
  const bytes=encodeCanonicalCbor(checked,{maxBytes:BUDGET.maximumConversationBytes,maxDepth:BUDGET.maximumConversationDepth,maxItems:BUDGET.maximumConversationItems});
  const body={schemaVersion:1 as const,scope:checked.scope,revision:natural(revision,1),throughTurnSequence:last.turnSequence,snapshotRef:{encoding:"canonical-cbor-v1" as const,digest:await digestBytes(bytes),encodedBytes:bytes.length,encodedItems:conversationItems(checked as unknown as NormalizedValue)},snapshotDigest:await digestStructuredValue(PI_CONVERSATION_SNAPSHOT_DOMAIN,1,checked)};
  return {head:{...body,headDigest:await digestStructuredValue(PI_CONVERSATION_HEAD_DOMAIN,1,body)},bytes};
}

// Reserve worst fixed metadata before a Pi transition reaches turn_complete.
// Actual fields have equal fixed identity/digest widths and smaller integers.
export function assertConversationGroupCapacity(messages: readonly NormalizedValue[]): void {
  const placeholder=`sha256:${"0".repeat(64)}`;
  const idBody="A".repeat(26);
  const envelope={schemaVersion:1,codec:PI_CONVERSATION_CODEC,scope:{tenantId:`tenant_${idBody}`,workspaceId:`ws_${idBody}`,userId:`subject_${idBody}`,sessionId:`sess_${idBody}`},groups:[{turnId:`turn_${idBody}`,turnSequence:Number.MAX_SAFE_INTEGER,inputDigest:placeholder,checkpointDigest:placeholder,messages}]};
  encodeCanonicalCbor(envelope,{maxBytes:BUDGET.maximumConversationBytes,maxDepth:BUDGET.maximumConversationDepth,maxItems:BUDGET.maximumConversationItems});
}

export function conversationInputMessages(input: NormalizedValue): NormalizedValue[] {
  if(input!==null&&typeof input==="object"&&!Array.isArray(input)&&Object.hasOwn(input,"messages")){
    const r=record(input,["messages"]);if(!Array.isArray(r.messages))fail("invalid public input messages");
    return r.messages.map((entry)=>{const m=record(entry,["role","content"]);if(m.role!=="user")fail("invalid public role");return {role:"user",content:text(m.content,true),timestamp:0};});
  }
  const r=record(input,["prompt","timestamp"]);return [{role:"user",content:text(r.prompt),timestamp:natural(r.timestamp)}];
}

function assertEncodedPiJson(value: NormalizedValue): void {
  const pending=[value];
  while(pending.length){const current=pending.pop()!;
    if(current instanceof Uint8Array)fail("portable tool arguments cannot contain binary capabilities");
    if(current===null||typeof current!=="object")continue;
    if(Array.isArray(current)){pending.push(...current);continue;}
    if(Object.hasOwn(current,"$pi.number.v1")){
      const decimal=current["$pi.number.v1"],number=typeof decimal==="string"?Number(decimal):NaN;
      if(Object.keys(current).length!==1||typeof decimal!=="string"||decimal.length>32||!Number.isFinite(number)||Object.is(number,-0)||Number.isSafeInteger(number)||number.toString()!==decimal)fail("invalid portable Pi JSON number wrapper");
    }else pending.push(...Object.values(current));
  }
}
