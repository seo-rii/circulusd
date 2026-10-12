import {describe,expect,it} from "vitest";
import {parsePortableConversationMessages} from "../src/index.ts";
const base={role:"assistant",api:"test",provider:"test",model:"test",usage:{input:0,output:0,cacheRead:0,cacheWrite:0,totalTokens:0,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}},timestamp:1};
function history(details:unknown,encoding:unknown="pi-tool-details-json-v1",present=true){
 const result:Record<string,unknown>={role:"toolResult",toolCallId:"call",toolName:"echo",content:[{type:"text",text:"done"}],isError:false,timestamp:2};
 if(present)result.details=details;if(encoding!==undefined)result.detailsEncoding=encoding;
 return [{role:"user",content:"echo",timestamp:0},{...structuredClone(base),content:[{type:"toolCall",id:"call",name:"echo",arguments:{}}],stopReason:"toolUse"},result,{...structuredClone(base),content:[{type:"text",text:"done"}],stopReason:"stop",timestamp:3}];
}
describe("portable Pi tool metadata",()=>{
 it.each([null,true,"",3,{scale:{"$pi.number.v1":"0.5"},nested:[null,{"$pi.number.v1":"1e-7"}]}])("preserves complete marked JSON metadata %j",details=>{
  expect(parsePortableConversationMessages(history(details),true)).toEqual(history(details));
 });
 it("preserves opaque legacy bytes and wrapper lookalikes",()=>{
  for(const details of [new Uint8Array([1,2]),{"$pi.number.v1":"opaque"},{scale:1}]){
   const messages=history(details,undefined);delete (messages[2] as Record<string,unknown>).detailsEncoding;
   expect(parsePortableConversationMessages(messages,true)).toEqual(messages);
  }
 });
 it.each([new Uint8Array([1]),{"$pi.number.v1":"1"},{"$pi.number.v1":"-0"},{"$pi.number.v1":"Infinity"},{"$pi.number.v1":"0.50"},{"$pi.number.v1":"0.5",extra:true}])("rejects malformed marked metadata %j",details=>{
  expect(()=>parsePortableConversationMessages(history(details),true)).toThrow();
 });
 it("requires known marker and present details",()=>{
  expect(()=>parsePortableConversationMessages(history(null,"future"),true)).toThrow();
  expect(()=>parsePortableConversationMessages(history(null,"pi-tool-details-json-v1",false),true)).toThrow();
 });
});
