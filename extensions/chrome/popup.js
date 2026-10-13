"use strict";
const host="com.account_access.session";
const status=document.querySelector("#status");
const select=document.querySelector("#account");
let tab;
async function init(){
  [tab]=await chrome.tabs.query({active:true,currentWindow:true});
  const result=await chrome.runtime.sendNativeMessage(host,{method:"accounts"});
  for(const account of result.accounts||[]){if(new URL(tab.url).origin===account.origin){const option=document.createElement("option");option.value=account.account;option.textContent=account.label;select.append(option);}}
  if(!select.options.length){status.textContent="No reviewed account adapter matches this tab. Configure that service in owner setup first.";document.querySelector("#connect").disabled=true;}
}
document.querySelector("#connect").onclick=async()=>{
 try{
  const url=new URL(tab.url);if(url.protocol!=="https:")throw new Error("HTTPS required");
  const granted=await chrome.permissions.request({origins:[url.origin+"/*"]});if(!granted)return;
  const cookies=await chrome.cookies.getAll({url:tab.url});
  const results=await chrome.scripting.executeScript({target:{tabId:tab.id},func:()=>({origin:location.origin,localStorage:Object.entries(localStorage).map(([name,value])=>({name,value}))})});
  if(results[0].result.origin!==url.origin)throw new Error("Tab changed; reconnect it.");
  const state={cookies:cookies.map(c=>({name:c.name,value:c.value,domain:c.domain,path:c.path,expires:c.expirationDate||-1,httpOnly:c.httpOnly,secure:c.secure,sameSite:({no_restriction:"None",lax:"Lax",strict:"Strict"})[c.sameSite]||"Lax"})),origins:[results[0].result]};
  const result=await chrome.runtime.sendNativeMessage(host,{method:"import",account:select.value,url:tab.url,state});
  status.textContent=result.status==="SESSION_IMPORTED"?"Session connected locally. Your agent can now try its permitted operations.":result.reason;
 }catch(error){status.textContent=error.message;}
};
init().catch(error=>status.textContent=error.message);
