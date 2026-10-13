"use strict";
const capability=location.hash.slice(1);
history.replaceState(null,"","/");
const el=id=>document.getElementById(id);
const selected=()=>["codex","claude"].filter(x=>el(x).checked);
const message=text=>el("message").textContent=text;
let state=null;
async function call(path,body){
 const r=await fetch(path,{method:body?"POST":"GET",headers:{Authorization:"Bearer "+capability,...(body?{"Content-Type":"application/json"}:{})},...(body?{body:JSON.stringify(body)}:{})});
 const value=await r.json();if(!r.ok)throw new Error(value.reason||"Please try again.");return value;
}
const friendly={account_already_added:"This account is already added. Use Manage permissions to repair it.",install_your_agent_first:"Choose your AI tools first.",existing_skill_would_be_overwritten:"Another skill uses this name. Review it before installing Account Access.",browser_execution_failed:"The website is temporarily unavailable. Use Manage permissions to try again.",connection_not_completed:"Complete sign-in using Manage permissions.",password_not_connected:"Save the login for this account first."};
function problem(e){message(friendly[e.message]||"Setup needs attention: "+e.message);}
function text(tag,value){const n=document.createElement(tag);n.textContent=value;return n;}
function permission(){const choice=state.catalog.find(x=>x.id===el("service").value);el("permission").textContent=choice?"Allowed: "+choice.operations.map(x=>x.description).join("; "):"";}
function prompt(agent){return (agent==="codex"?"Use $account-access":"/account-access")+" to read one permitted operation from each connected account. Give me a short summary of each. Save progress as a task.";}
async function refresh(){
 state=await call("/owner/state");
 const existing=new Set(state.accounts.map(x=>x.account));
 const previous=el("service").value;el("service").replaceChildren();
 for(const item of state.catalog.filter(x=>!existing.has(x.id))){const option=text("option",item.label);option.value=item.id;el("service").append(option);}
 if([...el("service").options].some(x=>x.value===previous))el("service").value=previous;
 permission();el("account-form").hidden=!el("service").options.length;
 const haveClients=state.principals.some(x=>["codex","claude"].includes(x));
 el("connect").hidden=!haveClients;el("connected-section").hidden=!state.accounts.length;el("use").hidden=!state.accounts.some(x=>x.connected);
 el("connected").replaceChildren();
 for(const account of state.accounts){const card=document.createElement("div");card.className="account";const detail=document.createElement("div");detail.append(text("strong",account.label));const grants=state.grants.filter(x=>x.account===account.account);detail.append(text("span","Allowed tools: "+[...new Set(grants.map(x=>x.principal==="claude"?"Claude Code":"Codex"))].join(", ")));const status=text("span",account.connected?"✓ Connected":"Connecting…");status.className="badge"+(account.connected?"":" pending");const job=Object.values(state.connection_jobs).find(x=>x.account===account.account&&x.status!=="RUNNING"&&x.status!=="CONNECTED");if(job&&!account.connected){status.textContent="Sign-in needs attention";status.className="badge pending";}card.append(detail,status);el("connected").append(card);}
 el("prompts").replaceChildren();
 for(const agent of state.principals.filter(x=>["codex","claude"].includes(x))){const card=document.createElement("div");card.className="prompt";card.append(text("strong",agent==="claude"?"Claude Code":"Codex"));const p=text("p",prompt(agent));const b=text("button","Copy request");b.type="button";b.onclick=async()=>{try{await navigator.clipboard.writeText(p.textContent);b.textContent="Copied";}catch{message("Select the request text and copy it.");}};card.append(p,b);el("prompts").append(card);}
 if(Object.values(state.connection_jobs).some(x=>x.status==="RUNNING"))setTimeout(()=>refresh().catch(problem),1200);
}
el("service").onchange=permission;
el("stop").onclick=async()=>{if(!confirm("Stop Account Access? Your saved connections will be kept."))return;try{await call("/owner/stop",{});message("Account Access is stopped. Reopen the app to continue.");document.querySelectorAll("button,input,select").forEach(x=>x.disabled=true);}catch(e){problem(e);}};
el("manage").onclick=e=>{e.preventDefault();location.href="/manage#"+capability;};
el("install").onclick=async()=>{el("install").disabled=true;try{if(!selected().length)throw new Error("Choose at least one AI tool.");await call("/owner/install",{agents:selected()});message("Your AI tools are ready. Connect an account below.");await refresh();el("connect").scrollIntoView({behavior:"smooth",block:"start"});}catch(e){problem(e);}finally{el("install").disabled=false;}};
el("account-form").onsubmit=async e=>{e.preventDefault();el("add").disabled=true;try{if(!el("allow").checked)throw new Error("Choose the reads you want to allow.");await call("/owner/add",{service:el("service").value,username:el("username").value,password:el("password").value,agents:selected()});el("username").value="";el("password").value="";el("allow").checked=false;message("Signing in. You can connect another account while this finishes.");await refresh();}catch(e){problem(e);}finally{el("add").disabled=false;}};
if(capability)refresh().catch(problem);else message("Open Account Access from its launcher to unlock your setup page.");
