"use strict";
const capability=location.hash.slice(1);
history.replaceState(null,"","/");
const el=id=>document.getElementById(id);
const message=text=>el("message").textContent=text;
let state=null;
async function call(path,body){
 const r=await fetch(path,{method:body?"POST":"GET",headers:{Authorization:"Bearer "+capability,...(body?{"Content-Type":"application/json"}:{})},...(body?{body:JSON.stringify(body)}:{})});
 const value=await r.json();if(!r.ok)throw new Error(value.reason||"Please try again.");return value;
}
const friendly={account_already_added:"This account is already added. Use Manage permissions to repair it.",install_your_agent_first:"Finish automatic setup first.",existing_skill_would_be_overwritten:"Another skill uses this name. Review it before installing Account Access.",browser_execution_failed:"The website is temporarily unavailable. Use Manage permissions to try again.",connection_not_completed:"Complete sign-in using Manage permissions.",password_not_connected:"Save the login for this account first."};
function problem(e){message(friendly[e.message]||"Setup needs attention: "+e.message);}
function text(tag,value){const n=document.createElement(tag);n.textContent=value;return n;}
function permission(){const choice=state.catalog.find(x=>x.id===el("service").value);el("permission").textContent=choice?"Allowed: "+choice.operations.map(x=>x.description).join("; "):"";}
let view="accounts";
let adding=false;
const labels={codex:"Codex",claude:"Claude Code"};
function prompt(){return "Give me a short summary of my connected accounts and save the results as one task.";}
function navigate(next){
 view=next;
 el("accounts-view").hidden=view!=="accounts";
 el("verification").hidden=view!=="verification";
 el("show-connect").hidden=view!=="accounts";
 el("page-title").textContent=view==="verification"?"Verification":"Your accounts";
 el("page-intro").textContent=view==="verification"?"Connect a code source once. Your AI handles supported login challenges.":"Keep using your AI. We handle supported sign-ins and approved reads.";
 document.querySelectorAll("[data-view]").forEach(b=>{const active=b.dataset.view===view;b.classList.toggle("active",active);if(active)b.setAttribute("aria-current","page");else b.removeAttribute("aria-current");});
}
document.querySelectorAll("[data-view]").forEach(b=>b.onclick=()=>navigate(b.dataset.view));
el("show-connect").onclick=()=>{adding=true;el("connect").hidden=false;el("connect").scrollIntoView({behavior:"smooth",block:"start"});};
el("import-nav").onclick=()=>{navigate("accounts");adding=true;el("connect").hidden=false;el("password-file").click();};
async function refresh(){
 state=await call("/owner/state");
 const existing=new Set(state.accounts.map(x=>x.account));
 const previous=el("service").value;el("service").replaceChildren();
 for(const item of state.catalog.filter(x=>!existing.has(x.id))){const option=text("option",item.label);option.value=item.id;el("service").append(option);}
 if([...el("service").options].some(x=>x.value===previous))el("service").value=previous;
 permission();el("account-form").hidden=!el("service").options.length;
 const haveClients=state.principals.includes("generic");
 const tools=(state.integrations||[]).filter(x=>labels[x]);
 const automatic=tools.length>0&&tools.every(x=>state.automatic_sessions?.[x]?.enabled===true);
 el("integration-title").textContent=automatic?"Ready in every new session":"Portable skill installed";
 el("agent-status").textContent=automatic?"Ask normally in "+tools.map(x=>labels[x]).join(" or ")+". No special command needed.":"The portable integration is installed. Open a new compatible AI session to use connected accounts.";
 el("automatic-status").textContent=automatic?"Automatic":"Portable skill ready";
 el("automatic-status").classList.toggle("pending",!automatic);
 el("service-status").textContent="Running on your computer";
 el("connect").hidden=!haveClients||(!adding&&state.accounts.length>0);
 el("connected-section").hidden=!state.accounts.length;
 const ready=state.accounts.filter(x=>x.connected&&x.portable_ready&&!x.challenges?.length);
 el("account-count").textContent=ready.length+" ready · "+state.accounts.length+" accounts";
 el("use").hidden=!ready.length;
 el("connected").replaceChildren();
 for(const account of state.accounts){
  const card=text("div","");card.className="account";const heading=text("div","");heading.className="account-heading";heading.append(text("strong",account.label));
  const available=account.connected&&account.portable_ready&&!account.challenges?.length;
  const status=text("span",!account.portable_ready?"Approval needed":available?"Connected":"Sign-in needs attention");status.className="badge"+(available?"":" pending");heading.append(status);card.append(heading);
  const operations=account.portable_ready?(account.approved_operations||[]):account.operations;
  card.append(text("p",(account.portable_ready?"Approved reads: ":"Available reads: ")+operations.map(x=>x.description).join("; ")));
  if(!available){const repair=text("a","Review access");repair.href="/manage";repair.onclick=e=>{e.preventDefault();location.href="/manage#"+capability;};card.append(repair);}
  el("connected").append(card);
 }
 el("prompts").replaceChildren();const example=text("div","");example.className="prompt";const p=text("p",prompt());const copy=text("button","Copy example");copy.type="button";copy.onclick=async()=>{try{await navigator.clipboard.writeText(p.textContent);copy.textContent="Copied";}catch{message("Select the example text to copy it.");}};example.append(p,copy);el("prompts").append(example);
 renderFactors();navigate(view);
 if(Object.values(state.connection_jobs).some(x=>x.status==="RUNNING"))setTimeout(()=>refresh().catch(problem),1200);
}
el("service").onchange=()=>{permission();el("allow").checked=false;el("username").value="";el("password").value="";};
el("stop").onclick=async()=>{if(!confirm("Stop Account Access? Your saved connections will be kept."))return;try{await call("/owner/stop",{});message("Account Access is paused. Open the app to resume it.");el("service-status").textContent="Paused";document.querySelectorAll("button,input,select").forEach(x=>x.disabled=true);}catch(e){problem(e);}};
el("manage").onclick=e=>{e.preventDefault();location.href="/manage#"+capability;};
el("account-form").onsubmit=async e=>{e.preventDefault();el("add").disabled=true;try{if(!el("allow").checked)throw new Error("Choose the reads you want to allow.");await call("/owner/add",{service:el("service").value,username:el("username").value,password:el("password").value,agents:["generic"]});el("username").value="";el("password").value="";el("allow").checked=false;message("Signing in. You can connect another account while this finishes.");await refresh();}catch(e){problem(e);}finally{el("add").disabled=false;}};
if(capability)call("/owner/install",{}).then(refresh).catch(problem);else message("Open Account Access from its launcher to unlock your setup page.");

let importPreview=null;
el("import-passwords").onclick=()=>{adding=true;el("password-file").click();};
el("password-file").onchange=async()=>{
 const file=el("password-file").files[0]; if(!file)return;
 try {if(file.size>4000000)throw new Error("password_file_too_large");importPreview=await call("/owner/import/preview",{csv:await file.text()});
 const review=el("import-review");review.replaceChildren();review.hidden=false;
 review.append(text("p","Select up to 32 logins and approve their reads. Selected saved logins will be replaced. Passwords are hidden."));
 const inputs=[];const importAuth=document.createElement("input");importAuth.type="checkbox";const authLabel=text("label","Also enroll included authenticator keys for supported login recovery");authLabel.prepend(importAuth);if(importPreview.rows.some(x=>x.has_authenticator))review.append(authLabel);
 for(const row of importPreview.rows.filter(x=>x.matches.length).slice(0,200)){
  const label=text("label",row.username+" · "+row.website);const check=document.createElement("input");check.type="checkbox";label.prepend(check);
  const select=document.createElement("select");for(const match of row.matches){const option=text("option",match.label+" — Allow: "+match.operations.map(x=>x.description).join("; "));option.value=match.id;select.append(option);}
  review.append(label,select);inputs.push({row,check,select});
 }
 review.append(text("p",importPreview.unsupported+" unsupported logins will not be saved. Delete the plaintext export after importing; this web page cannot delete your file."));
 const submit=text("button","Import selected accounts");submit.type="button";submit.onclick=async()=>{try{
 const selections=inputs.filter(x=>x.check.checked).map(x=>({row:x.row.id,account:x.select.value,operations:x.row.matches.find(m=>m.id===x.select.value).operations.map(o=>o.name),include_authenticator:importAuth.checked&&x.row.has_authenticator&&x.row.matches.find(m=>m.id===x.select.value).authenticator_supported}));
 await call("/owner/import/apply",{id:importPreview.id,selections});review.replaceChildren();review.hidden=true;importPreview=null;el("password-file").value="";message("Logins imported and encrypted. Enroll required verification below.");await refresh();
 }catch(e){problem(e);}};review.append(submit);
 }catch(e){problem(e);}
};
function renderFactors(){
 const container=el("factors");container.replaceChildren();
 for(const source of state.code_sources){
  const card=document.createElement("div");card.className="account";const kind={totp:"Authenticator",imap:"Email",gmail:"Gmail",twilio:"SMS gateway",mac_messages:"iPhone Messages",phone_relay:"Android phone"}[source.kind]||"Verification";card.append(text("strong",kind));card.append(text("p",source.accounts.map(id=>state.accounts.find(x=>x.account===id)?.label||id).join(", ")));const status=text("span",source.enrolled?"Connected":"One-time setup");status.className="badge"+(source.enrolled?"":" pending");card.append(status);
  const form=document.createElement("form");const fields={};
  const names=source.kind==="totp"?["seed"]:source.kind==="imap"?(source.mailbox_account?["username"]:["username","password"]):source.kind==="twilio"?["sid","auth_token"]:[];
  for(const name of names){const input=document.createElement("input");input.type=name==="username"?"text":"password";input.required=true;input.placeholder=name==="seed"?"Authenticator setup key or otpauth link":name==="password"?"Mailbox application password":name;input.setAttribute("aria-label",input.placeholder);fields[name]=input;form.append(input);}
  if(source.kind==="mac_messages")card.append(text("p","Enable iPhone text forwarding to this Mac and grant the signed Account Access app Full Disk Access in macOS privacy settings."));
  if(source.kind==="gmail")card.append(text("p","Connect the reviewed Gmail OAuth account in Manage permissions. Gmail consent grants mailbox read access."));
  const submit=text("button",source.enrolled?"Update verification":"Enable verification");submit.type="submit";form.append(submit);
  form.onsubmit=async event=>{event.preventDefault();try{const credential=Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,v.value]));if(source.kind==="mac_messages")credential.enabled=true;
  await call("/owner/source",{source:source.id,credential});Object.values(fields).forEach(x=>x.value="");for(const account of source.accounts)await call("/owner/verify",{account});message("Verification saved locally.");await refresh();}catch(e){problem(e);}};
  if(source.kind==="phone_relay"){const pair=text("button","Pair Android companion");pair.type="button";pair.onclick=async()=>{try{const result=await call("/owner/phone/pair",{source:source.id});await navigator.clipboard.writeText(JSON.stringify(result));message("Pairing copied. Paste into your Android companion on the same private Wi-Fi.");}catch(e){problem(e);}};card.append(pair);}
  if(source.enrolled){const disable=text("button","Disable verification");disable.type="button";disable.onclick=async()=>{try{await call("/owner/source/revoke",{source:source.id});await refresh();}catch(e){problem(e);}};card.append(disable);}
  card.append(form);container.append(card);
 }
 if(!state.code_sources.length){const empty=text("div","");empty.className="card";empty.append(text("h2","You’re all set"),text("p","Your current accounts do not need a verification code. Methods appear here when a supported account requires one."));container.append(empty);}
}
