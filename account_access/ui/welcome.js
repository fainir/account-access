"use strict";
const capability=location.hash.slice(1);
history.replaceState(null,"","/");
const el=id=>document.getElementById(id);
const message=text=>el("message").textContent=text;
let state=null;
let healthTimer=null,healthBusy=false,locallyPaused=false;
async function call(path,body){
 const r=await fetch(path,{method:body?"POST":"GET",headers:{Authorization:"Bearer "+capability,...(body?{"Content-Type":"application/json"}:{})},...(body?{body:JSON.stringify(body)}:{})});
 const value=await r.json();if(!r.ok)throw new Error(value.reason||"Please try again.");return value;
}
const friendly={account_already_added:"This account is already added. Use Manage permissions to repair it.",install_your_agent_first:"Finish automatic setup first.",existing_skill_would_be_overwritten:"Another skill uses this name. Review it before installing Account Access.",browser_execution_failed:"The website is temporarily unavailable. Use Manage permissions to try again.",connection_not_completed:"Complete sign-in using Manage permissions.",password_not_connected:"Save the login for this account first."};
Object.assign(friendly,{mailbox_connection_failed:"The mail server did not accept this connection. Check the email address and application password.",mailbox_not_connected:"Reconnect this mailbox in Verification.",invalid_mailbox_setup:"Check the email address, TLS IMAP server, port and application password.",mailbox_already_connected:"This mailbox is already saved. Use Update app password or Check connection.",mailbox_source_mismatch:"Choose the mailbox for this website's approved email address and server."});
function problem(e){message(friendly[e.message]||"Setup needs attention: "+e.message);}
function text(tag,value){const n=document.createElement(tag);n.textContent=value;return n;}
function renderRecoveryHealth(health){
 if(locallyPaused)return;
 const recovery=health?.status;
 el("service-status").textContent=recovery==="RETRYING"?"Retrying background recovery":recovery==="STOPPED"?"Background recovery stopped":recovery==="UNAVAILABLE"?"Local app unavailable":recovery==="RUNNING"?"Running on your computer":"Local setup is open";
 const notice=el("recovery-health");notice.hidden=!["RETRYING","STOPPED","UNAVAILABLE"].includes(recovery);
 notice.textContent=recovery==="RETRYING"?"Background recovery hit an internal problem and is retrying automatically. Your saved connections and completed task steps are preserved.":recovery==="STOPPED"?"Background recovery stopped. Use Repair installation in the app menu to restart it. Your saved connections are preserved.":recovery==="UNAVAILABLE"?"Account Access is not responding. Open the app to reconnect.":"";
}
async function checkRecoveryHealth(){
 if(healthBusy||document.hidden||locallyPaused)return;
 healthBusy=true;
 try{renderRecoveryHealth(await call("/owner/health"));}catch{renderRecoveryHealth({status:"UNAVAILABLE"});}finally{healthBusy=false;}
}
function permission(){const choice=state.catalog.find(x=>x.id===el("service").value);el("permission").textContent=choice?"Allowed: "+choice.operations.map(x=>x.description).join("; "):"";}
let view="accounts";
let adding=false;
const labels={codex:"Codex",claude:"Claude Code"};
const isExample=account=>["controlled-demo","public-example"].includes(account.environment);
const isReady=account=>account.connected&&account.portable_ready&&!account.challenges?.length;
function prompt(){return state.accounts.some(x=>!isExample(x)&&isReady(x))?"Summarize the approved information from my connected services and save the results as one task.":state.accounts.some(x=>isExample(x)&&isReady(x))?"Try my connected example accounts and save the results as one task. Label the results as examples.":"Check which of my configured services are available and tell me what needs attention.";}
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
 renderRecoveryHealth(state.background_recovery);
 el("connect").hidden=!haveClients||(!adding&&state.accounts.length>0);
 el("connected-section").hidden=!state.accounts.length;
 const ready=state.accounts.filter(isReady),services=state.accounts.filter(x=>!isExample(x)),examples=state.accounts.filter(isExample);
 el("account-count").textContent=services.filter(isReady).length+" ready · "+services.length+" service connections"+(examples.length?" · "+examples.filter(isReady).length+" ready / "+examples.length+" examples":"");
 el("use").hidden=!ready.length;
 el("connected").replaceChildren();
 for(const account of state.accounts){
  const card=text("div","");card.className="account";const heading=text("div","");heading.className="account-heading";heading.append(text("strong",account.label));
  const available=isReady(account);
  const status=text("span",!account.portable_ready?"Approval needed":available?(isExample(account)?"Example connected":"Connected"):"Sign-in needs attention");status.className="badge"+(available?"":" pending");heading.append(status);card.append(heading);
  if(isExample(account))card.append(text("p",account.environment==="public-example"?"Public testing website. These results do not validate access to a personal account.":"Local test connection. These results do not validate access to a personal account."));
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
el("stop").onclick=async()=>{if(!confirm("Stop Account Access? Your saved connections will be kept."))return;try{await call("/owner/stop",{});locallyPaused=true;clearInterval(healthTimer);message("Account Access is paused. Open the app to resume it.");el("service-status").textContent="Paused";el("recovery-health").hidden=true;document.querySelectorAll("button,input,select").forEach(x=>x.disabled=true);}catch(e){problem(e);}};
el("manage").onclick=e=>{e.preventDefault();location.href="/manage#"+capability;};
el("account-form").onsubmit=async e=>{e.preventDefault();el("add").disabled=true;try{if(!el("allow").checked)throw new Error("Choose the reads you want to allow.");await call("/owner/add",{service:el("service").value,username:el("username").value,password:el("password").value,agents:["generic"]});el("username").value="";el("password").value="";el("allow").checked=false;message("Signing in. You can connect another account while this finishes.");await refresh();}catch(e){problem(e);}finally{el("add").disabled=false;}};
if(capability)call("/owner/install",{}).then(refresh).then(()=>{healthTimer=setInterval(checkRecoveryHealth,5000);document.addEventListener("visibilitychange",checkRecoveryHealth);}).catch(problem);else message("Open Account Access from its launcher to unlock your setup page.");

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
function renderMailboxes(container){
 for(const mailbox of state.mailboxes||[]){
  const card=text("div","");card.className="account";card.append(text("strong",mailbox.label+" · "+mailbox.username));
  const checked=mailbox.connection_check?.status==="VERIFIED";card.append(text("p",checked?"Mailbox connection checked. Website code delivery is checked separately.":"Setup saved. Check the address and application password."));
  const check=text("button","Check connection");check.type="button";check.onclick=async()=>{try{await call("/owner/mailbox/check",{id:mailbox.id});await refresh();}catch(e){problem(e);}};card.append(check);
  const edit=document.createElement("form");const password=document.createElement("input");password.type="password";password.required=true;password.placeholder="New mailbox application password";password.setAttribute("aria-label",password.placeholder);const update=text("button","Update app password");update.type="submit";edit.append(password,update);edit.onsubmit=async e=>{e.preventDefault();try{const value=password.value;password.value="";await call("/owner/mailbox/password",{id:mailbox.id,password:value});await refresh();}catch(error){problem(error);}};card.append(edit);
  const disconnect=text("button","Disconnect mailbox");disconnect.type="button";disconnect.onclick=async()=>{if(!confirm("Remove the saved mailbox password? Websites using it will pause when they next need an email code."))return;try{await call("/owner/mailbox/remove",{id:mailbox.id});await refresh();}catch(e){problem(e);}};card.append(disconnect);container.append(card);
 }
 const details=document.createElement("details");details.append(text("summary","Connect Gmail or email"));const form=document.createElement("form");const provider=document.createElement("select");provider.setAttribute("aria-label","Email provider");for(const label of ["Gmail","Other email · TLS IMAP"])provider.append(text("option",label));form.append(provider);const fields={};
 for(const [name,label] of [["username","Email address"],["password","Application password"],["host","IMAP server"],["port","TLS port"]]){const input=document.createElement("input");input.type=name==="password"?"password":name==="port"?"number":"text";input.required=true;input.placeholder=label;input.setAttribute("aria-label",label);fields[name]=input;form.append(input);}
 provider.onchange=()=>{const gmail=provider.selectedIndex===0;fields.host.value=gmail?"imap.gmail.com":"";fields.port.value="993";fields.host.readOnly=fields.port.readOnly=gmail;fields.host.hidden=fields.port.hidden=gmail;};provider.onchange();
 details.append(text("p","Create a Google app password for Account Access with 2-Step Verification enabled. If Google does not offer app passwords for your account, this connection is not supported yet."));const google=text("a","Open Google App passwords");google.href="https://myaccount.google.com/apppasswords";google.target="_blank";google.rel="noreferrer";details.append(google);const save=text("button","Connect mailbox");save.type="submit";form.append(save);form.onsubmit=async event=>{event.preventDefault();save.disabled=true;try{const payload=Object.fromEntries(Object.entries(fields).map(([key,input])=>[key,input.value]));payload.port=Number(payload.port);payload.label=provider.selectedIndex===0?"Gmail":"Email";fields.password.value="";await call("/owner/mailbox/connect",payload);message("Mailbox setup saved. Its connection result is shown below; no website sign-in was started.");await refresh();}catch(error){problem(error);}finally{save.disabled=false;}};details.append(form,text("p","Your app password grants mailbox access and is encrypted locally. Account Access uses read-only checks and matching login messages for approved sign-ins. Mailbox checks fetch no messages and start no website login."));container.append(details);
}
function renderFactors(){
 const container=el("factors");container.replaceChildren();
 renderMailboxes(container);
 for(const source of state.code_sources){
  const card=document.createElement("div");card.className="account";const kind={totp:"Authenticator",imap:"Email",gmail:"Gmail",twilio:"SMS gateway",mac_messages:"iPhone Messages",phone_relay:"Android phone"}[source.kind]||"Verification";card.append(text("strong",kind));card.append(text("p",source.accounts.map(id=>state.accounts.find(x=>x.account===id)?.label||id).join(", ")));const email=["imap","gmail"].includes(source.kind);const checked=source.connection_check?.status==="VERIFIED";const status=text("span",source.enrolled?(email&&checked?"Mailbox connection checked":"Setup saved"):"One-time setup");status.className="badge"+(source.enrolled?"":" pending");card.append(status);
  if(email&&source.enrolled){card.append(text("p",checked?"Email access passed its last check. Website code delivery is still a separate check.":"Saving these details does not verify email access or code delivery."));const check=text("button","Check email connection");check.type="button";check.onclick=async()=>{check.disabled=true;try{await call("/owner/source/check",{source:source.id});message("Mailbox connection checked. No messages fetched or website sign-in started.");await refresh();}catch(e){problem(e);}finally{check.disabled=false;}};card.append(check);}
  const form=document.createElement("form");const fields={};
  const names=source.kind==="totp"?["seed"]:source.kind==="imap"?(source.mailbox_account?["username"]:["username","password"]):source.kind==="twilio"?["sid","auth_token"]:[];
  let mailboxMenu=null;if(source.kind==="imap"&&!source.mailbox_account){const matching=(state.mailboxes||[]).filter(x=>x.host.toLowerCase()===source.mail_server?.toLowerCase()&&x.port===source.mail_port&&x.username.toLowerCase()===source.recipient?.toLowerCase());if(matching.length){mailboxMenu=document.createElement("select");mailboxMenu.setAttribute("aria-label","Use a connected mailbox");mailboxMenu.append(text("option","Enter mailbox details"));mailboxMenu.firstChild.value="";for(const mailbox of matching){const option=text("option",mailbox.username);option.value=mailbox.id;mailboxMenu.append(option);}mailboxMenu.value=source.linked_mailbox||"";form.append(mailboxMenu);}}
  for(const name of names){const input=document.createElement("input");input.type=name==="username"?"text":"password";input.required=true;input.placeholder=name==="seed"?"Authenticator setup key or otpauth link":name==="password"?"Mailbox application password":name;input.setAttribute("aria-label",input.placeholder);fields[name]=input;form.append(input);}
  if(mailboxMenu){if(!source.enrolled&&mailboxMenu.options.length===2){const saved=(state.mailboxes||[]).find(x=>x.id===mailboxMenu.options[1].value);if(saved?.connection_check?.status==="VERIFIED")mailboxMenu.selectedIndex=1;}mailboxMenu.onchange=()=>Object.values(fields).forEach(input=>{input.disabled=!!mailboxMenu.value;input.hidden=input.disabled;if(input.disabled)input.value="";});mailboxMenu.onchange();}
  if(source.kind==="mac_messages")card.append(text("p","Enable iPhone text forwarding to this Mac and grant the signed Account Access app Full Disk Access in macOS privacy settings."));
  if(source.kind==="gmail")card.append(text("p","Connect the reviewed Gmail OAuth account in Manage permissions. Gmail consent grants mailbox read access."));
  const submit=text("button",source.enrolled?"Update verification":"Enable verification");submit.type="submit";form.append(submit);
  form.onsubmit=async event=>{event.preventDefault();try{const credential=mailboxMenu?.value?{mailbox:mailboxMenu.value}:Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,v.value]));if(source.kind==="mac_messages")credential.enabled=true;
  await call("/owner/source",{source:source.id,credential});Object.values(fields).forEach(x=>x.value="");if(email)await call("/owner/source/check",{source:source.id});for(const account of source.accounts){const current=state.accounts.find(x=>x.account===account);if(!current?.challenges?.some(x=>["captcha","passkey","device","admin","action","recovery","unknown"].includes(x.kind)))await call("/owner/verify",{account});}message("Verification saved locally. Check each website's sign-in status below.");await refresh();}catch(e){problem(e);}};
  if(source.kind==="phone_relay"){const pair=text("button","Pair Android companion");pair.type="button";pair.onclick=async()=>{try{const result=await call("/owner/phone/pair",{source:source.id});await navigator.clipboard.writeText(JSON.stringify(result));message("Pairing copied. Paste into your Android companion on the same private Wi-Fi.");}catch(e){problem(e);}};card.append(pair);}
  if(source.enrolled){const disable=text("button","Disable verification");disable.type="button";disable.onclick=async()=>{try{await call("/owner/source/revoke",{source:source.id});await refresh();}catch(e){problem(e);}};card.append(disable);}
  card.append(form);container.append(card);
 }
 if(!state.code_sources.length){const empty=text("div","");empty.className="card";empty.append(text("h2","Connect a website"),text("p","You can save your mailbox now. Website verification methods appear after you connect a supported account."));container.append(empty);}
}
