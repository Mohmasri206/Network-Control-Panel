'use strict';
const csrf = document.querySelector('meta[name="csrf-token"]').content;
let snapshot = null, busy = false, editingUntil = 0;
const $ = id => document.getElementById(id);
const text = (tag, value, cls) => { const el = document.createElement(tag); el.textContent = value; if(cls) el.className = cls; return el; };
const bytes = n => { let i=0; const units=['B','KB','MB','GB','TB']; while(n>=1024&&i<4){n/=1024;i++;} return `${n.toFixed(i?1:0)} ${units[i]}`; };
const rate = n => `${(n/1e6).toFixed(2)} Mbps`;
function notice(message, error=false){$('notice').hidden=false;$('notice').textContent=message;$('notice').className=error?'error':'';}
function renderDevices(){
  if(!snapshot)return;
  const query=$('search').value.toLowerCase(); const body=$('rows'); body.replaceChildren();
  for(const d of snapshot.clients){
    if(!`${d.ip} ${d.mac} ${d.name}`.toLowerCase().includes(query))continue;
    const p=d.policy||{}, tr=document.createElement('tr'), own=d.ip===snapshot.admin_ip;
    const identity=document.createElement('td'); identity.append(text('div',d.name||'جهاز بدون اسم','device-name'),text('div',d.ip,'device-address'),text('div',d.mac||'—','device-address mac'));
    if(own)identity.append(text('span','جهاز الإدارة','admin-tag')); tr.append(identity);
    const state=document.createElement('td');state.append(text('span',p.blocked?'محظور':(d.recent?'حديث الاتصال':'معروف'),`badge ${p.blocked?'blocked':(d.recent?'online':'')}`));tr.append(state);
    const usage=document.createElement('td');usage.append(text('div',`↓ ${bytes(d.down_bytes)}`,'metric'),text('div',`↑ ${bytes(d.up_bytes)}`,'metric'));tr.append(usage);
    tr.append(text('td',`${rate(d.down_bps)} / ${rate(d.up_bps)}`,'metric'));
    const inputs={};for(const key of ['down','up']){const td=document.createElement('td'),input=document.createElement('input');input.type='number';input.min='0';input.max='1000';input.step='0.1';input.value=p[key]||0;input.className='limit';input.disabled=own;input.setAttribute('aria-label',`${key==='down'?'حد التنزيل':'حد الرفع'} ${d.ip}`);input.addEventListener('input',()=>{editingUntil=Infinity;});td.append(input);tr.append(td);inputs[key]=input;}
    const actionCell=document.createElement('td'),group=document.createElement('div');group.className='actions';
    const save=text('button','حفظ','primary'),block=text('button',p.blocked?'فك الحظر':'حظر',p.blocked?'allow':'danger');save.disabled=block.disabled=own;
    save.onclick=()=>setPolicy(d.ip,!!p.blocked,inputs);block.onclick=()=>setPolicy(d.ip,!p.blocked,inputs);group.append(save,block);actionCell.append(group);tr.append(actionCell);body.append(tr);
  }
  if(!body.children.length){const tr=document.createElement('tr'),td=text('td','لا توجد أجهزة مطابقة');td.colSpan=7;tr.append(td);body.append(tr);}
}
function renderDNS(){if(!snapshot)return;const query=$('dns-search').value.toLowerCase(),body=$('dns-rows');body.replaceChildren();for(const row of snapshot.dns){if(!`${row.ip} ${row.domain}`.toLowerCase().includes(query))continue;const tr=document.createElement('tr');for(const key of ['time','ip','domain','type'])tr.append(text('td',row[key],key==='domain'?'dns-domain':''));body.append(tr);}if(!body.children.length){const tr=document.createElement('tr'),td=text('td','لا توجد استعلامات مطابقة في آخر جزء من السجل.');td.colSpan=4;tr.append(td);body.append(tr);}}
async function setPolicy(ip,blocked,inputs){
  if(busy)return;busy=true;
  try{const response=await fetch('/api/policy',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({ip,blocked,down:Number(inputs.down.value),up:Number(inputs.up.value)})});const result=await response.json();if(!response.ok)throw Error(result.error||'تعذّر الحفظ');editingUntil=0;notice(`تم تطبيق سياسة ${ip} وحفظها.`);await refresh(true);}catch(e){notice(e.message,true);}finally{busy=false;}
}
async function refresh(force=false){
  try{const response=await fetch('/api/status',{cache:'no-store'});if(response.status===401){location.href='/login';return;}const result=await response.json();if(!response.ok)throw Error(result.error||'تعذّر قراءة الحالة');snapshot=result;$('connection').textContent='متصل · تحديث كل 5 ثوانٍ';$('count').textContent=result.clients.length;$('recent').textContent=`${result.clients.filter(d=>d.recent).length} حديث الاتصال · ${result.clients.filter(d=>d.policy?.blocked).length} محظور`;$('download').textContent=bytes(result.download);$('upload').textContent=bytes(result.upload);$('health').textContent=`${Math.round(result.cpu)}% / ${Math.round(result.ram)}%`;$('uptime').textContent=`مدة التشغيل: ${Math.floor(result.uptime/86400)} يوم و${Math.floor(result.uptime%86400/3600)} ساعة`;
    if(force||(!document.activeElement?.closest('#rows')&&Date.now()>editingUntil))renderDevices();renderDNS();
  }catch(e){$('connection').textContent='تعذّر التحديث';notice(e.message,true);}
}
$('search').addEventListener('input',()=>{editingUntil=0;renderDevices();});$('dns-search').addEventListener('input',renderDNS);
refresh();setInterval(()=>{if(!busy&&!document.hidden)refresh();},5000);
