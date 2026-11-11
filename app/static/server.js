'use strict';
const el=id=>document.getElementById(id);
const size=n=>`${(n/1073741824).toFixed(1)} GB`;
function node(tag,text,cls){const n=document.createElement(tag);n.textContent=text;if(cls)n.className=cls;return n;}
const names={smbd:'مشاركة الملفات · Samba',xrdp:'سطح المكتب · RDP',ssh:'إدارة الجهاز · SSH','share-internet':'مشاركة الإنترنت','kali-net-panel':'لوحة MOH'};
function paint(d){
 el('cpu').textContent=`${Math.round(d.cpu)}%`;el('cpu-bar').value=d.cpu;
 el('memory').textContent=`${Math.round(d.memory.percent)}%`;el('memory-bar').value=d.memory.percent;
 el('memory-detail').textContent=`${size(d.memory.used)} / ${size(d.memory.total)}`;
 el('temperature').textContent=d.temperature===null?'غير متاحة':`${Math.round(d.temperature)}°C`;
 el('uptime').textContent=`${Math.floor(d.uptime/86400)} يوم · ${Math.floor(d.uptime%86400/3600)} ساعة`;
 el('disks').replaceChildren();
 for(const disk of d.disks){const box=node('div','','disk'),row=node('div','','row');row.append(node('b',disk.mount),node('code',disk.device));const bar=document.createElement('progress');bar.max=100;bar.value=disk.percent;box.append(row,bar,node('small',`${size(disk.used)} مستخدم من ${size(disk.total)} · ${disk.percent}% · ${disk.filesystem}`));el('disks').append(box);}
 if(!d.disks.length)el('disks').textContent='لا توجد أقراص مركبة متاحة للقراءة.';
 el('services-list').replaceChildren();
 for(const [key,value] of Object.entries(d.services)){const row=node('div','','service');row.append(node('span',names[key]||key),node('span',value==='active'?'تعمل':value==='inactive'?'متوقفة':value==='failed'?'فشلت':value==='unknown'?'تعذر الفحص':'غير مفعلة',`state ${value==='active'?'on':''}`));el('services-list').append(row);}
 el('desktop-state').textContent=d.services.xrdp==='active'?'تعمل؛ يلزم التحقق من صلاحيات الوصول':'تحتاج إعدادًا على كالي';
 el('warnings').replaceChildren(...(d.warnings.length?d.warnings.map(w=>node('p',w,'warning')):[node('p','لا توجد تنبيهات مساحة أو ذاكرة في آخر قراءة.')]));
 el('updated').textContent=`آخر قراءة ${new Date(d.sampled_at*1000).toLocaleTimeString('ar')} · تحديث كل 30 ثانية`;
}
async function refresh(){if(document.hidden)return;try{const r=await fetch('/api/server/health',{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});if(r.status===401){location.href='/login';return;}if(!r.ok)throw Error();paint(await r.json());el('connection').textContent='متصل بالخادم';}catch{el('connection').textContent='تعذر الاتصال · القراءات قديمة';el('warnings').replaceChildren(node('p','تعذر جلب حالة الجهاز. افتح الصفحة من لوحة MOH المثبتة على كالي.','warning'));}}
refresh();setInterval(refresh,30000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
