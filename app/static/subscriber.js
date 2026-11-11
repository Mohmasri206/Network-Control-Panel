'use strict';
(()=>{
const embedded=document.getElementById('subscriber-data');if(!embedded)return;
let data=JSON.parse(embedded.textContent),offset=0;
const $=id=>document.getElementById(id),text=(id,value)=>{$(id).textContent=value;};
const types={account:'حساب مشترك',trial:'تجربة مجانية',direct:'إذن دخول مباشر',open:'شبكة مفتوحة',login:'تسجيل الدخول مطلوب',blocked:'الجهاز محظور',key:'اتصال مشفر مطلوب'};
const speed=n=>n?`${Number(n).toLocaleString('en-US')} Mbps`:'بلا حد';
const date=n=>n?new Intl.DateTimeFormat('ar-PS',{timeZone:'Asia/Hebron',dateStyle:'medium',timeStyle:'short'}).format(new Date(n*1000)):'غير مسجل';
function clock(){const now=(Date.now()+offset)/1000,remaining=Math.max(0,Math.ceil(data.expires-now));
 if(!data.expires){text('remaining-label',data.allowed?'مفتوحة':'غير مفعلة');text('remaining-note',data.allowed?'حتى إيقاف الإذن أو تسجيل الخروج':'سجّل الدخول لبدء الجلسة');$('session-progress').hidden=true;return;}
 text('remaining-label',`${String(Math.floor(remaining/3600)).padStart(2,'0')}:${String(Math.floor(remaining%3600/60)).padStart(2,'0')}:${String(remaining%60).padStart(2,'0')}`);
 text('remaining-note',remaining?'العداد متزامن مع وقت الخادم':'انتهى وقت الجلسة');
 const duration=data.expires-data.started;$('session-progress').hidden=!(data.started&&duration>0);if(data.started&&duration>0){$('session-progress').max=duration;$('session-progress').value=remaining;}}
function draw(value){data=value;offset=data.server_now*1000-Date.now();text('connection-label',data.allowed?'الإنترنت متاح':'الإنترنت غير متاح');$('connection-label').className='connection-badge'+(data.allowed?'':' offline');text('user-label',data.username||(data.kind==='trial'?'تجربة مجانية':'هذا الجهاز'));text('kind-label',types[data.kind]||'حالة الاتصال');text('down-limit',data.allowed?speed(data.down):'—');text('up-limit',data.allowed?speed(data.up):'—');text('ip-value',data.ip);text('mac-value',data.mac);text('started-value',date(data.started));text('expires-value',data.expires?date(data.expires):(data.allowed?'جلسة مفتوحة':'لا توجد جلسة'));
 text('scope-note',!data.allowed?'تسجيل الدخول مطلوب لاستعمال الإنترنت.':data.shared?`أنت ضمن مجموعة التجربة المشتركة: سقف المجموعة ${speed(data.pool_down)} تنزيل و${speed(data.pool_up)} رفع. السرعة المتاحة لجهازك تتغير حسب استخدام بقية أجهزة التجربة.`:'الحدود المعروضة هي حدود جهازك أو حسابك، والسرعة الفعلية تعتمد على المصدر.');
 $('subscriber-logout').hidden=!data.can_logout;$('subscriber-login').hidden=data.allowed;
 text('session-status-message',data.can_logout?((data.kind==='direct'||data.kind==='open')?'يمكن إنهاء جلسة الحساب، لكن الإنترنت سيبقى متاحًا بسبب إذن الدخول المباشر أو فتح الشبكة.':'تسجيل الخروج ينهي جلسة هذا الجهاز، ولا يمدد وقت التجربة المجانية.'):data.kind==='direct'?'جهازك لديه إذن دخول مباشر من المدير. لا توجد جلسة حساب لإنهائها هنا.':data.kind==='open'?'الشبكة مفتوحة حاليًا ولا تتطلب جلسة حساب.':'لا توجد جلسة إنترنت مفعّلة لهذا الجهاز.');clock();}
async function refresh(){try{const r=await fetch('/session-info',{cache:'no-store'}),v=await r.json();if(!r.ok)throw Error(v.error||'تعذر تحديث الحالة');draw(v);$('session-error').hidden=true;}catch(e){text('session-error',e.message);$('session-error').hidden=false;}}
$('status-refresh').addEventListener('click',refresh);draw(data);setInterval(clock,1000);setInterval(()=>{if(!document.hidden)refresh();},5000);
})();
