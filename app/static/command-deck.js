'use strict';
window.addEventListener('moh:status',event=>{
 const data=event.detail,container=document.getElementById('deck-fleet');
 if(!container)return;
 document.getElementById('deck-clients').textContent=`${data.online_count??0} أجهزة نشطة`;
 document.getElementById('deck-wan').textContent=data.wan||'واجهة المصدر';
 const devices=(data.clients||[]).filter(d=>d.online).slice(0,5);
 const make=(tag,text,cls)=>{const e=document.createElement(tag);e.textContent=text;if(cls)e.className=cls;return e;};
 container.replaceChildren();
 for(const device of devices){
  const row=make('a',null,'fleet-device');row.href='#devices';
  const identity=make('div',null,'fleet-identity');
  identity.append(make('span',(device.name||'جهاز').slice(0,1),'fleet-avatar'),make('b',device.name||device.ip));
  row.append(identity,make('code',device.ip),make('span',device.policy?.blocked?'محظور':device.policy?.allowed?'مسموح':'بانتظار الدخول',device.policy?.blocked?'fleet-status denied':device.policy?.allowed?'fleet-status permitted':'fleet-status'),make('span','↖','fleet-arrow'));
  container.append(row);
 }
 if(!devices.length)container.append(make('p','لا توجد أجهزة نشطة مرصودة حاليًا.','empty'));
});
document.addEventListener('click',event=>{
 if(!event.target.closest('.nav-menu'))document.querySelectorAll('.nav-menu[open]').forEach(menu=>menu.open=false);
});
document.addEventListener('keydown',event=>{if(event.key==='Escape')document.querySelectorAll('.nav-menu[open]').forEach(menu=>menu.open=false);});
document.addEventListener('toggle',event=>{if(event.target.matches?.('.nav-menu')&&event.target.open)document.querySelectorAll('.nav-menu[open]').forEach(menu=>{if(menu!==event.target)menu.open=false;});},true);
