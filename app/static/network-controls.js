'use strict';
// A single speed mode prevents full-speed and manual-limit controls contradicting each other.
{
 const form=$('device-form'),actions=form.querySelector('.form-actions');
 const modeLabel=node('label','وضع السرعة'),mode=document.createElement('select');mode.id='device-speed-mode';
 for(const [value,label] of [['inherit','حسب الحساب أو الشبكة'],['limited','تحديد سرعة لهذا الجهاز'],['unlimited','سرعة كاملة بلا حد']]){const option=node('option',label);option.value=value;mode.append(option);}
 modeLabel.append(mode);form.insertBefore(modeLabel,actions);
 $('device-full').closest('label').hidden=true;$('device-inherit').closest('label').hidden=true;
 const explanation=node('p','','hint');explanation.id='device-speed-summary';form.insertBefore(explanation,actions);
 mode.onchange=()=>{$('device-full').checked=mode.value==='unlimited';$('device-inherit').checked=mode.value==='inherit';if(mode.value==='unlimited'){$('device-direct').checked=true;$('device-blocked').checked=false;}updateInheritance();};
 const boundLabel=node('label','ربط السماح بعنوان IP · اختياري'),bound=document.createElement('input');bound.type='text';bound.id='device-bound-ip';bound.placeholder='اتركه فارغًا للسماح حسب MAC';bound.autocomplete='off';bound.maxLength=15;boundLabel.append(bound);form.insertBefore(boundLabel,actions);
 const durationLabel=node('label','مدة السماح المباشر'),duration=document.createElement('select');duration.id='device-duration';for(const [value,label] of [['keep','الاحتفاظ بالمدة الحالية'],['0','سماح مفتوح'],['30','30 دقيقة من الآن'],['60','ساعة من الآن'],['1440','يوم من الآن']]){const option=node('option',label);option.value=value;duration.append(option);}durationLabel.append(duration);form.insertBefore(durationLabel,actions);
 const expiry=node('p','اختر جهازًا لعرض مدة السماح الحالية.','hint');expiry.id='device-expiry';form.insertBefore(expiry,actions);
 updateInheritance();
}
