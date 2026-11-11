'use strict';
// Native form navigation retains server-rendered errors and CSRF validation.
// Give immediate feedback; never duplicate an in-flight authentication request.
(()=>{
const snapshots=new Map();
function restore(){for(const [form,items] of snapshots){form.removeAttribute('aria-busy');delete form.dataset.submitting;for(const item of items){item.button.disabled=item.disabled;item.button.textContent=item.text;}const note=form.querySelector('.submit-feedback');if(note)note.remove();}snapshots.clear();}
document.querySelectorAll('form[method="post"]').forEach(form=>form.addEventListener('submit',event=>{
 if(event.defaultPrevented)return;
 if(form.dataset.submitting==='1'){event.preventDefault();return;}
 form.dataset.submitting='1';form.setAttribute('aria-busy','true');
 const items=[...form.querySelectorAll('button[type="submit"],button:not([type]),input[type="submit"]')].map(button=>({button,disabled:button.disabled,text:button.textContent}));snapshots.set(form,items);
 const action=form.getAttribute('action')||'',message=action.includes('logout')?'جارٍ تسجيل الخروج…':action.includes('trial')?'جارٍ تفعيل التجربة…':'جارٍ تسجيل الدخول…';
 for(const item of items){item.button.disabled=true;item.button.textContent=message;}
 const note=document.createElement('p');note.className='submit-feedback';note.setAttribute('role','status');note.textContent='انتظر اكتمال الطلب.';form.append(note);
 setTimeout(()=>{if(form.dataset.submitting==='1'&&note.isConnected)note.textContent='الطلب ما زال قيد التنفيذ. لا حاجة للضغط مجددًا.';},6000);
}));
window.addEventListener('pageshow',restore);
})();
