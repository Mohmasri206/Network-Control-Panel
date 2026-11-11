'use strict';
const copyField=document.getElementById('contact-copy-value'),copyStatus=document.getElementById('copy-status');
document.querySelectorAll('[data-copy]').forEach(button=>button.addEventListener('click',async()=>{
 const value=button.dataset.copy;let copied=false;
 if(navigator.clipboard&&window.isSecureContext){try{await navigator.clipboard.writeText(value);copied=true;}catch{}}
 if(!copied&&copyField){copyField.value=value;copyField.focus();copyField.select();copyField.setSelectionRange(0,value.length);try{copied=document.execCommand('copy');}catch{}}
 if(copyStatus)copyStatus.textContent=copied?'تم النسخ. يمكنك فتح واتساب ولصق الرقم أو الرابط.':'حدّد النص في الحقل وانسخه يدويًا، ثم افتح واتساب.';
}));
