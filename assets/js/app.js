async function copyText(txt){
  try { await navigator.clipboard.writeText(txt); alert("Copied ✅"); }
  catch(e){ prompt("Copy:", txt); }
}
