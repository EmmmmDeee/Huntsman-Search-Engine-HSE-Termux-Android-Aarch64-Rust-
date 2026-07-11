import { $ } from '/static/js/helpers.js';
export function applyTheme(){
  // SpiderFoot-compatible: dark is the default; only opt out explicitly.
  const stored = localStorage.getItem('theme');
  const dark = stored !== 'light-theme';
  document.body.classList.toggle('dark-theme', dark);
  $('#theme-label').textContent = dark ? 'Light Mode' : 'Dark Mode';
}
document.addEventListener('DOMContentLoaded', ()=>{
  $('#theme-toggle').addEventListener('click', e=>{
    e.preventDefault();
    const dark = !document.body.classList.contains('dark-theme');
    localStorage.setItem('theme', dark ? 'dark-theme' : 'light-theme');
    applyTheme();
  });
});

