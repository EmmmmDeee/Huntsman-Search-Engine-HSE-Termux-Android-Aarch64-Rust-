import { $ } from '/static/js/helpers.js';
export function applyTheme(){
  // Dark is the base look (app.css's :root tokens) — `.light-theme` is an
  // explicit opt-out override block, applied only when chosen.
  const light = localStorage.getItem('theme') === 'light-theme';
  document.body.classList.toggle('light-theme', light);
  $('#theme-label').textContent = light ? 'Dark Mode' : 'Light Mode';
}
document.addEventListener('DOMContentLoaded', ()=>{
  $('#theme-toggle').addEventListener('click', e=>{
    e.preventDefault();
    const light = !document.body.classList.contains('light-theme');
    localStorage.setItem('theme', light ? 'light-theme' : 'dark-theme');
    applyTheme();
  });
});

