// Applies the saved theme before the page paints (kept in its own file so the
// Content-Security-Policy can block all inline scripts).
try {
  var t = localStorage.getItem('theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', t);
} catch (e) {}
