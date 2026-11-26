// Theme bootstrap: set data-theme before first paint so there is no flash.
// Loaded as a blocking classic script from <head>; kept out of the HTML so the
// page needs no 'unsafe-inline' in script-src.
(function () {
  try {
    var t = localStorage.getItem('sentinel-theme');
    if (!t) t = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) {}
})();
