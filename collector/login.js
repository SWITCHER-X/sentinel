// Login form submit handler (external so CSP can drop 'unsafe-inline').
document.getElementById('f').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const e = document.getElementById('e');
  const btn = document.getElementById('submit');
  e.textContent = '';
  btn.disabled = true;
  try {
    const r = await fetch('/api/v1/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('u').value,
        password: document.getElementById('p').value
      })
    });
    if (r.ok) { location.href = '/'; return; }
    const j = await r.json().catch(() => ({}));
    e.textContent = j.error || ('Sign-in failed (' + r.status + '). Try again.');
  } catch (err) {
    e.textContent = 'Cannot reach the hub. Check that sentinel-hub is running.';
  } finally {
    btn.disabled = false;
  }
});
