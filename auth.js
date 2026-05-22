// auth.js – minimal client side auth for demo
// This script works with the Express backend defined in backend/server.js.
// It stores a JWT token in localStorage and redirects to admin.html on success.

(function () {
  const form = document.getElementById('loginForm');
  const msgEl = document.getElementById('msg');

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = form.email.value.trim();
      const password = form.password.value;
      try {
        const resp = await fetch('http://localhost:3000/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: email, password })
        });
        const data = await resp.json();
        if (resp.ok && data.token) {
          localStorage.setItem('authToken', data.token);
          window.location.href = 'admin.html';
        } else {
          showMessage(data.msg || 'Login failed', 'error');
        }
      } catch (err) {
        console.error(err);
        showMessage('Unable to reach server', 'error');
      }
    });
  }

  // Helper for admin page to guard access
  function guardAdmin() {
    const token = localStorage.getItem('authToken');
    if (!token) {
      window.location.href = 'login.html';
    }
  }

  // Logout function used by admin.html
  window.logout = function () {
    localStorage.removeItem('authToken');
    window.location.href = 'login.html';
  };

  // Simple toast/message display
  function showMessage(text, type) {
    if (!msgEl) return;
    msgEl.textContent = text;
    msgEl.style.color = type === 'error' ? '#ff6b6b' : '#90ee90';
    setTimeout(() => { msgEl.textContent = ''; }, 3000);
  }

  // Expose guard for admin page
  window.guardAdmin = guardAdmin;
})();
