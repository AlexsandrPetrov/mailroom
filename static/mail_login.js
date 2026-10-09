'use strict';
const form = document.getElementById('login-form');
const errorBox = document.getElementById('login-error');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.classList.add('hidden');
  const button = form.querySelector('button');
  button.disabled = true;
  try {
    const response = await fetch('/api/mail/login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Не удалось войти');
    location.href = '/mail';
  } catch (e) {
    errorBox.textContent = e.message === 'Failed to fetch' ? 'Сервер недоступен' : e.message;
    errorBox.classList.remove('hidden');
  } finally {
    button.disabled = false;
  }
});
