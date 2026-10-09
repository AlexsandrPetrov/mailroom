// Вход администратора: пароль, затем (если включена) код 2FA.
const form = document.getElementById('login-form');
const errorBox = document.getElementById('login-error');
const otpField = document.getElementById('otp-field');
let stage = 'password';

function showError(text) {
  errorBox.textContent = text;
  errorBox.classList.remove('hidden');
}

async function post(url, body) {
  const response = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
  let data = {};
  try { data = await response.json(); } catch (e) { /* пустой ответ */ }
  return {ok: response.ok, data};
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.classList.add('hidden');
  const fields = Object.fromEntries(new FormData(form));
  const button = form.querySelector('button');
  button.disabled = true;
  try {
    if (stage === 'password') {
      const {ok, data} = await post('/api/auth/login', {username: fields.username, password: fields.password});
      if (!ok) return showError(data.error || 'Ошибка входа');
      if (data.status === 'requires_2fa') {
        stage = 'otp';
        otpField.classList.remove('hidden');
        form.username.disabled = true;
        form.password.disabled = true;
        form.otp.required = true;
        form.otp.focus();
        return;
      }
    } else {
      const {ok, data} = await post('/api/auth/verify-2fa', {otp: fields.otp});
      if (!ok) {
        if (/истекло/.test(data.error || '')) location.reload();
        return showError(data.error || 'Неверный код');
      }
    }
    location.href = '/';
  } catch (e) {
    showError('Сервер недоступен');
  } finally {
    button.disabled = false;
  }
});
