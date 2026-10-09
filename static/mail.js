// Mailroom Mail Client JavaScript

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

let currentFolder = 'INBOX';
let currentPage = 1;
let currentPassword = '';
let selectedMessages = new Set();
let currentMessageId = null;

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' Б';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' КБ';
  return (bytes / (1024 * 1024)).toFixed(1) + ' МБ';
}

async function getPassword() {
  if (currentPassword) return currentPassword;
  return new Promise((resolve) => {
    const modal = $('#password-modal');
    const form = $('#password-form');
    modal.showModal();
    form.onsubmit = (e) => {
      e.preventDefault();
      const data = new FormData(form);
      currentPassword = data.get('password');
      modal.close();
      resolve(currentPassword);
    };
    modal.onclose = () => resolve('');
  });
}

async function apiCall(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken,
    ...(options.headers || {})
  };
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    currentPassword = '';
    return apiCall(path, options);
  }
  return response;
}

async function loadFolders() {
  try {
    const password = await getPassword();
    if (!password) return;
    const response = await apiCall(`/api/client/mail/folders?password=${encodeURIComponent(currentPassword)}`);
    const data = await response.json();
    if (data.folders) {
      renderFolders(data.folders);
    }
  } catch (e) {
    console.error('Failed to load folders:', e);
  }
}

function renderFolders(folders) {
  const container = $('#mail-folders .folder-section');
  const standardFolders = ['INBOX', 'Sent', 'Drafts', 'Trash', 'Spam'];
  const folderIcons = {
    'INBOX': '📥', 'Sent': '📤', 'Drafts': '📝', 'Trash': '🗑', 'Spam': '🚫'
  };
  const folderNames = {
    'INBOX': 'Входящие', 'Sent': 'Отправленные', 'Drafts': 'Черновики', 'Trash': 'Корзина', 'Spam': 'Спам'
  };

  container.innerHTML = '<span class="folder-section-title">Папки</span>' +
    standardFolders.map(f => `
      <button class="folder-item ${f === currentFolder ? 'active' : ''}" data-folder="${f}">
        <span class="folder-icon">${folderIcons[f] || '📁'}</span>
        <span class="folder-name">${folderNames[f] || f}</span>
        <span class="folder-count" id="count-${f}">0</span>
      </button>
    `).join('') +
    folders.filter(f => !standardFolders.includes(f)).map(f => `
      <button class="folder-item ${f === currentFolder ? 'active' : ''}" data-folder="${f}">
        <span class="folder-icon">📁</span>
        <span class="folder-name">${f}</span>
        <span class="folder-count" id="count-${f}">0</span>
      </button>
    `).join('');

  $$('.folder-item').forEach(btn => {
    btn.addEventListener('click', () => switchFolder(btn.dataset.folder));
  });
}

async function switchFolder(folder) {
  currentFolder = folder;
  currentPage = 1;
  $$('.folder-item').forEach(btn => btn.classList.toggle('active', btn.dataset.folder === folder));
  await loadMessageList();
}

async function loadMessageList() {
  const password = await getPassword();
  if (!password) return;

  const tbody = $('#mail-list-body');
  tbody.innerHTML = '<tr class="loading-row"><td colspan="7">Загрузка писем...</td></tr>';
  $('#mail-empty').style.display = 'none';

  try {
    const params = new URLSearchParams({
      password: currentPassword,
      folder: currentFolder,
      page: currentPage,
      per_page: 20,
      search: $('#search-input').value
    });
    const response = await apiCall(`/api/client/mail/list?${params}`);
    const data = await response.json();

    if (data.messages && data.messages.length > 0) {
      renderMessageList(data.messages);
      updatePagination(data);
      $('#mail-list-container').style.display = 'block';
      $('#mail-empty').style.display = 'none';
    } else {
      $('#mail-list-container').style.display = 'none';
      $('#mail-empty').style.display = 'flex';
    }
  } catch (e) {
    console.error('Failed to load messages:', e);
    tbody.innerHTML = '<tr class="error-row"><td colspan="7">Ошибка загрузки писем</td></tr>';
  }
}

function renderMessageList(messages) {
  const tbody = $('#mail-list-body');
  tbody.innerHTML = messages.map(msg => `
    <tr class="message-row ${msg.unread ? 'unread' : ''}" data-id="${msg.id}">
      <td class="col-checkbox"><input type="checkbox" class="msg-checkbox" value="${msg.id}"></td>
      <td class="col-star">${msg.flags?.includes('\\Flagged') ? '★' : '☆'}</td>
      <td class="col-from">${escapeHtml(msg.from)}</td>
      <td class="col-subject">
        <span class="subject-text">${escapeHtml(msg.subject)}</span>
        ${msg.has_attachments ? '<span class="attachment-icon" title="Есть вложения">📎</span>' : ''}
      </td>
      <td class="col-date">${msg.date_str || ''}</td>
      <td class="col-size">${formatSize(msg.size)}</td>
      <td class="col-attach">${msg.has_attachments ? '📎' : ''}</td>
    </tr>
  `).join('');

  $$('.msg-checkbox').forEach(cb => {
    cb.addEventListener('change', (e) => {
      const id = e.target.value;
      if (e.target.checked) selectedMessages.add(id);
      else selectedMessages.delete(id);
      updateSelectionUI();
    });
  });

  $$('.message-row').forEach(row => {
    row.addEventListener('click', (e) => {
      if (e.target.type === 'checkbox') return;
      const id = row.dataset.id;
      if (e.shiftKey && currentMessageId) {
        // Range selection
        const rows = Array.from($$('#mail-list-body .message-row'));
        const start = rows.findIndex(r => r.dataset.id === currentMessageId);
        const end = rows.findIndex(r => r.dataset.id === id);
        const [min, max] = [Math.min(start, end), Math.max(start, end)];
        rows.slice(min, max + 1).forEach(r => {
          const cb = r.querySelector('.msg-checkbox');
          cb.checked = true;
          selectedMessages.add(r.dataset.id);
        });
        updateSelectionUI();
      } else {
        currentMessageId = id;
        loadMessage(id);
      }
    });
  });
}

function updateSelectionUI() {
  const count = selectedMessages.size;
  $$('.msg-checkbox').forEach(cb => cb.checked = selectedMessages.has(cb.value));
  $('#select-all').checked = count > 0 && count === $$('.msg-checkbox').length;
  $('#delete-btn').textContent = count ? `🗑 Удалить (${count})` : '🗑 Удалить';
}

function updatePagination(data) {
  $('#page-info').textContent = `${data.page} / ${data.pages || 1}`;
  $('#prev-page').disabled = data.page <= 1;
  $('#next-page').disabled = data.page >= (data.pages || 1);
}

async function loadMessage(msgId) {
  const password = await getPassword();
  if (!password) return;

  try {
    const response = await apiCall(`/api/client/mail/message/${msgId}?password=${encodeURIComponent(currentPassword)}&folder=${currentFolder}`);
    const msg = await response.json();
    renderMessage(msg);
  } catch (e) {
    console.error('Failed to load message:', e);
  }
}

function renderMessage(msg) {
  const reader = $('#mail-reader');
  const placeholder = $('.reader-placeholder');
  const content = $('#reader-content');

  placeholder.style.display = 'none';
  content.style.display = 'block';

  $('#message-subject').textContent = msg.subject;
  $('#message-from').textContent = msg.from;
  $('#message-date').textContent = msg.date_str || msg.date;
  $('#message-to').textContent = msg.to ? `Кому: ${msg.to}` : '';
  if (msg.cc) {
    $('#message-to').textContent += ` | Копия: ${msg.cc}`;
  }

  if (msg.body_html) {
    $('#message-body').innerHTML = sanitizeHtml(msg.body_html);
  } else {
    $('#message-body').textContent = msg.body_text || '';
  }

  renderAttachments(msg.attachments);
  currentMessageId = msg.id;

  $('#reply-btn').onclick = () => openCompose({ replyTo: msg });
  $('#reply-all-btn').onclick = () => openCompose({ replyAll: msg });
  $('#forward-btn').onclick = () => openCompose({ forward: msg });
  $('#delete-btn').onclick = () => deleteMessages([msg.id]);
}

function renderAttachments(attachments) {
  const container = $('#message-attachments');
  if (!attachments || attachments.length === 0) {
    container.style.display = 'none';
    return;
  }
  container.style.display = 'block';
  container.innerHTML = '<h4>Вложения:</h4>' + attachments.map((att, i) => `
    <div class="attachment-item">
      <span class="attachment-icon">${getFileIcon(att.filename)}</span>
      <span class="attachment-name">${escapeHtml(att.filename)}</span>
      <span class="attachment-size">${formatSize(att.size)}</span>
      <button class="icon-button download-att" data-index="${i}">⬇</button>
    </div>
  `).join('');

  $$('.download-att').forEach(btn => {
    btn.onclick = () => downloadAttachment(currentMessageId, parseInt(btn.dataset.index));
  });
}

function getFileIcon(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const icons = {
    pdf: '📄', doc: '📄', docx: '📄', txt: '📄',
    xls: '📊', xlsx: '📊', csv: '📊',
    jpg: '🖼', jpeg: '🖼', png: '🖼', gif: '🖼', webp: '🖼',
    zip: '📦', rar: '📦', '7z': '📦',
    mp3: '🎵', wav: '🎵', mp4: '🎬', mov: '🎬',
  };
  return icons[ext] || '📄';
}

function sanitizeHtml(html) {
  const div = document.createElement('div');
  div.innerHTML = html;
  // Remove scripts and event handlers
  $$('script', div).forEach(s => s.remove());
  $$('[onclick]', div).forEach(el => el.removeAttribute('onclick'));
  $$('[onload]', div).forEach(el => el.removeAttribute('onload'));
  $$('[onerror]', div).forEach(el => el.removeAttribute('onerror'));
  return div.innerHTML;
}

function openCompose({ replyTo, replyAll, forward } = {}) {
  const modal = $('#compose-modal');
  const form = $('#compose-form');
  form.reset();
  $$('#attached-files').innerHTML = '';

  if (replyTo) {
    $('#compose-title').textContent = 'Ответ';
    $('#compose-form [name="to"]').value = replyTo.from;
    $('#compose-form [name="subject"]').value = 'Re: ' + $('#message-subject').textContent;
    $('#compose-in-reply-to').value = currentMessageId;
    $('#compose-references').value = ($('#message-id').value || '') + ' ' + currentMessageId;
    $('#compose-message-id').value = '';
    // Pre-fill body with quoted text
    const quotedText = '\n\n---\n' + $('#message-body').textContent.split('\n').map(l => '> ' + l).join('\n');
    $('#compose-editor').value = quotedText;
  } else if (forward) {
    $('#compose-title').textContent = 'Пересылка';
    $('#compose-form [name="subject"]').value = 'Fwd: ' + $('#message-subject').textContent;
    // Include original message
  } else {
    $('#compose-title').textContent = 'Новое письмо';
  }

  modal.showModal();
}

function closeCompose() {
  $('#compose-modal').close();
  $('#compose-form').reset();
  $$('#attached-files').innerHTML = '';
  $('#compose-in-reply-to').value = '';
  $('#compose-references').value = '';
  $('#compose-message-id').value = '';
  $('#compose-password').value = '';
}

function setupCompose() {
  const form = $('#compose-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const submitter = e.submitter;
    const isDraft = submitter.id === 'save-draft';

    const password = await getPassword();
    if (!password) return;

    const formData = new FormData(form);
    formData.append('password', currentPassword);

    try {
      const response = await fetch('/api/client/mail/send', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrfToken },
        body: formData
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error);
      alert('Письмо отправлено');
      $('#compose-modal').close();
      await loadMessageList();
    } catch (e) {
      alert('Ошибка отправки: ' + e.message);
    }
  });

  // Attachments
  $('#attachments-input').addEventListener('change', (e) => {
    const container = $$('#attached-files')[0];
    container.innerHTML = '';
    Array.from(e.target.files).forEach((file, i) => {
      const div = document.createElement('div');
      div.className = 'attached-file';
      div.innerHTML = `<span>${file.name}</span> <span>(${formatSize(file.size)})</span> <button type="button" class="icon-button" data-index="${i}">✕</button>`;
      div.querySelector('button').onclick = () => {
        div.remove();
        // Note: Can't easily remove from FormData, would need rebuild
      };
      container.appendChild(div);
    });
  });

  $('#compose-modal').addEventListener('close', closeCompose);
}

async function deleteMessages(ids) {
  if (!confirm(`Удалить ${ids.length} писем?`)) return;
  const password = await getPassword();
  if (!password) return;

  try {
    const formData = new FormData();
    formData.append('password', currentPassword);
    ids.forEach(id => formData.append('msg_ids', id));
    formData.append('folder', 'Trash');

    const response = await fetch('/api/client/mail/move', {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken },
      body: formData
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    selectedMessages.clear();
    updateSelectionUI();
    await loadMessageList();
  } catch (e) {
    alert('Ошибка удаления: ' + e.message);
  }
}

async function markRead(ids, read = true) {
  const password = await getPassword();
  if (!password) return;

  try {
    const formData = new FormData();
    formData.append('password', currentPassword);
    ids.forEach(id => formData.append('msg_ids', id));
    formData.append('flag', '\\Seen');
    formData.append('action', read ? 'add' : 'remove');

    const response = await fetch('/api/client/mail/flags', {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken },
      body: formData
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    await loadMessageList();
  } catch (e) {
    console.error('Failed to mark messages:', e);
  }
}

async function downloadAttachment(msgId, index) {
  window.location.href = `/api/client/mail/attachment/${msgId}/${index}?password=${encodeURIComponent(currentPassword)}&folder=${currentFolder}`;
}

function initMailClient() {
  // Check auth
  const auth = await fetch('/api/client/me');
  if (!auth.ok) {
    location.href = '/client/login';
    return;
  }
  const me = await auth.json();
  $('#mail-address').textContent = me.address;

  // Load folders and messages
  await loadFolders();
  await loadMessageList();

  // Event listeners
  $('#search-input').addEventListener('input', debounce(() => {
    currentPage = 1;
    loadMessageList();
  }, 300));

  $('#refresh-btn').addEventListener('click', loadMessageList);
  $('#prev-page').addEventListener('click', () => {
    if (currentPage > 1) { currentPage--; loadMessageList(); }
  });
  $('#next-page').addEventListener('click', () => {
    currentPage++;
    loadMessageList();
  });
  $('#select-all').addEventListener('change', (e) => {
    $$('.msg-checkbox').forEach(cb => {
      cb.checked = e.target.checked;
      if (e.target.checked) selectedMessages.add(cb.value);
      else selectedMessages.delete(cb.value);
    });
    updateSelectionUI();
  });

  $('#compose-btn').addEventListener('click', () => openCompose({}));
  $('#mail-logout').addEventListener('click', async () => {
    await fetch('/api/client/logout', { method: 'POST' });
    location.href = '/client/login';
  });

  setupCompose();
  loadMessageList();
}

function debounce(fn, delay) {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn(...args), delay);
  };
}

// Initialize when DOM ready
document.addEventListener('DOMContentLoaded', initMailClient);