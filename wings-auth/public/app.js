/* ═══════════════════════════════════════════════════════════
   Wings for Growth – Auth App
   Backend: localStorage  |  Password hashing: Web Crypto PBKDF2
   ═══════════════════════════════════════════════════════════ */

/* ── CRYPTO ─────────────────────────────────────────────── */
async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256
  );
  const toHex = a => [...new Uint8Array(a)].map(b => b.toString(16).padStart(2,'0')).join('');
  return `pbkdf2:${toHex(salt.buffer)}:${toHex(bits)}`;
}

async function verifyPassword(password, stored) {
  const [, saltHex, hashHex] = stored.split(':');
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const enc  = new TextEncoder();
  const key  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256
  );
  const computed = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2,'0')).join('');
  return computed === hashHex;
}

function genId()    { return crypto.randomUUID(); }
function genToken() { return [...crypto.getRandomValues(new Uint8Array(32))].map(b=>b.toString(16).padStart(2,'0')).join(''); }

/* ── LOCAL STORAGE LAYER ─────────────────────────────────── */
const DB = {
  users:    () => JSON.parse(localStorage.getItem('wfg_users')   || '[]'),
  tokens:   () => JSON.parse(localStorage.getItem('wfg_tokens')  || '{}'),
  save:     (k, v) => localStorage.setItem(k, JSON.stringify(v)),
  session:  () => JSON.parse(sessionStorage.getItem('wfg_session') || 'null'),
  setSession: d  => sessionStorage.setItem('wfg_session', JSON.stringify(d)),
  clearSession:  () => sessionStorage.removeItem('wfg_session'),
};

/* ── SEED DEMO USER (once) ───────────────────────────────── */
async function seedDemo() {
  const users = DB.users();
  if (users.length === 0) {
    users.push({
      id: genId(),
      name: 'Demo Mentor',
      email: 'mentor@example.com',
      passwordHash: await hashPassword('Mentor@123'),
      createdAt: new Date().toISOString(),
    });
    DB.save('wfg_users', users);
  }
}

/* ── AUTH FUNCTIONS ──────────────────────────────────────── */
async function authLogin(email, password) {
  const user = DB.users().find(u => u.email === email.toLowerCase().trim());
  if (!user) return { success: false, message: 'Invalid email or password.' };
  const ok = await verifyPassword(password, user.passwordHash);
  if (!ok)  return { success: false, message: 'Invalid email or password.' };
  DB.setSession({ userId: user.id, email: user.email, name: user.name });
  return { success: true, user };
}

async function authRegister(name, email, password) {
  if (password.length < 8) return { success: false, message: 'Password must be at least 8 characters.' };
  const users = DB.users();
  if (users.find(u => u.email === email.toLowerCase().trim()))
    return { success: false, message: 'An account with this email already exists.' };
  const u = { id: genId(), name: name.trim(), email: email.toLowerCase().trim(),
              passwordHash: await hashPassword(password), createdAt: new Date().toISOString() };
  users.push(u);
  DB.save('wfg_users', users);
  DB.setSession({ userId: u.id, email: u.email, name: u.name });
  return { success: true, user: u };
}

function authForgotPassword(email) {
  const emailLow = email.toLowerCase().trim();
  const user     = DB.users().find(u => u.email === emailLow);
  const tokens   = DB.tokens();
  const now      = Date.now();
  Object.keys(tokens).forEach(t => { if (tokens[t].expires < now) delete tokens[t]; });
  let token = null;
  if (user) {
    token = genToken();
    tokens[token] = { email: emailLow, expires: now + 15 * 60 * 1000 };
    DB.save('wfg_tokens', tokens);
  }
  return { success: true, resetToken: token };
}

async function authResetPassword(token, password) {
  if (password.length < 8) return { success: false, message: 'Password must be at least 8 characters.' };
  const tokens = DB.tokens();
  const data   = tokens[token];
  if (!data || data.expires < Date.now()) return { success: false, message: 'Invalid or expired reset token.' };
  const users = DB.users();
  const idx   = users.findIndex(u => u.email === data.email);
  if (idx === -1) return { success: false, message: 'User not found.' };
  users[idx].passwordHash = await hashPassword(password);
  DB.save('wfg_users', users);
  delete tokens[token];
  DB.save('wfg_tokens', tokens);
  return { success: true };
}

/* ── STATE ──────────────────────────────────────────────── */
let resetToken = null;
let resetEmail = '';
let loginCountdownTimer = null;
let pwCountdownTimer    = null;

/* ── VIEW SWITCHER ──────────────────────────────────────── */
function showView(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const el = document.getElementById(id);
  if (el) el.classList.add('active');
  ['login-error','reg-error','forgot-error','create-pw-error'].forEach(clearError);
}

function clearError(id) {
  const el = document.getElementById(id);
  if (el) { el.textContent = ''; el.style.display = 'none'; }
}

function showError(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
}

/* ── EYE TOGGLES ────────────────────────────────────────── */
document.querySelectorAll('.eye-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.target);
    const isPass = input.type === 'password';
    input.type = isPass ? 'text' : 'password';
    btn.querySelector('.eye-icon').style.display     = isPass ? 'none' : '';
    btn.querySelector('.eye-off-icon').style.display = isPass ? ''     : 'none';
  });
});

/* ── NAV LINKS ──────────────────────────────────────────── */
document.getElementById('go-forgot').addEventListener('click', e => {
  e.preventDefault(); showView('view-forgot');
});
document.getElementById('go-register').addEventListener('click', e => {
  e.preventDefault(); showView('view-register');
});
document.getElementById('go-login-from-reg').addEventListener('click', e => {
  e.preventDefault(); showView('view-login');
});
document.getElementById('back-to-login-btn').addEventListener('click', () => {
  showView('view-login');
});
document.getElementById('simulate-reset-link').addEventListener('click', e => {
  e.preventDefault();
  if (!resetToken) { alert('Please submit the Forgot Password form first.'); return; }
  showView('view-create-password');
});
document.getElementById('back-to-forgot-from-create').addEventListener('click', e => {
  e.preventDefault(); showView('view-forgot');
});
document.getElementById('help-link').addEventListener('click', e => {
  e.preventDefault(); alert('For help, please contact support@wingsfor growth.org');
});

/* ── PASSWORD REQUIREMENTS ──────────────────────────────── */
const newPwInput  = document.getElementById('new-password');
const createPwBtn = document.getElementById('create-pw-btn');

function checkPwReqs(val) {
  const checks = {
    'req-len':   val.length >= 8,
    'req-lower': /[a-z]/.test(val),
    'req-upper': /[A-Z]/.test(val),
    'req-spec':  /[\d\W\s]/.test(val),
  };
  let all = true;
  for (const [id, met] of Object.entries(checks)) {
    document.getElementById(id).classList.toggle('met', met);
    if (!met) all = false;
  }
  createPwBtn.disabled = !all;
  return all;
}
checkPwReqs('');
newPwInput.addEventListener('input', () => checkPwReqs(newPwInput.value));

/* ── COUNTDOWN ──────────────────────────────────────────── */
function startCountdown(spanId, seconds, onDone) {
  const span = document.getElementById(spanId);
  let n = seconds;
  span.textContent = n;
  return setInterval(() => { n--; span.textContent = n; if (n <= 0) onDone(); }, 1000);
}

/* ── MODAL ──────────────────────────────────────────────── */
const showModal = id => { document.getElementById(id).style.display = 'flex'; };
const hideModal = id => { document.getElementById(id).style.display = 'none';  };

/* ── LOADING STATE ──────────────────────────────────────── */
function setLoading(id, state) {
  const btn = document.getElementById(id);
  if (!btn) return;
  btn.classList.toggle('loading', state);
  if (id !== 'create-pw-btn') btn.disabled = state;
}

/* ── FORM: LOGIN ─────────────────────────────────────────── */
document.getElementById('form-login').addEventListener('submit', async e => {
  e.preventDefault();
  clearError('login-error');
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  if (!email || !password) { showError('login-error', 'Please enter your email and password.'); return; }

  setLoading('login-btn', true);
  const res = await authLogin(email, password);
  setLoading('login-btn', false);

  if (!res.success) { showError('login-error', res.message); return; }

  showModal('modal-login-success');
  if (loginCountdownTimer) clearInterval(loginCountdownTimer);
  loginCountdownTimer = startCountdown('login-countdown', 5, () => {
    clearInterval(loginCountdownTimer);
    window.location.href = 'dashboard.html';
  });
});

document.getElementById('redirect-dashboard-btn').addEventListener('click', () => {
  if (loginCountdownTimer) clearInterval(loginCountdownTimer);
  window.location.href = 'dashboard.html';
});

/* ── FORM: REGISTER ──────────────────────────────────────── */
document.getElementById('form-register').addEventListener('submit', async e => {
  e.preventDefault();
  clearError('reg-error');
  const name     = document.getElementById('reg-name').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirm  = document.getElementById('reg-confirm').value;

  if (!name || !email || !password || !confirm) { showError('reg-error', 'All fields are required.'); return; }
  if (password !== confirm) { showError('reg-error', 'Passwords do not match.'); return; }
  if (password.length < 8)  { showError('reg-error', 'Password must be at least 8 characters.'); return; }

  setLoading('reg-btn', true);
  const res = await authRegister(name, email, password);
  setLoading('reg-btn', false);

  if (!res.success) { showError('reg-error', res.message); return; }

  showModal('modal-login-success');
  if (loginCountdownTimer) clearInterval(loginCountdownTimer);
  loginCountdownTimer = startCountdown('login-countdown', 5, () => {
    clearInterval(loginCountdownTimer);
    window.location.href = 'dashboard.html';
  });
});

/* ── FORM: FORGOT PASSWORD ───────────────────────────────── */
document.getElementById('form-forgot').addEventListener('submit', async e => {
  e.preventDefault();
  clearError('forgot-error');
  const email = document.getElementById('forgot-email').value.trim();
  if (!email) { showError('forgot-error', 'Please enter your registered email address.'); return; }

  setLoading('forgot-btn', true);
  const res = authForgotPassword(email);
  setLoading('forgot-btn', false);

  resetToken = res.resetToken || null;
  resetEmail = email;
  document.getElementById('help-email-display').textContent = email;
  showView('view-help');
});

/* ── FORM: CREATE PASSWORD ───────────────────────────────── */
document.getElementById('form-create-password').addEventListener('submit', async e => {
  e.preventDefault();
  clearError('create-pw-error');
  const password = newPwInput.value;

  if (!checkPwReqs(password)) { showError('create-pw-error', 'Password does not meet all requirements.'); return; }
  if (!resetToken) { showError('create-pw-error', 'Reset token missing. Please request a new reset link.'); return; }

  setLoading('create-pw-btn', true);
  const res = await authResetPassword(resetToken, password);
  setLoading('create-pw-btn', false);

  if (!res.success) { showError('create-pw-error', res.message); return; }

  resetToken = null;
  showModal('modal-pw-changed');
  if (pwCountdownTimer) clearInterval(pwCountdownTimer);
  pwCountdownTimer = startCountdown('pw-countdown', 7, () => {
    clearInterval(pwCountdownTimer);
    hideModal('modal-pw-changed');
    showView('view-login');
  });
});

document.getElementById('redirect-login-btn').addEventListener('click', () => {
  if (pwCountdownTimer) clearInterval(pwCountdownTimer);
  hideModal('modal-pw-changed');
  showView('view-login');
});

/* ── INIT ────────────────────────────────────────────────── */
(async () => {
  if (!window.crypto || !window.crypto.subtle) {
    document.body.innerHTML = '<div style="font-family:sans-serif;padding:40px;text-align:center"><h2>Browser Not Supported</h2><p style="margin-top:12px;color:#666">Please open this page in a modern browser (Edge, Chrome, Firefox).</p></div>';
    return;
  }
  await seedDemo();
})();
