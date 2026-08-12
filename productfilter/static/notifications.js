// ============================================
// ProductFilter Notifications — notifications.js
// Place this file in /static/notifications.js
// ============================================

const CS_ALERTS_KEY = 'productfilter_price_alerts';
const CS_CHECK_KEY  = 'productfilter_last_check';
const CHECK_INTERVAL = 30 * 60 * 1000; // 30 minutes

// ── Register service worker ──
async function registerSW() {
  if (!('serviceWorker' in navigator)) return null;
  try {
    const reg = await navigator.serviceWorker.register('/static/sw.js', { scope: '/' });
    console.log('ProductFilter SW registered');
    return reg;
  } catch (err) {
    console.error('SW registration failed:', err);
    return null;
  }
}

// ── Request notification permission ──
async function requestPermission() {
  if (!('Notification' in window)) {
    showToast('Your browser does not support notifications.', 'error');
    return false;
  }

  if (Notification.permission === 'granted') return true;

  if (Notification.permission === 'denied') {
    showToast('Notifications blocked. Please enable in browser settings.', 'error');
    return false;
  }

  const permission = await Notification.requestPermission();
  return permission === 'granted';
}

// ── Save a price alert ──
// A stored alert is replayed later — as a notification target and as a link.
// Anything that is not a plain http(s) URL is dropped rather than kept.
function safeLink(url) {
  try {
    const u = new URL(url, window.location.origin);
    return (u.protocol === 'http:' || u.protocol === 'https:') ? u.href : '/';
  } catch (e) {
    return '/';
  }
}

function saveAlert(title, targetPrice, currentPrice, link) {
  link = safeLink(link);
  const alerts = getAlerts();
  const id = Date.now().toString();

  // Avoid duplicates
  const exists = alerts.find(a => a.title.toLowerCase() === title.toLowerCase());
  if (exists) {
    exists.target_price = targetPrice;
    exists.current_price = currentPrice;
    exists.link = link;
    localStorage.setItem(CS_ALERTS_KEY, JSON.stringify(alerts));
    showToast(`Alert updated for ${title}!`, 'success');
    updateBellBadge();
    return;
  }

  alerts.push({ id, title, target_price: targetPrice, current_price: currentPrice, link, created: Date.now() });
  localStorage.setItem(CS_ALERTS_KEY, JSON.stringify(alerts));
  showToast(`🔔 Alert set! We'll notify you when ${title} drops to ₹${targetPrice}`, 'success');
  updateBellBadge();
}

// ── Get all alerts ──
function getAlerts() {
  try {
    return JSON.parse(localStorage.getItem(CS_ALERTS_KEY) || '[]');
  } catch {
    return [];
  }
}

// ── Remove an alert ──
function removeAlert(id) {
  const alerts = getAlerts().filter(a => a.id !== id);
  localStorage.setItem(CS_ALERTS_KEY, JSON.stringify(alerts));
  updateBellBadge();
  renderAlertsPanel();
}

// ── Clear all alerts ──
function clearAllAlerts() {
  localStorage.removeItem(CS_ALERTS_KEY);
  updateBellBadge();
  renderAlertsPanel();
}

// ── Update bell badge count ──
function updateBellBadge() {
  const count = getAlerts().length;
  const badge = document.getElementById('bell-badge');
  if (!badge) return;
  badge.textContent = count;
  badge.style.display = count > 0 ? 'flex' : 'none';
}

// ── Trigger background price check via SW ──
async function triggerPriceCheck() {
  const lastCheck = parseInt(localStorage.getItem(CS_CHECK_KEY) || '0');
  if (Date.now() - lastCheck < CHECK_INTERVAL) return;

  const alerts = getAlerts();
  if (alerts.length === 0) return;

  const reg = await navigator.serviceWorker?.ready;
  if (reg && reg.active) {
    reg.active.postMessage({ type: 'CHECK_PRICES', alerts });
    localStorage.setItem(CS_CHECK_KEY, Date.now().toString());
  }
}

// ── Show alert set modal ──
function openAlertModal(title, currentPrice, link) {
  const modal = document.getElementById('alert-modal');
  const titleEl = document.getElementById('modal-product-title');
  const priceEl = document.getElementById('modal-current-price');
  const inputEl = document.getElementById('modal-target-price');

  if (!modal) return;

  titleEl.textContent = title;
  priceEl.textContent = `₹${Number(currentPrice).toLocaleString('en-IN')}`;
  inputEl.value = Math.floor(currentPrice * 0.9); // suggest 10% below
  inputEl.max = currentPrice;

  modal.dataset.title = title;
  modal.dataset.currentPrice = currentPrice;
  modal.dataset.link = link;
  modal.classList.remove('hidden');
  modal.classList.add('flex');

  setTimeout(() => {
    document.getElementById('modal-inner')?.classList.remove('scale-95', 'opacity-0');
    document.getElementById('modal-inner')?.classList.add('scale-100', 'opacity-100');
  }, 10);
}

// ── Close modal ──
function closeAlertModal() {
  const modal = document.getElementById('alert-modal');
  const inner = document.getElementById('modal-inner');
  inner?.classList.add('scale-95', 'opacity-0');
  inner?.classList.remove('scale-100', 'opacity-100');
  setTimeout(() => {
    modal?.classList.add('hidden');
    modal?.classList.remove('flex');
  }, 200);
}

// ── Confirm alert from modal ──
async function confirmAlert() {
  const modal = document.getElementById('alert-modal');
  const targetPrice = parseFloat(document.getElementById('modal-target-price').value);
  const title = modal.dataset.title;
  const currentPrice = parseFloat(modal.dataset.currentPrice);
  const link = modal.dataset.link;

  if (!targetPrice || targetPrice <= 0) {
    showToast('Please enter a valid target price.', 'error');
    return;
  }

  if (targetPrice >= currentPrice) {
    showToast('Target price must be lower than current price!', 'error');
    return;
  }

  const granted = await requestPermission();
  if (!granted) return;

  saveAlert(title, targetPrice, currentPrice, link);
  closeAlertModal();
}

// ── Toggle alerts panel ──
function toggleAlertsPanel() {
  const panel = document.getElementById('alerts-panel');
  if (!panel) return;
  if (panel.classList.contains('hidden')) {
    renderAlertsPanel();
    panel.classList.remove('hidden');
    panel.classList.add('flex');
  } else {
    panel.classList.add('hidden');
    panel.classList.remove('flex');
  }
}

// ── Render alerts inside panel ──
function renderAlertsPanel() {
  const container = document.getElementById('alerts-list');
  if (!container) return;
  const alerts = getAlerts();

  container.textContent = '';

  if (alerts.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'text-center py-8';
    const icon = document.createElement('div');
    icon.className = 'text-4xl mb-3';
    icon.textContent = '🔔';
    const line1 = document.createElement('div');
    line1.className = 'text-gray-500 text-sm';
    line1.textContent = 'No price alerts yet.';
    const line2 = document.createElement('div');
    line2.className = 'text-gray-400 text-xs mt-1';
    line2.textContent = 'Use the Alert button on any product to add one.';
    empty.append(icon, line1, line2);
    container.appendChild(empty);
    return;
  }

  // Built with DOM APIs on purpose. A product title comes from the listing,
  // and on a marketplace the seller writes that title — interpolating it into
  // innerHTML turned any saved alert into stored XSS on our own origin.
  // textContent cannot execute markup.
  alerts.forEach((a) => {
    const row = document.createElement('div');
    row.className = 'flex items-center justify-between bg-gray-50 rounded-xl px-3 py-3 gap-3';

    const left = document.createElement('div');
    left.className = 'flex-1 min-w-0';

    const title = document.createElement('div');
    title.className = 'font-medium text-gray-800 text-sm truncate';
    title.textContent = a.title;

    const meta = document.createElement('div');
    meta.className = 'text-xs text-gray-500 mt-0.5';
    meta.append(document.createTextNode('Alert when ≤ '));

    const target = document.createElement('span');
    target.className = 'font-bold text-green-600';
    target.textContent = '₹' + Number(a.target_price).toLocaleString('en-IN');

    const now = document.createElement('span');
    now.className = 'text-gray-400 ml-1';
    now.textContent = '(now ₹' + Number(a.current_price).toLocaleString('en-IN') + ')';

    meta.append(target, now);
    left.append(title, meta);

    // Delegated via data-action: an inline onclick here would be dead markup,
    // because the Content-Security-Policy forbids inline script.
    const remove = document.createElement('button');
    remove.className = 'text-gray-400 hover:text-red-500 transition text-lg flex-shrink-0';
    remove.setAttribute('title', 'Remove alert');
    remove.setAttribute('data-action', 'remove-alert');
    remove.setAttribute('data-id', a.id);
    remove.textContent = '✕';

    row.append(left, remove);
    container.appendChild(row);
  });
}

// ── Toast notification ──
function showToast(message, type = 'success') {
  const existing = document.getElementById('cs-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'cs-toast';
  toast.className = `fixed bottom-20 left-1/2 -translate-x-1/2 z-[9999] px-5 py-3 rounded-2xl text-white text-sm font-medium shadow-xl transition-all duration-300 flex items-center gap-2 ${
    type === 'success' ? 'bg-green-500' : 'bg-red-500'
  }`;
  // textContent, not innerHTML: a toast should never be able to render markup
  toast.textContent = (type === 'success' ? '✅ ' : '❌ ') + message;
  document.body.appendChild(toast);

  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(-50%) translateY(10px)'; }, 3000);
  setTimeout(() => toast.remove(), 3400);
}

// ── Init on page load ──
document.addEventListener('DOMContentLoaded', async () => {
  await registerSW();
  updateBellBadge();
  triggerPriceCheck();

  // Close modal on backdrop click
  document.getElementById('alert-modal')?.addEventListener('click', (e) => {
    if (e.target === document.getElementById('alert-modal')) closeAlertModal();
  });

  // Close panel on outside click
  document.addEventListener('click', (e) => {
    const panel = document.getElementById('alerts-panel');
    const bell  = document.getElementById('bell-btn');
    if (panel && !panel.contains(e.target) && !bell?.contains(e.target)) {
      panel.classList.add('hidden');
      panel.classList.remove('flex');
    }
  });
});