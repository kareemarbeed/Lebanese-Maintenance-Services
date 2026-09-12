<?php
declare(strict_types=1);

session_start();

require_once __DIR__ . '/db_connection.php';
require_once __DIR__ . '/admin_chat_store.php';
require_once __DIR__ . '/site_settings.php';
require_once __DIR__ . '/lang.php';

if (!isset($_SESSION['user_type']) || (string) $_SESSION['user_type'] !== 'admin') {
    header('Location: login.php');
    exit;
}

ensureAdminChatTable($pdo);
ensureSiteSettingsTable($pdo);
$siteSettings = loadSiteSettings($pdo, ['site_favicon' => '']);
$siteFavicon  = trim((string) ($siteSettings['site_favicon'] ?? ''));

if (!isset($_SESSION['admin_chat_csrf']) || !is_string($_SESSION['admin_chat_csrf'])) {
    $_SESSION['admin_chat_csrf'] = bin2hex(random_bytes(32));
}
$adminCsrf = $_SESSION['admin_chat_csrf'];

$totalUnread = countAdminUnreadFromUsers($pdo);
$dir         = t('dir');
$fontUrl     = t('font_url');
$isRtl       = isRtl();
?>
<!DOCTYPE html>
<html lang="<?php echo getLang(); ?>" dir="<?php echo $dir; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <?php if ($siteFavicon !== ''): ?>
        <link rel="icon" href="<?php echo htmlspecialchars($siteFavicon, ENT_QUOTES, 'UTF-8'); ?>">
    <?php endif; ?>
    <title><?php echo htmlspecialchars(t('admin_chat_mgmt_title'), ENT_QUOTES, 'UTF-8'); ?> – <?php echo htmlspecialchars(t('site_name'), ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php if ($isRtl): ?>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <?php endif; ?>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        :root {
            --ink: #0f172a; --muted: #475569; --line: #dbe2ea;
            --brand: #0f766e; --brand-deep: #115e59; --accent: #ea580c;
            --surface: #f8fafc; --card: #ffffff;
        }

        html, body { height: 100%; overflow: hidden; }

        body {
            font-family: <?php echo $isRtl ? "'Cairo', sans-serif" : "'Plus Jakarta Sans', sans-serif"; ?>;
            background: linear-gradient(135deg, #ecfeff, #f8fafc 45%, #fff7ed);
            display: flex; flex-direction: column;
        }

        /* ── Top bar ───────────────────────────────── */
        .topbar {
            background: rgba(255,255,255,0.9);
            border-bottom: 1px solid var(--line);
            backdrop-filter: blur(14px);
            padding: 14px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-shrink: 0;
            z-index: 10;
        }

        .topbar-left { display: flex; align-items: center; gap: 14px; }
        .back-link {
            display: inline-flex; align-items: center; gap: 6px;
            color: var(--brand); text-decoration: none; font-weight: 600; font-size: .9rem;
        }
        .back-link:hover { color: var(--brand-deep); }

        .topbar h1 { font-size: 1.2rem; font-weight: 800; color: #042f2e; }
        .topbar p  { font-size: .82rem; color: var(--muted); }

        .unread-global {
            background: #ef4444; color: #fff;
            font-size: .75rem; font-weight: 700;
            padding: 2px 9px; border-radius: 999px;
            display: inline-block;
        }

        /* ── Lang switcher ─────────────────────────── */
        .lang-btn {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 7px 14px; border-radius: 999px; border: 1.5px solid var(--line);
            background: #fff; color: var(--ink); font-size: .82rem; font-weight: 700;
            text-decoration: none; cursor: pointer; transition: border-color .2s;
        }
        .lang-btn:hover { border-color: var(--brand); color: var(--brand); }

        /* ── Shell ─────────────────────────────────── */
        .shell {
            display: flex; flex: 1; overflow: hidden;
        }

        /* ── Sidebar ───────────────────────────────── */
        .sidebar {
            width: 300px; flex-shrink: 0;
            background: var(--card);
            border-<?php echo $isRtl ? 'left' : 'right'; ?>: 1px solid var(--line);
            display: flex; flex-direction: column; overflow: hidden;
        }

        .sidebar-header {
            padding: 16px 18px 12px;
            border-bottom: 1px solid var(--line);
            flex-shrink: 0;
        }
        .sidebar-header h2 { font-size: 1rem; font-weight: 700; margin-bottom: 4px; }

        .conv-list { overflow-y: auto; flex: 1; }

        .conv-item {
            display: flex; align-items: flex-start; gap: 10px;
            padding: 13px 16px; cursor: pointer;
            border-bottom: 1px solid rgba(0,0,0,.05);
            transition: background .18s;
        }
        .conv-item:hover  { background: #f1f5f9; }
        .conv-item.active { background: #ecfdf5; border-<?php echo $isRtl ? 'right' : 'left'; ?>: 3px solid var(--brand); }

        .conv-avatar {
            width: 40px; height: 40px; border-radius: 50%; flex-shrink: 0;
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            display: flex; align-items: center; justify-content: center;
            color: #fff; font-weight: 700; font-size: .9rem;
        }
        .conv-avatar.provider { background: linear-gradient(135deg, #7c3aed, #5b21b6); }

        .conv-meta { flex: 1; min-width: 0; }
        .conv-name { font-size: .88rem; font-weight: 700; color: var(--ink); margin-bottom: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .conv-preview { font-size: .78rem; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .conv-role-badge {
            font-size: .68rem; font-weight: 700; padding: 1px 7px; border-radius: 999px;
            background: #e0f2fe; color: #0369a1; margin-bottom: 3px; display: inline-block;
        }
        .conv-role-badge.provider { background: #ede9fe; color: #6d28d9; }

        .unread-badge {
            flex-shrink: 0; background: #ef4444; color: #fff;
            font-size: .7rem; font-weight: 700; min-width: 20px; height: 20px;
            border-radius: 999px; display: flex; align-items: center; justify-content: center;
            padding: 0 5px; margin-top: 3px;
        }

        .conv-empty {
            padding: 40px 20px; text-align: center; color: var(--muted); font-size: .88rem;
        }

        /* ── Chat pane ─────────────────────────────── */
        .chat-pane {
            flex: 1; display: flex; flex-direction: column; overflow: hidden;
        }

        .chat-header {
            padding: 14px 20px; background: var(--card);
            border-bottom: 1px solid var(--line); flex-shrink: 0;
            display: flex; align-items: center; gap: 10px;
        }
        .chat-header-avatar {
            width: 38px; height: 38px; border-radius: 50%;
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            display: flex; align-items: center; justify-content: center;
            color: #fff; font-weight: 700;
        }
        .chat-header-avatar.provider { background: linear-gradient(135deg, #7c3aed, #5b21b6); }
        .chat-header-name { font-size: 1rem; font-weight: 700; }
        .chat-header-role { font-size: .78rem; color: var(--muted); }

        .chat-placeholder {
            flex: 1; display: flex; align-items: center; justify-content: center;
            flex-direction: column; gap: 12px; color: var(--muted);
        }
        .chat-placeholder i { font-size: 2.5rem; opacity: .3; }
        .chat-placeholder p { font-size: .92rem; }

        .messages-area {
            flex: 1; overflow-y: auto; padding: 20px;
            display: flex; flex-direction: column; gap: 10px;
        }

        .msg-row {
            display: flex;
            justify-content: <?php echo $isRtl ? 'flex-end' : 'flex-start'; ?>;
        }
        .msg-row.self {
            justify-content: <?php echo $isRtl ? 'flex-start' : 'flex-end'; ?>;
        }

        .msg-bubble {
            max-width: 68%; padding: 10px 14px; border-radius: 18px;
            font-size: .88rem; line-height: 1.55;
            background: #f1f5f9; color: var(--ink);
            border-bottom-<?php echo $isRtl ? 'right' : 'left'; ?>-radius: 4px;
        }
        .msg-row.self .msg-bubble {
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            color: #fff;
            border-bottom-<?php echo $isRtl ? 'right' : 'left'; ?>-radius: 18px;
            border-bottom-<?php echo $isRtl ? 'left' : 'right'; ?>-radius: 4px;
        }

        .msg-meta { font-size: .7rem; color: var(--muted); margin-top: 3px; text-align: <?php echo $isRtl ? 'left' : 'right'; ?>; }
        .msg-row.self .msg-meta { text-align: <?php echo $isRtl ? 'right' : 'left'; ?>; color: rgba(255,255,255,.7); }

        .chat-input-row {
            padding: 14px 18px; background: var(--card); border-top: 1px solid var(--line);
            display: flex; gap: 10px; align-items: flex-end; flex-shrink: 0;
        }
        .chat-input-row textarea {
            flex: 1; border: 2px solid var(--line); border-radius: 14px;
            padding: 10px 14px; font-family: inherit; font-size: .9rem;
            resize: none; max-height: 120px; line-height: 1.5; color: var(--ink);
        }
        .chat-input-row textarea:focus { outline: none; border-color: var(--brand); }
        .send-btn {
            height: 44px; padding: 0 20px; border-radius: 12px; border: none;
            background: linear-gradient(135deg, var(--brand), var(--brand-deep));
            color: #fff; font-weight: 700; font-size: .88rem; cursor: pointer;
            display: flex; align-items: center; gap: 7px; white-space: nowrap;
            transition: filter .2s;
        }
        .send-btn:hover { filter: brightness(1.06); }
        .send-btn:disabled { opacity: .55; cursor: not-allowed; }

        /* RTL tweaks */
        <?php if ($isRtl): ?>
        .back-link i { transform: scaleX(-1); }
        <?php endif; ?>
    </style>
</head>
<body class="<?php echo htmlspecialchars(getLangBodyClass(), ENT_QUOTES, 'UTF-8'); ?>">

<!-- Top bar -->
<div class="topbar">
    <div class="topbar-left">
        <a href="admin_dashboard.php" class="back-link">
            <i class="fa-solid fa-arrow-left"></i>
            <?php echo htmlspecialchars(t('nav_back_home'), ENT_QUOTES, 'UTF-8'); ?>
        </a>
        <div>
            <h1>
                <i class="fa-solid fa-comments" style="color:var(--brand);margin-<?php echo $isRtl?'left':'right';?>:8px;"></i>
                <?php echo htmlspecialchars(t('admin_chat_mgmt_title'), ENT_QUOTES, 'UTF-8'); ?>
                <?php if ($totalUnread > 0): ?>
                    <span class="unread-global"><?php echo $totalUnread; ?></span>
                <?php endif; ?>
            </h1>
            <p><?php echo htmlspecialchars(t('admin_chat_mgmt_sub'), ENT_QUOTES, 'UTF-8'); ?></p>
        </div>
    </div>
    <a href="<?php echo htmlspecialchars(langSwitchUrl(), ENT_QUOTES, 'UTF-8'); ?>" class="lang-btn">
        <i class="fa-solid <?php echo t('lang_switch_icon'); ?>"></i>
        <?php echo htmlspecialchars(t('lang_switch_label'), ENT_QUOTES, 'UTF-8'); ?>
    </a>
</div>

<!-- Shell -->
<div class="shell">

    <!-- Sidebar: conversation list -->
    <div class="sidebar" id="convSidebar">
        <div class="sidebar-header">
            <h2><?php echo htmlspecialchars(t('admin_chat_mgmt_all'), ENT_QUOTES, 'UTF-8'); ?></h2>
        </div>
        <div class="conv-list" id="convList">
            <div class="conv-empty"><?php echo htmlspecialchars(t('lbl_loading'), ENT_QUOTES, 'UTF-8'); ?></div>
        </div>
    </div>

    <!-- Chat pane -->
    <div class="chat-pane" id="chatPane">
        <div class="chat-placeholder" id="chatPlaceholder">
            <i class="fa-regular fa-comments"></i>
            <p><?php echo htmlspecialchars(t('admin_chat_mgmt_select'), ENT_QUOTES, 'UTF-8'); ?></p>
        </div>

        <div id="chatActive" style="display:none; flex-direction:column; flex:1; overflow:hidden;">
            <div class="chat-header" id="chatHeader">
                <div class="chat-header-avatar" id="chatHeaderAvatar">?</div>
                <div>
                    <div class="chat-header-name" id="chatHeaderName"></div>
                    <div class="chat-header-role" id="chatHeaderRole"></div>
                </div>
            </div>
            <div class="messages-area" id="messagesArea"></div>
            <div class="chat-input-row">
                <textarea id="replyInput" rows="1"
                    placeholder="<?php echo htmlspecialchars(t('admin_chat_mgmt_reply_ph'), ENT_QUOTES, 'UTF-8'); ?>"></textarea>
                <button class="send-btn" id="sendBtn" disabled>
                    <i class="fa-solid fa-paper-plane"></i>
                    <?php echo htmlspecialchars(t('admin_chat_mgmt_send'), ENT_QUOTES, 'UTF-8'); ?>
                </button>
            </div>
        </div>
    </div>

</div>

<script>
const CSRF      = <?php echo json_encode($adminCsrf); ?>;
const IS_RTL    = <?php echo $isRtl ? 'true' : 'false'; ?>;
const LABELS    = {
    customer : <?php echo json_encode(t('admin_chat_mgmt_customer')); ?>,
    provider : <?php echo json_encode(t('admin_chat_mgmt_provider')); ?>,
    unread   : <?php echo json_encode(t('admin_chat_mgmt_unread_badge')); ?>,
    you      : <?php echo json_encode(t('admin_chat_admin')); ?>,
    loading  : <?php echo json_encode(t('lbl_loading')); ?>,
    noConv   : <?php echo json_encode(t('admin_chat_mgmt_empty')); ?>,
};

let activeRole = null;
let activeId   = null;
let lastMsgId  = 0;
let pollTimer  = null;

/* ── Helpers ─────────────────────────────────────────── */
function initials(name) {
    return (name || '?').split(/\s+/).map(w => w[0]).join('').toUpperCase().slice(0, 2) || '?';
}

function timeLabel(ts) {
    const d = new Date(ts.replace(' ', 'T'));
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function escHtml(str) {
    const el = document.createElement('div');
    el.textContent = str;
    return el.innerHTML;
}

/* ── Conversation list ───────────────────────────────── */
async function loadConversations() {
    try {
        const r = await fetch('admin_chat_api.php?action=conversations');
        const d = await r.json();
        if (!d.ok) return;

        const list = document.getElementById('convList');
        if (!d.conversations.length) {
            list.innerHTML = `<div class="conv-empty">${escHtml(LABELS.noConv)}</div>`;
            return;
        }

        list.innerHTML = d.conversations.map(c => {
            const isProvider = c.user_role === 'service_provider';
            const isActive   = c.user_role === activeRole && c.user_id === activeId;
            const roleLabel  = isProvider ? LABELS.provider : LABELS.customer;
            const badgeClass = isProvider ? 'provider' : '';
            const unreadHtml = c.unread_count > 0
                ? `<div class="unread-badge">${c.unread_count}</div>` : '';
            return `<div class="conv-item${isActive ? ' active' : ''}"
                         onclick="openConv('${escHtml(c.user_role)}', ${c.user_id}, '${escHtml(c.user_name)}')">
                <div class="conv-avatar ${badgeClass}">${escHtml(initials(c.user_name))}</div>
                <div class="conv-meta">
                    <div class="conv-role-badge ${badgeClass}">${escHtml(roleLabel)}</div>
                    <div class="conv-name">${escHtml(c.user_name)}</div>
                    <div class="conv-preview">${escHtml(c.last_message || '')}</div>
                </div>
                ${unreadHtml}
            </div>`;
        }).join('');
    } catch(e) {}
}

/* ── Open conversation ───────────────────────────────── */
function openConv(role, id, name) {
    activeRole = role;
    activeId   = id;
    lastMsgId  = 0;

    const isProvider = role === 'service_provider';
    const roleLabel  = isProvider ? LABELS.provider : LABELS.customer;

    document.getElementById('chatPlaceholder').style.display = 'none';
    const ca = document.getElementById('chatActive');
    ca.style.display = 'flex';

    const avatarEl = document.getElementById('chatHeaderAvatar');
    avatarEl.textContent = initials(name);
    avatarEl.className = 'chat-header-avatar' + (isProvider ? ' provider' : '');
    document.getElementById('chatHeaderName').textContent = name;
    document.getElementById('chatHeaderRole').textContent = roleLabel;
    document.getElementById('sendBtn').disabled = false;

    document.getElementById('messagesArea').innerHTML = '';

    loadConversations();
    fetchMessages();
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(fetchMessages, 3000);
}

/* ── Fetch messages ──────────────────────────────────── */
async function fetchMessages() {
    if (!activeRole || !activeId) return;
    try {
        const r = await fetch(`admin_chat_api.php?action=fetch&user_role=${activeRole}&user_id=${activeId}&since_id=${lastMsgId}`);
        const d = await r.json();
        if (!d.ok) return;

        if (d.messages.length) {
            const area = document.getElementById('messagesArea');
            d.messages.forEach(msg => appendMessage(area, msg));
            area.scrollTop = area.scrollHeight;
            lastMsgId = d.last_id;
        }
        loadConversations();
    } catch(e) {}
}

function appendMessage(area, msg) {
    const self = msg.is_self;
    const row  = document.createElement('div');
    row.className = 'msg-row' + (self ? ' self' : '');
    row.innerHTML = `
        <div>
            <div class="msg-bubble">${escHtml(msg.message)}</div>
            <div class="msg-meta">${escHtml(timeLabel(msg.created_at))}</div>
        </div>`;
    area.appendChild(row);
}

/* ── Send reply ──────────────────────────────────────── */
document.getElementById('sendBtn').addEventListener('click', sendReply);
document.getElementById('replyInput').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendReply(); }
});
document.getElementById('replyInput').addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 120) + 'px';
    document.getElementById('sendBtn').disabled = !this.value.trim();
});

async function sendReply() {
    const input = document.getElementById('replyInput');
    const text  = input.value.trim();
    if (!text || !activeRole || !activeId) return;

    const btn = document.getElementById('sendBtn');
    btn.disabled = true;

    const body = new FormData();
    body.append('action',     'send');
    body.append('user_role',  activeRole);
    body.append('user_id',    activeId);
    body.append('message',    text);
    body.append('csrf_token', CSRF);

    try {
        const r = await fetch('admin_chat_api.php', { method: 'POST', body });
        const d = await r.json();
        if (d.ok) {
            input.value = '';
            input.style.height = 'auto';
            const area = document.getElementById('messagesArea');
            appendMessage(area, d.message);
            area.scrollTop = area.scrollHeight;
            lastMsgId = Math.max(lastMsgId, d.message.message_id);
            loadConversations();
        }
    } catch(e) {}

    btn.disabled = !input.value.trim();
}

/* ── Init ────────────────────────────────────────────── */
loadConversations();
setInterval(loadConversations, 10000);
</script>
</body>
</html>
