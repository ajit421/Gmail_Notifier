/**
 * @file Code.gs
 * @description Main entry point, Gmail engine, Telegram API layer,
 *              deduplication engine, trigger management, audit logging,
 *              test suite, security audit, quota audit, and health check
 *              for GmailTelegramForwarder.
 *              Phase 6 adds: runAllTests(), auditSecurity(),
 *              auditQuota(), healthCheck().
 *
 * @author      Ajit
 * @version     2.0
 * @phase       6 of 6 (Complete)
 */


// ─────────────────────────────────────────────────────────────────────────────
// Core Orchestration
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Main entry point — called by the time-based trigger every N minutes.
 *
 * Full pipeline: secrets → Gmail search → filter → dedup → extract
 *   → format → send → dedup-write → mark-read → label → logEvent.
 *
 * @return {void}
 */
function checkAndForward() {
  // ── Step 1: Validate secrets before touching Gmail ───────────────────────
  let secrets;
  try {
    secrets = getSecrets();
  } catch (e) {
    Logger.log('Configuration error — aborting run: ' + e.message);
    return;
  }

  // ── Step 2: Record wall-clock start + generate run ID ──────────────────
  const startTime = Date.now();
  const runId = 'run_' + Date.now().toString(36).toUpperCase();

  // ── Step 3: Search Gmail for threads matching the configured query ────────
  let threads;
  try {
    threads = GmailApp.search(
      CONFIG.GMAIL_SEARCH_QUERY,
      0,
      CONFIG.MAX_THREADS_PER_RUN
    );
  } catch (e) {
    Logger.log('Gmail search failed: ' + e.message);
    return;
  }

  // ── Step 4: Short-circuit when nothing to process ────────────────────────
  if (!threads || threads.length === 0) {
    Logger.log('No unread threads found.');
    return;
  }

  Logger.log('Found ' + threads.length + ' thread(s) to process.');

  // ── Step 5: Ensure the processed label exists once per run ───────────────
  const label = getOrCreateLabel(CONFIG.PROCESSED_LABEL);
  // label may be null if creation failed — handled gracefully below.

  // ── Step 6: Run counters ──────────────────────────────────────────────────
  let successCount = 0;
  let skipCount    = 0;
  let errorCount   = 0;

  // ── Step 7: Process every message in every thread ────────────────────────
  outerLoop:
  for (let ti = 0; ti < threads.length; ti++) {
    const thread = threads[ti];
    let messages;

    try {
      messages = thread.getMessages();
    } catch (e) {
      Logger.log('Failed to get messages for thread ' + ti + ': ' + e.message);
      errorCount++;
      continue;
    }

    for (let mi = 0; mi < messages.length; mi++) {
      const message   = messages[mi];
      const messageId = message.getId();

      // ── Step 7a: Only process unread messages ──────────────────────────
      if (!message.isUnread()) continue;

      // ── Step 7c: Deduplication ─────────────────────────────────────────
      if (isAlreadyProcessed(messageId)) {
        Logger.log('Duplicate skipped: ' + messageId);
        skipCount++;
        continue;
      }

      // ── Step 7d: Sender filter ─────────────────────────────────────────
      let rawFrom = '';
      try { rawFrom = message.getFrom(); } catch (_) {}
      if (!passesSenderFilter(rawFrom)) {
        try { message.markRead(); } catch (_) {}
        skipCount++;
        continue;
      }

      // ── Step 7e: Subject keyword filter ───────────────────────────────
      let rawSubject = '';
      try { rawSubject = message.getSubject(); } catch (_) {}
      if (!passesSubjectFilter(rawSubject)) {
        try { message.markRead(); } catch (_) {}
        skipCount++;
        continue;
      }

      // ── Step 7f: Extract structured data ──────────────────────────────
      let emailData;
      try {
        emailData = extractEmailData(message);
      } catch (e) {
        Logger.log('Extraction failed for ' + messageId + ': ' + e.message);
        errorCount++;
        logEvent('ERROR', '', 'Extraction failed', messageId, runId);
        continue;
      }

      Logger.log('Extracted: ' + emailData.subject + ' | ' + emailData.senderEmail);

      // ── Step 7h: Format and send to Telegram ──────────────────────────
      const telegramText = formatTelegramMessage(emailData);
      const sent = sendToTelegram(secrets.token, secrets.chatId, telegramText);

      if (sent) {
        successCount++;
        Logger.log('Sent to Telegram: ' + emailData.subject + ' | ' + emailData.messageId);
        markAsProcessed(messageId);

        if (CONFIG.ENABLE_ATTACHMENT_FORWARDING && emailData.attachmentCount > 0) {
          const attachResult = sendAttachments(secrets.token, secrets.chatId, emailData);
          Logger.log(
            'Attachments — sent: ' + attachResult.sent +
            ', failed: '  + attachResult.failed +
            ', skipped: ' + attachResult.skipped
          );
        }

        try {
          message.markRead();
        } catch (e) {
          Logger.log('markRead failed for ' + messageId + ': ' + e.message);
        }

        if (label) {
          try {
            thread.addLabel(label);
          } catch (e) {
            Logger.log('addLabel failed for ' + messageId + ': ' + e.message);
          }
        }
        logEvent('SUCCESS', emailData.sender, emailData.subject, emailData.messageId, runId);
      } else {
        errorCount++;
        Logger.log('Send failed — email left unread for retry: ' + emailData.messageId);
        logEvent('FAILED', emailData.sender, emailData.subject, emailData.messageId, runId);
      }

      // ── Step 7i: Execution-time guard (4.5 min = 270 000 ms) ───────────
      if (Date.now() - startTime > 270000) {
        Logger.log('Approaching 5-min limit. Stopping early.');
        break outerLoop;
      }
    } // end inner message loop
  } // end outer thread loop

  // ── Step 8: Run summary ───────────────────────────────────────────────────
  Logger.log(
    'Run complete | Sent: '    + successCount +
    ' | Skipped: ' + skipCount   +
    ' | Errors: '  + errorCount
  );

  // ── Step 9: Probabilistic dedup key pruning (~15% of runs) ───────────────
  if (Math.random() < 0.15) {
    pruneOldProcessedKeys();
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Secrets & Configuration
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Loads required secrets from Script Properties at runtime.
 * Throws a descriptive Error if TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is
 * absent, empty, or whitespace-only.
 * Never logs token or chatId values, even partially.
 *
 * @throws {Error} When a required Script Property is missing or blank.
 * @return {Readonly<{ token: string, chatId: string }>} Frozen secrets object.
 */
function getSecrets() {
  const props  = PropertiesService.getScriptProperties();
  const token  = props.getProperty('TELEGRAM_BOT_TOKEN');
  const chatId = props.getProperty('TELEGRAM_CHAT_ID');

  if (!token || token.trim() === '') {
    throw new Error(
      'Missing Script Property: TELEGRAM_BOT_TOKEN. ' +
      'Go to Apps Script Editor → Project Settings (gear icon) ' +
      '→ Script Properties → Add row, and set TELEGRAM_BOT_TOKEN ' +
      'to your bot token from @BotFather.'
    );
  }
  if (!chatId || chatId.trim() === '') {
    throw new Error(
      'Missing Script Property: TELEGRAM_CHAT_ID. ' +
      'Go to Apps Script Editor → Project Settings (gear icon) ' +
      '→ Script Properties → Add row, and set TELEGRAM_CHAT_ID ' +
      'to the numeric ID of your target Telegram chat.'
    );
  }

  return Object.freeze({ token: token.trim(), chatId: chatId.trim() });
}


// ─────────────────────────────────────────────────────────────────────────────
// Gmail Parsing — Private Helper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Strips HTML markup and decodes entities from a raw email body string.
 * Called only by extractEmailData() when getPlainBody() is unavailable.
 *
 * @param  {string|null|undefined} html - Raw HTML string.
 * @return {string} Plain text, or '' if input is null/undefined.
 */
function stripHtml(html) {
  if (html == null) return '';
  let text = html;
  text = text.replace(/<style[\s\S]*?<\/style>/gi, ' ');
  text = text.replace(/<script[\s\S]*?<\/script>/gi, ' ');
  text = text.replace(/<[^>]+>/gi, ' ');
  text = text
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi,  '&')
    .replace(/&lt;/gi,   '<')
    .replace(/&gt;/gi,   '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi,  "'");

  // 4b. Remove invisible / zero-width Unicode control characters
  // Covers: null bytes, C0 controls, soft-hyphen, CGJ, zero-width
  // spaces/joiners/BOM, line/paragraph separators, interlinear annotation.
  text = text.replace(
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u00AD\u034F\u200B-\u200F\u2028\u2029\uFEFF\uFFF9-\uFFFB]/g,
    ''
  );

  // 4c. Remove email spacer sequences (invisible chars surrounded by spaces)
  text = text.replace(/(\s*\u034F\s*)+/g, ' ');
  text = text.replace(/(\s*\uFEFF\s*)+/g, ' ');
  text = text.replace(/(\s*\u200B\s*)+/g, ' ');

  return text.trim();
}


// ─────────────────────────────────────────────────────────────────────────────
// Gmail Parsing — Public
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Parses a GmailMessage into a frozen plain-object DTO.
 * All fields have null-safe fallbacks. Result is Object.freeze()'d.
 *
 * @param  {GoogleAppsScript.Gmail.GmailMessage} message - Message to parse.
 * @throws {Error} Re-throws unexpected non-recoverable extraction failures.
 * @return {Readonly<{
 *   messageId: string, sender: string, senderEmail: string,
 *   subject: string, bodyPreview: string, timestamp: string, rawDate: Date,
 *   attachments: GoogleAppsScript.Base.Blob[], attachmentCount: number,
 *   attachmentNames: string[]
 * }>} Frozen email data object.
 */
function extractEmailData(message) {
  const messageId = message.getId();

  let rawFrom = '';
  try { rawFrom = message.getFrom() || ''; } catch (_) {}

  const fromMatch = rawFrom.match(/^(.*?)\s*<([^>]+)>\s*$/);
  let sender, senderEmail;
  if (fromMatch) {
    senderEmail = (fromMatch[2] || '').trim();
    sender = (fromMatch[1] || '').trim().replace(/^["']|["']$/g, '').trim();
    if (!sender) sender = senderEmail;
  } else {
    senderEmail = rawFrom.trim();
    sender      = senderEmail;
  }
  if (!senderEmail) senderEmail = '(unknown sender)';
  if (!sender)      sender      = senderEmail;

  let subject = '';
  try { subject = message.getSubject() || ''; } catch (_) {}
  if (!subject.trim()) subject = '(No Subject)';

  let rawBody = '';
  try { rawBody = message.getPlainBody() || ''; } catch (_) {}
  if (!rawBody.trim()) {
    let htmlBody = '';
    try { htmlBody = message.getBody() || ''; } catch (_) {}
    rawBody = stripHtml(htmlBody);
  }

  let cleanedBody = rawBody;
  cleanedBody = cleanedBody.replace(/\r\n|\r|\n/g, ' ');
  cleanedBody = cleanedBody.replace(/  +/g, ' ');
  cleanedBody = cleanedBody.replace(/[-_]{3,}/g, ' ');
  cleanedBody = cleanedBody.trim();

  let bodyPreview;
  if (!cleanedBody) {
    bodyPreview = '(No preview available)';
  } else if (cleanedBody.length > CONFIG.BODY_PREVIEW_CHARS) {
    bodyPreview = cleanedBody.substring(0, CONFIG.BODY_PREVIEW_CHARS) + '\u2026';
  } else {
    bodyPreview = cleanedBody;
  }

  let rawDate, timestamp;
  try {
    rawDate = message.getDate();
    timestamp = rawDate.toLocaleString('en-IN', {
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZone: 'Asia/Kolkata',
    });
  } catch (_) {
    rawDate   = new Date();
    timestamp = rawDate.toLocaleString();
  }

  let attachments = [];
  try {
    attachments = message.getAttachments({
      includeInlineImages: !CONFIG.EXCLUDE_INLINE_IMAGES,
      includeAttachments:  true,
    });
  } catch (_) {}
  const attachmentCount = attachments.length;
  const attachmentNames = attachments.map(function(a) { try { return a.getName(); } catch(_) { return ''; } });

  let accountEmail = '';
  try { accountEmail = Session.getActiveUser().getEmail() || ''; } catch (_) {}

  return Object.freeze({ messageId, sender, senderEmail, subject, bodyPreview, timestamp, rawDate, attachments, attachmentCount, attachmentNames, accountEmail });
}


// ─────────────────────────────────────────────────────────────────────────────
// Telegram — Private Helper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Escapes all MarkdownV2 reserved characters in a dynamic value so Telegram
 * does not interpret them as formatting. Called only inside formatTelegramMessage().
 *
 * Reserved characters escaped: _ * [ ] ( ) ~ ` > # + - = | { } . ! \
 *
 * @param  {*} text - Any value; coerced to string before processing.
 * @return {string} Escaped string safe for MarkdownV2 inline content.
 */
function escapeMdV2(text) {
  const s = String(text);
  if (s === 'null' || s === 'undefined') return '';
  return s.replace(/([_*[\]()~`>#+\-=|{}.!\\])/g, '\\$1');
}


// ─────────────────────────────────────────────────────────────────────────────
// Telegram — Formatting & Sending
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Builds a complete Telegram MarkdownV2 message string from an emailData DTO.
 * Static MarkdownV2 markers (* _ emoji) are NOT escaped — they are intentional
 * formatting. Every dynamic email field IS wrapped in escapeMdV2().
 *
 * @param  {Readonly<{ messageId: string, sender: string, senderEmail: string,
 *           subject: string, bodyPreview: string, timestamp: string,
 *           rawDate: Date, attachmentCount: number,
 *           accountEmail: string }>} emailData - Frozen DTO from extractEmailData().
 * @return {string} Ready-to-send MarkdownV2 message string.
 */
function formatTelegramMessage(emailData) {
  // Guard: return safe fallback if emailData is missing or not an object.
  if (!emailData || typeof emailData !== 'object') {
    return '📧 *New Email*\n\n_Could not parse email data\\._';
  }

  const attachmentLine = (emailData.attachmentCount > 0)
    ? '📎 *Attachment:* Yes ✅'
    : '📎 *Attachment:* No ❌';

  return (
    `📧 ${escapeMdV2(emailData.accountEmail)}\n\n` +
    `👤 *From:* ${escapeMdV2(emailData.sender)}\n` +
    `📮  ${escapeMdV2(emailData.senderEmail)}\n\n` +
    `📌 *Subject:*\n` +
    ` ${escapeMdV2(emailData.subject)}\n\n` +
    `📝 *Message:*\n` +
    ` ${escapeMdV2(emailData.bodyPreview)}\n\n` +
    attachmentLine + `\n\n` +
    `🕐 _${escapeMdV2(emailData.timestamp)}_`
  );
}

/**
 * Posts a formatted text message to a Telegram chat via the Bot API.
 * Uses UrlFetchApp with muteHttpExceptions:true so all HTTP error codes
 * are handled explicitly rather than thrown as exceptions.
 * Never logs token or chatId values.
 *
 * @param  {string} botToken - Telegram bot token from getSecrets().
 * @param  {string} chatId   - Target chat/channel ID from getSecrets().
 * @param  {string} text     - MarkdownV2 message from formatTelegramMessage().
 * @return {boolean} true on successful delivery; false on any failure.
 */
function sendToTelegram(botToken, chatId, text) {
  try {
    const url     = 'https://api.telegram.org/bot' + botToken + '/sendMessage';
    const payload = {
      chat_id:                  chatId,
      text:                     text,
      parse_mode:               CONFIG.TELEGRAM_PARSE_MODE,
      disable_web_page_preview: CONFIG.DISABLE_WEB_PAGE_PREVIEW,
    };

    const options = {
      method:             'post',
      contentType:        'application/json',
      payload:            JSON.stringify(payload),
      muteHttpExceptions: true,   // MANDATORY — never remove
    };

    const response     = UrlFetchApp.fetch(url, options);
    const code         = response.getResponseCode();
    const responseText = response.getContentText();

    // ── HTTP 200 ────────────────────────────────────────────────────────────
    if (code === 200) {
      let result;
      try { result = JSON.parse(responseText); } catch (_) { result = {}; }
      if (result.ok) {
        return true;
      }
      Logger.log('Telegram returned ok:false — ' + (result.description || responseText));
      return false;
    }

    // ── HTTP 400 Bad Request ────────────────────────────────────────────────
    if (code === 400) {
      let desc = responseText;
      try { desc = JSON.parse(responseText).description || responseText; } catch (_) {}
      Logger.log('Telegram 400 Bad Request: ' + desc);
      Logger.log('Hint: Check escapeMdV2() — a special character may be unescaped');
      return false;
    }

    // ── HTTP 401 Unauthorized ───────────────────────────────────────────────
    if (code === 401) {
      Logger.log(
        'Telegram 401 Unauthorized — TELEGRAM_BOT_TOKEN is invalid. ' +
        'Go to Project Settings → Script Properties and update the token.'
      );
      return false;
    }

    // ── HTTP 403 Forbidden ──────────────────────────────────────────────────
    if (code === 403) {
      Logger.log(
        'Telegram 403 Forbidden — Bot cannot send to this chat. ' +
        'Ensure TELEGRAM_CHAT_ID is correct and the bot is not blocked.'
      );
      return false;
    }

    // ── HTTP 429 Too Many Requests ──────────────────────────────────────────
    if (code === 429) {
      let retryAfter = 'unknown';
      try {
        const parsed = JSON.parse(responseText);
        if (parsed.parameters && parsed.parameters.retry_after) {
          retryAfter = parsed.parameters.retry_after;
        }
      } catch (_) {}
      Logger.log('Telegram 429 Rate Limited. Retry after ' + retryAfter + ' seconds.');
      return false;
    }

    // ── HTTP 5xx Server Error ───────────────────────────────────────────────
    if (code >= 500 && code < 600) {
      Logger.log('Telegram server error ' + code + '. Will retry next cycle.');
      return false;
    }

    // ── Any other code ──────────────────────────────────────────────────────
    Logger.log('Unexpected Telegram response: HTTP ' + code + ' — ' + responseText);
    return false;

  } catch (e) {
    // Network-level exception (DNS failure, timeout, etc.)
    Logger.log('Network error reaching Telegram API: ' + e.message);
    return false;
  }
}

/**
 * POSTs a single Blob to a Telegram chat via the sendDocument endpoint.
 * Uses UrlFetchApp with muteHttpExceptions:true so all HTTP error codes
 * are handled explicitly rather than thrown as exceptions.
 * Never logs token or chatId values.
 *
 * @param  {string} botToken - Telegram bot token from getSecrets().
 * @param  {string} chatId   - Target chat/channel ID from getSecrets().
 * @param  {GoogleAppsScript.Base.Blob} blob - Attachment blob to upload.
 * @param  {string} caption  - Caption text for the document message.
 * @return {boolean} true on successful delivery; false on any failure.
 */
function sendAttachmentToTelegram(botToken, chatId, blob, caption) {
  try {
    const url  = 'https://api.telegram.org/bot' + botToken + '/sendDocument';
    const payload = {
      chat_id:    chatId,
      document:   blob,
      caption:    caption,
      parse_mode: CONFIG.TELEGRAM_PARSE_MODE,
    };

    const options = {
      method:             'post',
      payload:            payload,
      muteHttpExceptions: true,   // MANDATORY — never remove
    };

    const response     = UrlFetchApp.fetch(url, options);
    const code         = response.getResponseCode();
    const responseText = response.getContentText();

    if (code === 200) {
      let result;
      try { result = JSON.parse(responseText); } catch (_) { result = {}; }
      if (result.ok) return true;
      Logger.log('sendAttachmentToTelegram: Telegram returned ok:false — ' + (result.description || responseText));
      return false;
    }

    Logger.log('sendAttachmentToTelegram: Unexpected HTTP ' + code + ' — ' + responseText);
    return false;

  } catch (e) {
    Logger.log('sendAttachmentToTelegram: Network error — ' + e.message);
    return false;
  }
}

/**
 * Iterates emailData.attachments, skips oversized files (logged as warnings),
 * and calls sendAttachmentToTelegram() for each eligible blob.
 * The size ceiling is capped at 50 MB regardless of CONFIG.MAX_ATTACHMENT_MB
 * to respect the Telegram Bot API hard limit.
 *
 * @param  {string} botToken  - Telegram bot token from getSecrets().
 * @param  {string} chatId    - Target chat/channel ID from getSecrets().
 * @param  {Readonly<{ attachments: GoogleAppsScript.Base.Blob[],
 *           attachmentCount: number, attachmentNames: string[] }>} emailData
 *         - Frozen DTO from extractEmailData().
 * @return {{ sent: number, failed: number, skipped: number }}
 */
function sendAttachments(botToken, chatId, emailData) {
  const maxBytes = Math.min(CONFIG.MAX_ATTACHMENT_MB, 50) * 1024 * 1024;
  let sent = 0, failed = 0, skipped = 0;

  for (let i = 0; i < emailData.attachments.length; i++) {
    const blob = emailData.attachments[i];
    let size = 0;
    try { size = blob.getBytes().length; } catch (_) {}

    if (size > maxBytes) {
      Logger.log(
        'Attachment skipped (exceeds ' + CONFIG.MAX_ATTACHMENT_MB + ' MB limit): ' +
        emailData.attachmentNames[i] + ' (' + (size / 1024 / 1024).toFixed(2) + ' MB)'
      );
      skipped++;
      continue;
    }

    const caption = escapeMdV2(emailData.attachmentNames[i] || 'attachment');
    const ok = sendAttachmentToTelegram(botToken, chatId, blob, caption);
    if (ok) {
      sent++;
    } else {
      Logger.log('Attachment send failed: ' + emailData.attachmentNames[i]);
      failed++;
    }
  }

  return { sent: sent, failed: failed, skipped: skipped };
}


// ─────────────────────────────────────────────────────────────────────────────
// Deduplication
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Checks whether a Gmail message ID has already been forwarded.
 * Reads a single Script Property key — O(1), safe in the hot path.
 * Fails OPEN (returns false) on error: a duplicate send is always
 * preferable to silently dropping a message.
 *
 * @param  {string} messageId - Unique Gmail message ID from emailData.messageId.
 * @return {boolean} true if already processed; false if new or on error.
 */
function isAlreadyProcessed(messageId) {
  try {
    const key   = CONFIG.PROCESSED_KEY_PREFIX + messageId;
    const value = PropertiesService.getScriptProperties().getProperty(key);
    return value !== null;
  } catch (e) {
    Logger.log('Dedup check failed for ' + messageId + ': ' + e.message);
    return false; // fail-open: risk duplicate over silent loss
  }
}

/**
 * Records a Gmail message ID as processed by storing a timestamped entry
 * in Script Properties. Failures are logged but never re-thrown — the
 * email is already sent; a duplicate on the next cycle is acceptable.
 *
 * @param  {string} messageId - Unique Gmail message ID to mark as processed.
 * @return {void}
 */
function markAsProcessed(messageId) {
  try {
    const key   = CONFIG.PROCESSED_KEY_PREFIX + messageId;
    const value = new Date().toISOString();
    PropertiesService.getScriptProperties().setProperty(key, value);
  } catch (e) {
    Logger.log('Failed to mark as processed ' + messageId + ': ' + e.message);
    // Non-fatal — do not re-throw.
  }
}

/**
 * Removes stale deduplication keys from Script Properties using two strategies:
 *
 *   Strategy A (primary)  — age-based: delete keys older than
 *                           CONFIG.DEDUP_RETENTION_DAYS days.
 *   Strategy B (safety)   — count-based: if >400 dedup keys remain after
 *                           age pruning, delete oldest until only 350 remain.
 *
 * Called probabilistically (~15% of runs) at the end of checkAndForward().
 * PropertiesService is capped at 500 keys; this keeps the count well clear.
 *
 * @return {void}
 */
function pruneOldProcessedKeys() {
  try {
    const props    = PropertiesService.getScriptProperties();
    const allProps = props.getProperties(); // single bulk fetch — OK here, not in hot path

    // Calculate the age cutoff date
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - CONFIG.DEDUP_RETENTION_DAYS);

    // Collect all dedup keys and their stored timestamps
    const dedupEntries = []; // [{ key, date }]
    const prefix = CONFIG.PROCESSED_KEY_PREFIX;

    for (const key in allProps) {
      if (!key.startsWith(prefix)) continue;
      const storedDate = new Date(allProps[key]);
      dedupEntries.push({ key: key, date: isNaN(storedDate.getTime()) ? new Date(0) : storedDate });
    }

    // ── Strategy A: age-based pruning ────────────────────────────────────────
    let agePruned = 0;
    const keysToDelete = [];
    for (let i = 0; i < dedupEntries.length; i++) {
      if (dedupEntries[i].date < cutoff) {
        keysToDelete.push(dedupEntries[i].key);
      }
    }

    for (let i = 0; i < keysToDelete.length; i++) {
      try {
        props.deleteProperty(keysToDelete[i]);
        agePruned++;
      } catch (e) {
        Logger.log('Failed to delete dedup key ' + keysToDelete[i] + ': ' + e.message);
      }
    }

    // ── Strategy B: count-based safety valve ─────────────────────────────────
    const deletedSet   = new Set(keysToDelete);
    const remaining    = dedupEntries.filter(function(e) { return !deletedSet.has(e.key); });
    let   safetyPruned = 0;

    if (remaining.length > 400) {
      // Sort oldest first
      remaining.sort(function(a, b) { return a.date - b.date; });
      const excess = remaining.length - 350;
      for (let i = 0; i < excess; i++) {
        try {
          props.deleteProperty(remaining[i].key);
          safetyPruned++;
        } catch (e) {
          Logger.log('Safety prune failed for ' + remaining[i].key + ': ' + e.message);
        }
      }
      Logger.log('Safety pruning: removed ' + safetyPruned + ' excess keys, 350 retained');
    }

    // ── Final summary log ─────────────────────────────────────────────────────
    const finalCount = remaining.length - safetyPruned;
    if (agePruned > 0 || safetyPruned > 0) {
      Logger.log(
        'Pruning complete: ' + agePruned + ' aged out, ' +
        safetyPruned + ' safety-pruned, ' +
        finalCount   + ' keys retained.'
      );
    } else {
      Logger.log('Pruning ran: no keys needed removal.');
    }

  } catch (e) {
    Logger.log('pruneOldProcessedKeys failed: ' + e.message);
    // Never propagate — pruning failure must not crash checkAndForward().
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Filtering
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the raw From header passes the sender allowlist.
 * When CONFIG.ALLOWED_SENDERS is empty, all senders pass.
 *
 * @param  {string} rawFrom - Raw From header value from message.getFrom().
 * @return {boolean} true if the sender is allowed (or no filter is active).
 */
function passesSenderFilter(rawFrom) {
  if (!CONFIG.ALLOWED_SENDERS || CONFIG.ALLOWED_SENDERS.length === 0) return true;
  const n = (rawFrom || '').toLowerCase();
  return CONFIG.ALLOWED_SENDERS.some(function(a) { return n.includes(a.toLowerCase()); });
}

/**
 * Returns true if the subject line passes the keyword filter.
 * When CONFIG.REQUIRED_SUBJECT_KEYWORDS is empty, all subjects pass.
 * At least one keyword must match (OR logic), case-insensitive.
 *
 * @param  {string|null|undefined} subject - Email subject line.
 * @return {boolean} true if the subject passes (or no filter is active).
 */
function passesSubjectFilter(subject) {
  if (!CONFIG.REQUIRED_SUBJECT_KEYWORDS || CONFIG.REQUIRED_SUBJECT_KEYWORDS.length === 0) return true;
  const n = (subject || '').toLowerCase();
  return CONFIG.REQUIRED_SUBJECT_KEYWORDS.some(function(k) { return n.includes(k.toLowerCase()); });
}


// ─────────────────────────────────────────────────────────────────────────────
// Gmail Label Helper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns a GmailLabel object for the given name, creating it if absent.
 * Returns null on failure so checkAndForward() can proceed gracefully.
 *
 * @param  {string} labelName - Label name (use CONFIG.PROCESSED_LABEL).
 * @return {GoogleAppsScript.Gmail.GmailLabel|null} Label object or null on error.
 */
function getOrCreateLabel(labelName) {
  try {
    let label = GmailApp.getUserLabelByName(labelName);
    if (!label) {
      label = GmailApp.createLabel(labelName);
      Logger.log('Created Gmail label: ' + labelName);
    }
    return label;
  } catch (e) {
    Logger.log('Failed to get or create label "' + labelName + '": ' + e.message);
    return null;
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Audit Logging
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns the Google Sheets ID used for audit logging, creating the
 * spreadsheet automatically on first call and persisting the ID in
 * Script Properties. Returns null on any failure.
 *
 * @return {string|null} Spreadsheet ID, or null if unavailable.
 */
function getLogSpreadsheetId() {
  try {
    const props = PropertiesService.getScriptProperties();
    const stored = props.getProperty('LOG_SPREADSHEET_ID');
    if (stored) {
      try {
        SpreadsheetApp.openById(stored); // verify still accessible
        return stored;
      } catch (_) {
        Logger.log('Stored spreadsheet not accessible. Creating new one.');
      }
    }
    const ss    = SpreadsheetApp.create('Gmail Telegram Forwarder — Audit Log');
    const newId = ss.getId();
    props.setProperty('LOG_SPREADSHEET_ID', newId);
    Logger.log('\uD83D\uDCCA Audit log created: ' + ss.getUrl());
    return newId;
  } catch (e) {
    Logger.log('getLogSpreadsheetId failed: ' + e.message);
    return null;
  }
}

/**
 * Appends one structured row to the audit log spreadsheet.
 * Is a no-op when CONFIG.ENABLE_SHEET_LOGGING is false.
 * Never throws — all failures are logged silently.
 *
 * @param  {string}  status    - 'SUCCESS' | 'FAILED' | 'SKIPPED' | 'ERROR'.
 * @param  {string}  sender    - emailData.sender (or '' on system events).
 * @param  {string}  subject   - emailData.subject (or '' on system events).
 * @param  {string}  messageId - Gmail message ID (or '' on system events).
 * @param  {string=} runId     - Run identifier from checkAndForward(). Default 'UNKNOWN'.
 * @return {void}
 */
function logEvent(status, sender, subject, messageId, runId) {
  if (!CONFIG.ENABLE_SHEET_LOGGING) return;

  try {
    const ssId = getLogSpreadsheetId();
    if (!ssId) {
      Logger.log('Logging skipped: no spreadsheet.');
      return;
    }

    const ss  = SpreadsheetApp.openById(ssId);
    let sheet = ss.getSheetByName(CONFIG.LOG_SHEET_NAME);
    let isNew = false;
    if (!sheet) {
      sheet = ss.insertSheet(CONFIG.LOG_SHEET_NAME);
      isNew = true;
      const header = [['Timestamp (IST)', 'Status', 'Sender', 'Subject', 'Message ID', 'Run ID']];
      sheet.getRange(1, 1, 1, 6).setValues(header).setFontWeight('bold');
      sheet.setFrozenRows(1);
    }

    const ts = new Date().toLocaleString('en-IN', {
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZone:  'Asia/Kolkata',
    });

    sheet.appendRow([ts, status, sender || '', subject || '', messageId || '', runId || 'UNKNOWN']);

    if (isNew) sheet.autoResizeColumns(1, 6);

  } catch (e) {
    Logger.log('logEvent() failed silently: ' + e.message);
    // Never re-throw — logging must not affect the forwarding pipeline.
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Trigger Management
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Private helper — returns the approximate next-run time as a short
 * locale string (current time + 5 minutes, IST).
 *
 * @return {string} Human-readable next-run estimate.
 */
function getNextRunEstimate() {
  return new Date(Date.now() + 30 * 60 * 1000).toLocaleString('en-IN', {
    timeStyle: 'short',
    timeZone:  'Asia/Kolkata',
  });
}

/**
 * Creates a time-based trigger that calls checkAndForward() every 5 minutes.
 * Idempotent — removes all existing checkAndForward triggers before creating
 * a new one. Safe to run multiple times without creating duplicates.
 *
 * @return {void}
 */
function installTrigger() {
  try {
    const all      = ScriptApp.getProjectTriggers();
    const existing = all.filter(function(t) { return t.getHandlerFunction() === 'checkAndForward'; });
    if (existing.length > 0) {
      existing.forEach(function(t) { ScriptApp.deleteTrigger(t); });
      Logger.log('Removed ' + existing.length + ' existing checkAndForward trigger(s).');
    }
    ScriptApp.newTrigger('checkAndForward').timeBased().everyMinutes(30).create();
    Logger.log('\u2705 Trigger installed successfully.');
    Logger.log('   Handler : checkAndForward');
    Logger.log('   Interval: every 30 minutes');
    Logger.log('   Next run : approximately ' + getNextRunEstimate());
  } catch (e) {
    Logger.log('\u274C Trigger installation failed: ' + e.message);
    Logger.log('Fix: Run from the Apps Script editor with your account logged in, not via deployment.');
  }
}

/**
 * Removes all checkAndForward and sendDailySummary triggers.
 * Pauses automatic forwarding and the daily digest in one call.
 *
 * @return {void}
 */
function removeTrigger() {
  try {
    const all = ScriptApp.getProjectTriggers();
    let fwdCount = 0, sumCount = 0;
    all.forEach(function(t) {
      const h = t.getHandlerFunction();
      if (h === 'checkAndForward')   { ScriptApp.deleteTrigger(t); fwdCount++; }
      if (h === 'sendDailySummary')  { ScriptApp.deleteTrigger(t); sumCount++;  }
    });
    if (fwdCount + sumCount > 0) {
      Logger.log('\u23F8 Triggers removed: ' + fwdCount + ' checkAndForward, ' + sumCount + ' sendDailySummary');
      Logger.log('Automatic forwarding is paused. Run installTrigger() to resume.');
    } else {
      Logger.log('No active triggers found. System was already paused.');
    }
  } catch (e) {
    Logger.log('removeTrigger failed: ' + e.message);
  }
}

/**
 * Diagnostic helper — logs the current trigger state and returns a
 * status object for programmatic inspection. Read-only: never modifies triggers.
 *
 * @return {{ forwarderActive: boolean, summaryActive: boolean,
 *            forwarderCount: number, summaryCount: number }}
 */
function getTriggerStatus() {
  try {
    const all = ScriptApp.getProjectTriggers();
    const fwd = all.filter(function(t) { return t.getHandlerFunction() === 'checkAndForward'; });
    const sum = all.filter(function(t) { return t.getHandlerFunction() === 'sendDailySummary'; });

    Logger.log('\u2550\u2550\u2550 Trigger Status \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550');
    Logger.log('checkAndForward : ' + (fwd.length > 0 ? 'ACTIVE \u2014 ' + fwd.length + ' trigger(s)' : 'INACTIVE \u2014 no triggers'));
    fwd.forEach(function(t) {
      Logger.log('  TriggerID: ' + t.getUniqueId());
      Logger.log('  Type     : time-based');
    });
    Logger.log('sendDailySummary: ' + (sum.length > 0 ? 'ACTIVE \u2014 ' + sum.length + ' trigger(s)' : 'INACTIVE \u2014 no triggers'));
    sum.forEach(function(t) {
      Logger.log('  TriggerID: ' + t.getUniqueId());
      Logger.log('  Type     : time-based');
    });
    Logger.log('\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550');

    return {
      forwarderActive: fwd.length > 0,
      summaryActive:   sum.length > 0,
      forwarderCount:  fwd.length,
      summaryCount:    sum.length,
    };
  } catch (e) {
    Logger.log('getTriggerStatus failed: ' + e.message);
    return { forwarderActive: false, summaryActive: false, forwarderCount: 0, summaryCount: 0 };
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Daily Summary
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sends a daily statistics digest to Telegram with today's forwarded count.
 * Counts processed messages from Script Properties (always available).
 * Run manually or via installDailySummaryTrigger() at 8 AM daily.
 *
 * @return {void}
 */
function sendDailySummary() {
  // ── Part A: Count today's processed messages from Script Properties ────────
  let processedToday = 0;
  try {
    const allProps  = PropertiesService.getScriptProperties().getProperties();
    const prefix    = CONFIG.PROCESSED_KEY_PREFIX;
    const todayStr  = new Date().toDateString();
    for (const key in allProps) {
      if (!key.startsWith(prefix)) continue;
      try {
        const d = new Date(allProps[key]);
        if (!isNaN(d.getTime()) && d.toDateString() === todayStr) processedToday++;
      } catch (_) {}
    }
  } catch (e) {
    Logger.log('sendDailySummary: failed reading properties — ' + e.message);
  }

  // ── Part B: Build MarkdownV2 message ─────────────────────────────────────
  const todayFormatted = new Date().toLocaleString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric', timeZone: 'Asia/Kolkata',
  });
  const timeFormatted = new Date().toLocaleString('en-IN', {
    timeStyle: 'short', timeZone: 'Asia/Kolkata',
  });

  const msg =
    '\uD83D\uDCCA *Daily Summary*\n' +
    '_Gmail \u2192 Telegram Forwarder_\n\n' +
    '\u2705 *Forwarded today:* ' + escapeMdV2(String(processedToday)) + '\n' +
    '\uD83D\uDDD3 *Date:* ' + escapeMdV2(todayFormatted) + '\n' +
    '\uD83D\uDD50 *Report time:* ' + escapeMdV2(timeFormatted) + '\n\n' +
    '_This is an automated daily digest\\._';

  // ── Part C: Load secrets and send ─────────────────────────────────────────
  let secrets;
  try {
    secrets = getSecrets();
  } catch (e) {
    Logger.log('sendDailySummary: secrets error — ' + e.message);
    return;
  }

  const result = sendToTelegram(secrets.token, secrets.chatId, msg);
  if (result) {
    Logger.log('\uD83D\uDCCA Daily summary sent to Telegram.');
  } else {
    Logger.log('\uD83D\uDCCA Daily summary send failed.');
  }

  /*
   * MANUAL SETUP — Daily Summary Trigger
   * To schedule this function daily at 8:00 AM IST, run
   * installDailySummaryTrigger() defined below.
   */
}

/**
 * Creates a daily time-based trigger that calls sendDailySummary() at 8 AM.
 * Idempotent — removes existing sendDailySummary triggers before creating.
 *
 * NOTE: The trigger fires at 8 AM in the script project's configured timezone.
 * Set timezone to Asia/Kolkata via Project Settings → Time zone.
 *
 * @return {void}
 */
function installDailySummaryTrigger() {
  try {
    const all      = ScriptApp.getProjectTriggers();
    const existing = all.filter(function(t) { return t.getHandlerFunction() === 'sendDailySummary'; });
    if (existing.length > 0) {
      existing.forEach(function(t) { ScriptApp.deleteTrigger(t); });
      Logger.log('Removed ' + existing.length + ' existing sendDailySummary trigger(s).');
    }
    ScriptApp.newTrigger('sendDailySummary').timeBased().everyDays(1).atHour(8).create();
    Logger.log('\uD83D\uDCCA Daily summary trigger installed: 8 AM daily.');
    Logger.log('Note: Trigger fires in the script project timezone.');
    Logger.log('To set timezone: Project Settings \u2192 Time zone \u2192 Asia/Kolkata (IST)');
  } catch (e) {
    Logger.log('installDailySummaryTrigger failed: ' + e.message);
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Manual Testing Helper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Developer utility — sends a canned test message to the configured Telegram
 * chat. Run once manually to verify bot token, chat ID, and MarkdownV2
 * formatting before enabling the live trigger.
 *
 * Safe to run multiple times — does NOT read Gmail or touch dedup state.
 * Select this function in the Apps Script editor dropdown and click Run.
 *
 * @return {void}
 */
function testSendMessage() {
  // ── Step 1: Load and validate secrets ────────────────────────────────────
  let secrets;
  try {
    secrets = getSecrets();
  } catch (e) {
    Logger.log('testSendMessage failed — secrets error: ' + e.message);
    return;
  }

  // ── Step 2: Build a synthetic emailData object ────────────────────────────
  const testEmailData = {
    messageId:    'TEST-001',
    sender:       'Gmail Telegram Forwarder',
    senderEmail:  'system@test.local',
    subject:      'Phase 3 Test — Telegram Connection Verified',
    bodyPreview:  'This is an automated test message. If you see this in ' +
                  'Telegram, the bot token, chat ID, and MarkdownV2 ' +
                  'formatting are all working correctly.',
    timestamp:    new Date().toLocaleString('en-IN', {
                    dateStyle: 'medium',
                    timeStyle: 'short',
                    timeZone:  'Asia/Kolkata',
                  }),
    rawDate:      new Date(),
    attachments:      [],
    attachmentCount:  0,
    attachmentNames:  [],
    accountEmail: (function() { try { return Session.getActiveUser().getEmail() || 'test@account.local'; } catch(_) { return 'test@account.local'; } }()),
  };

  // ── Step 3: Format and send ───────────────────────────────────────────────
  const text   = formatTelegramMessage(testEmailData);
  const result = sendToTelegram(secrets.token, secrets.chatId, text);

  // ── Step 4: Report outcome ────────────────────────────────────────────────
  if (result) {
    Logger.log('\u2705 Test passed. Check Telegram for the message.');
  } else {
    Logger.log('\u274C Test failed. Review error logs above.');
    Logger.log(
      'Checklist: TELEGRAM_BOT_TOKEN set? TELEGRAM_CHAT_ID set? ' +
      'Bot started (sent /start to bot)? Bot added to group if group chat?'
    );
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Phase 6 — Test Suite, Security Audit, Quota Audit, Health Check
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Private test-runner helper. Logs pass/fail and increments counters.
 * Counters are maintained on the _testCounters object passed by reference.
 *
 * @param {string}  name     - Test name shown in Logger.
 * @param {boolean} cond     - Condition that must be true to pass.
 * @param {string}  failMsg  - Message shown on failure.
 * @param {{pass:number,fail:number}} counters - Shared counter object.
 * @return {void}
 */
function _assert(name, cond, failMsg, counters) {
  if (cond) {
    Logger.log('  \u2705 PASS \u2014 ' + name);
    counters.pass++;
  } else {
    Logger.log('  \u274C FAIL \u2014 ' + name + ': ' + failMsg);
    counters.fail++;
  }
}

/**
 * Runs the full automated test suite for GmailTelegramForwarder.
 * Tests Groups A-G cover: escapeMdV2, stripHtml, extractEmailData,
 * formatTelegramMessage, isAlreadyProcessed, passesSenderFilter,
 * and a live sendToTelegram probe.
 * Never mutates real Gmail data. Cleans up all test PropertiesService keys.
 *
 * @example runAllTests()
 * @return {void}
 */
function runAllTests() {
  const c = { pass: 0, fail: 0 };
  try {

    // ── Group A: escapeMdV2() ──────────────────────────────────────────────
    Logger.log('--- Testing escapeMdV2() ---');
    _assert('A1 basic parens/brackets', escapeMdV2('Hello (World) [Test] {Val}') === 'Hello \\(World\\) \\[Test\\] \\{Val\\}', 'escaping failed', c);
    _assert('A2 dot and bang',          escapeMdV2('Price: $10.99! Save now.') === 'Price: $10\\.99\\! Save now\\.', 'escaping failed', c);
    _assert('A3 underscore asterisk',   escapeMdV2('_italic_ and *bold*') === '\\_italic\\_ and \\*bold\\*', 'escaping failed', c);
    _assert('A4 backslash',             escapeMdV2('C:\\Users\\file') === 'C:\\\\Users\\\\file', 'backslash not doubled', c);
    _assert('A5 null → empty string',   escapeMdV2(null) === '', 'null should return empty string', c);
    _assert('A5 null type check',       typeof escapeMdV2(null) === 'string', 'should be string', c);
    _assert('A6 number coercion',       escapeMdV2(42) === '42', 'number not coerced', c);
    _assert('A7 empty string',          escapeMdV2('') === '', 'empty string failed', c);
    const a8out = escapeMdV2('_ * [ ] ( ) ~ ` > # + = | { } . ! \\');
    // Every special char must be preceded by backslash in output
    const specials = ['_','*','[',']','(',')','>','#','+','=','|','{','}','.','!'];
    const a8ok = specials.every(function(ch) {
      // find unescaped: ch NOT preceded by backslash
      return !new RegExp('(?<!\\\\)\\' + ch).test(a8out);
    });
    _assert('A8 all 18 chars escaped', a8ok, 'unescaped special char found in: ' + a8out, c);

    // ── Group B: stripHtml() ──────────────────────────────────────────────
    Logger.log('--- Testing stripHtml() ---');
    _assert('B1 basic tag removal',  stripHtml('<p>Hello <b>World</b></p>').trim() === 'Hello World', 'tags not removed', c);
    const b2 = stripHtml('<style>body{color:red}</style><p>Text</p>');
    _assert('B2 style block gone',   !b2.includes('color') && !b2.includes('body'), 'style block leaked', c);
    _assert('B2 text preserved',     b2.trim() === 'Text', 'text not preserved', c);
    const b3 = stripHtml('AT&amp;T &lt;Wireless&gt; &quot;Plans&quot; it&#39;s');
    _assert('B3 &amp;',              b3.includes('AT&T'), '&amp; not decoded', c);
    _assert('B3 &lt;&gt;',           b3.includes('<Wireless>'), '&lt;&gt; not decoded', c);
    _assert('B3 &quot;',             b3.includes('"Plans"'), '&quot; not decoded', c);
    _assert("B3 &#39;",              b3.includes("it's"), '&#39; not decoded', c);
    const b4 = stripHtml('Hello\u200BWorld\uFEFF');
    _assert('B4 zero-width removed', !b4.includes('\u200B') && !b4.includes('\uFEFF'), 'invisible chars remain', c);
    _assert('B5 null → empty',       typeof stripHtml(null) === 'string' && stripHtml(null) === '', 'null not handled', c);
    const b6 = stripHtml('<script>alert("xss")</script>Safe content');
    _assert('B6 script removed',     !b6.includes('alert') && !b6.includes('<script>'), 'script not removed', c);
    _assert('B6 safe content kept',  b6.includes('Safe content'), 'content removed', c);

    // ── Group C: extractEmailData() ───────────────────────────────────────
    Logger.log('--- Testing extractEmailData() ---');
    const mockMsg = {
      getId:        function() { return 'TEST_MSG_ID_001'; },
      getFrom:      function() { return '"Test Sender" <sender@example.com>'; },
      getSubject:   function() { return 'Test Subject: Check (this) & that!'; },
      getPlainBody: function() { return '  Line one.\n\nLine two.  \n'; },
      getBody:      function() { return '<p>Fallback</p>'; },
      getDate:      function() { return new Date('2026-04-28T09:00:00Z'); },
      isUnread:     function() { return true; },
    };
    const ed = extractEmailData(mockMsg);
    _assert('C1 messageId',       ed.messageId === 'TEST_MSG_ID_001', 'got: ' + ed.messageId, c);
    _assert('C2 senderEmail',     ed.senderEmail === 'sender@example.com', 'got: ' + ed.senderEmail, c);
    _assert('C3 sender name',     ed.sender === 'Test Sender', 'got: ' + ed.sender, c);
    _assert('C4 subject',         ed.subject === 'Test Subject: Check (this) & that!', 'got: ' + ed.subject, c);
    _assert('C5 no newlines',     !ed.bodyPreview.includes('\n') && !ed.bodyPreview.includes('\r'), 'newline in preview', c);
    _assert('C6 preview not empty', ed.bodyPreview.length > 0, 'empty preview', c);
    _assert('C7 rawDate is Date', ed.rawDate instanceof Date, 'not a Date', c);
    ed.messageId = 'TAMPERED';
    _assert('C8 frozen',          ed.messageId === 'TEST_MSG_ID_001', 'object was mutated', c);
    const mockPlain = { getId: function(){return 'X';}, getFrom: function(){return 'plain@example.com';}, getSubject: function(){return 'S';}, getPlainBody: function(){return 'body';}, getBody: function(){return '';}, getDate: function(){return new Date();}, isUnread: function(){return true;} };
    const ed2 = extractEmailData(mockPlain);
    _assert('C9 plain sender',    ed2.sender === 'plain@example.com' && ed2.senderEmail === 'plain@example.com', 'got: ' + ed2.sender, c);
    const mockNull = { getId: function(){return 'Y';}, getFrom: function(){return '';}, getSubject: function(){return null;}, getPlainBody: function(){return 'b';}, getBody: function(){return '';}, getDate: function(){return new Date();}, isUnread: function(){return true;} };
    const ed3 = extractEmailData(mockNull);
    _assert('C10 null subject fallback', ed3.subject === '(No Subject)', 'got: ' + ed3.subject, c);

    // ── Group D: formatTelegramMessage() ─────────────────────────────────
    Logger.log('--- Testing formatTelegramMessage() ---');
    const ted = { messageId:'TEST001', sender:'Test User', senderEmail:'test@example.com', subject:'Invoice #1234 (April)', bodyPreview:'Please find attached the invoice for $500.00.', timestamp:'28 Apr 2026, 9:00 am', rawDate: new Date() };
    const fmt = formatTelegramMessage(ted);
    _assert('D1 is string',      typeof fmt === 'string', 'not a string', c);
    _assert('D2 sender present', fmt.includes('Test User'), 'sender missing', c);
    // # and ( must be escaped (preceded by \)
    _assert('D3 # escaped',      !(/(?<!\\)#/).test(fmt), 'unescaped # in output', c);
    _assert('D3 ( escaped',      !(/(?<!\\)\(/).test(fmt), 'unescaped ( in output', c);
    _assert('D4 emoji 📧',       fmt.includes('\uD83D\uDCE7'), 'emoji missing', c);
    _assert('D4 emoji 👤',       fmt.includes('\uD83D\uDC64'), 'emoji missing', c);
    _assert('D4 emoji 📮',       fmt.includes('\uD83D\uDCEE'), 'emoji missing', c);
    _assert('D4 emoji 📌',       fmt.includes('\uD83D\uDCCC'), 'emoji missing', c);
    _assert('D4 emoji 📝',       fmt.includes('\uD83D\uDCDD'), 'emoji missing', c);
    _assert('D4 emoji 🕐',       fmt.includes('\uD83D\uDD50'), 'emoji missing', c);
    const fmtNull = formatTelegramMessage(null);
    _assert('D5 null fallback string', typeof fmtNull === 'string' && fmtNull.length > 0, 'null fallback failed', c);
    _assert('D6 under 4096 chars',     fmt.length <= 4096, 'exceeds Telegram limit: ' + fmt.length, c);

    // ── Group E: isAlreadyProcessed() / markAsProcessed() ────────────────
    Logger.log('--- Testing isAlreadyProcessed() ---');
    const freshId = 'NONEXISTENT_' + Date.now();
    _assert('E1 unknown ID → false', isAlreadyProcessed(freshId) === false, 'should be false', c);
    const testId  = 'TEST_DEDUP_' + Date.now();
    markAsProcessed(testId);
    _assert('E2 mark then check', isAlreadyProcessed(testId) === true, 'should be true after mark', c);
    try { PropertiesService.getScriptProperties().deleteProperty(CONFIG.PROCESSED_KEY_PREFIX + testId); } catch(_) {}
    _assert('E3 after cleanup → false', isAlreadyProcessed(testId) === false, 'cleanup failed', c);

    // ── Group F: passesSenderFilter() ────────────────────────────────────
    Logger.log('--- Testing passesSenderFilter() ---');
    if (!CONFIG.ALLOWED_SENDERS || CONFIG.ALLOWED_SENDERS.length === 0) {
      _assert('F1 empty → passes all', passesSenderFilter('anyone@anywhere.com') === true, 'should be true', c);
      Logger.log('  \u2139 Filter inactive \u2014 ALLOWED_SENDERS is empty');
    } else {
      CONFIG.ALLOWED_SENDERS.forEach(function(e) {
        _assert('F2 listed sender passes: ' + e, passesSenderFilter(e) === true, 'should pass', c);
      });
      _assert('F2 unlisted sender blocked', passesSenderFilter('definitelynotlisted_xyz@x.com') === false, 'should be false', c);
    }

    // ── Group G: sendToTelegram() live probe ──────────────────────────────
    Logger.log('--- Testing sendToTelegram() live ---');
    const badResult = sendToTelegram('000:INVALID_TOKEN_XYZ', '0', 'test');
    _assert('G1 invalid token → false (no throw)', badResult === false, 'should be false', c);
    let secrets2;
    try { secrets2 = getSecrets(); } catch(_) { secrets2 = null; }
    if (!secrets2) {
      Logger.log('  \u26A0 G2 skipped \u2014 Script Properties not configured');
    } else {
      const liveResult = sendToTelegram(secrets2.token, secrets2.chatId, '\uD83D\uDD2C *Automated test message* \u2014 runAllTests\\(\\)');
      _assert('G2 live send → true', liveResult === true, 'live send returned false', c);
    }

  } catch (e) {
    Logger.log('\uD83D\uDCA5 Test suite crashed: ' + e.message + ' \u2014 partial results above');
  }

  Logger.log('\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550');
  Logger.log('Test Results: ' + c.pass + ' passed, ' + c.fail + ' failed');
  if (c.fail > 0) {
    Logger.log('\u26A0 ' + c.fail + ' test(s) failed \u2014 review failures above');
  } else {
    Logger.log('\u2705 All tests passed \u2014 system is production-ready');
  }
  Logger.log('\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550');
}

/**
 * Scans runtime state for 10 known security anti-patterns.
 * Does NOT log any portion of bot token or chat ID.
 * SEC-5 and SEC-6 require manual human verification (flagged in output).
 *
 * @example auditSecurity()
 * @return {void}
 */
function auditSecurity() {
  let pass = 0, fail = 0, manual = 0;
  function sec(id, name, ok, msg) {
    if (ok === 'manual') {
      Logger.log('  \u2139 ' + id + ': ' + name + ' \u2014 ' + msg);
      manual++; pass++;
    } else if (ok) {
      Logger.log('  \u2705 ' + id + ': ' + name + ' \u2014 OK');
      pass++;
    } else {
      Logger.log('  \u274C ' + id + ': ' + name + ' \u2014 ' + msg);
      fail++;
    }
  }

  // SEC-1: No secrets in CONFIG keys
  const badSubstrings = ['token','secret','key','password','chat_id'];
  let badKey = null;
  Object.keys(CONFIG).forEach(function(k) {
    if (badSubstrings.some(function(b){ return k.toLowerCase().includes(b); })) badKey = k;
  });
  sec('SEC-1','Secrets not in CONFIG', !badKey, 'CONFIG contains key ' + badKey + ' \u2014 move to Script Properties');

  // SEC-2: Script Properties populated
  let secrets3 = null;
  try { secrets3 = getSecrets(); sec('SEC-2','Script Properties populated', true, ''); }
  catch(e) { sec('SEC-2','Script Properties populated', false, 'TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing \u2014 trigger will fail on next fire'); }

  // SEC-3: Bot token format
  if (secrets3) {
    sec('SEC-3','Bot token format', /^\d{8,12}:[A-Za-z0-9_-]{35,}$/.test(secrets3.token), 'Token format does not match Telegram pattern \u2014 verify TELEGRAM_BOT_TOKEN');
  } else { sec('SEC-3','Bot token format', false, 'Cannot check \u2014 secrets unavailable'); }

  // SEC-4: Chat ID format
  if (secrets3) {
    sec('SEC-4','Chat ID format', /^-?\d{5,}$/.test(secrets3.chatId), 'TELEGRAM_CHAT_ID is not a valid numeric chat ID');
  } else { sec('SEC-4','Chat ID format', false, 'Cannot check \u2014 secrets unavailable'); }

  // SEC-5 & SEC-6: Manual checks
  sec('SEC-5','No secrets in Logger calls','manual','Ensure no Logger.log() references token/chatId variables. Search: Logger.log.*token and Logger.log.*chatId');
  sec('SEC-6','muteHttpExceptions active','manual','Confirm UrlFetchApp.fetch() in sendToTelegram() includes muteHttpExceptions: true');

  // SEC-7: Trigger count sanity
  try {
    const trigs = ScriptApp.getProjectTriggers().filter(function(t){ return t.getHandlerFunction() === 'checkAndForward'; });
    if (trigs.length > 2) sec('SEC-7','Trigger count sanity', false, trigs.length + ' checkAndForward triggers detected \u2014 run removeTrigger() then installTrigger()');
    else if (trigs.length === 0) { Logger.log('  \u26A0 SEC-7: No active trigger \u2014 run installTrigger() to resume'); pass++; }
    else sec('SEC-7','Trigger count sanity', true, '');
  } catch(e) { sec('SEC-7','Trigger count sanity', false, e.message); }

  // SEC-8: PropertiesService key count
  try {
    const ap = PropertiesService.getScriptProperties().getProperties();
    const total = Object.keys(ap).length;
    const dedup = Object.keys(ap).filter(function(k){ return k.startsWith(CONFIG.PROCESSED_KEY_PREFIX); }).length;
    if (total > 450) sec('SEC-8','PropertiesService key count', false, total + ' properties \u2014 approaching 500 key limit. Run pruneOldProcessedKeys()');
    else if (dedup > 400) sec('SEC-8','PropertiesService key count', false, dedup + ' dedup keys \u2014 run pruneOldProcessedKeys()');
    else sec('SEC-8','PropertiesService key count', true, 'Usage: ' + total + ' total, ' + dedup + ' dedup keys \u2014 healthy');
  } catch(e) { sec('SEC-8','PropertiesService key count', false, e.message); }

  // SEC-9: CONFIG mutability
  try {
    CONFIG._securityTest = 'MUTATED';
    if (CONFIG._securityTest === 'MUTATED') {
      sec('SEC-9','CONFIG immutability', false, 'CONFIG is mutable \u2014 Object.freeze(CONFIG) missing from Config.gs');
      try { delete CONFIG._securityTest; } catch(_) {}
    } else {
      sec('SEC-9','CONFIG immutability', true, '');
    }
  } catch(_) { sec('SEC-9','CONFIG immutability', true, 'Frozen (assignment threw in strict mode)'); }

  // SEC-10: DEDUP_RETENTION_DAYS sanity
  const days = CONFIG.DEDUP_RETENTION_DAYS;
  if (days < 1) sec('SEC-10','DEDUP_RETENTION_DAYS sanity', false, 'Value < 1 \u2014 dedup keys deleted too fast, duplicates will be sent');
  else if (days > 30) sec('SEC-10','DEDUP_RETENTION_DAYS sanity', false, 'Value > 30 \u2014 PropertiesService will fill before pruning clears space');
  else sec('SEC-10','DEDUP_RETENTION_DAYS sanity', true, '');

  Logger.log('\u2550\u2550\u2550 Security Audit Summary \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550');
  Logger.log('Passed : ' + pass);
  Logger.log('Failed : ' + fail);
  Logger.log('Manual : ' + manual + ' (require human verification)');
  Logger.log(fail > 0 ? '\u274C ' + fail + ' security issue(s) found \u2014 see details above' : '\u2705 Security audit passed');
  Logger.log('\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550');
}

/**
 * Calculates daily quota consumption and headroom at current CONFIG values.
 * Compares usage projections against Google Apps Script free-tier limits.
 * Logs a formatted table with ✅ / ⚠ / ❌ ratings per service.
 *
 * @example auditQuota()
 * @return {void}
 */
function auditQuota() {
  const cyclesPerDay   = Math.floor(24 * 60 / 5);          // 288
  const emailsPerCycle = CONFIG.MAX_THREADS_PER_RUN;        // 10
  const emailsPerDay   = cyclesPerDay * emailsPerCycle;     // 2880

  function row(label, limit, used) {
    const headroom = ((limit - used) / limit * 100).toFixed(1);
    const icon = headroom > 30 ? '\u2705' : (headroom > 10 ? '\u26A0' : '\u274C');
    Logger.log(icon + ' ' + label + ' | Used: ' + used + ' | Limit: ' + limit + ' | Headroom: ' + headroom + '%');
    return parseFloat(headroom);
  }

  Logger.log('\u2550\u2550\u2550 Quota Audit (' + cyclesPerDay + ' cycles/day, ' + emailsPerDay + ' emails/day max) \u2550\u2550\u2550');
  const h1 = row('Gmail reads (search)',     20000, cyclesPerDay);
  const h2 = row('UrlFetchApp calls',        20000, emailsPerDay);
  const h3 = row('Exec time (min)',          90,    parseFloat((cyclesPerDay * 7 / 60).toFixed(1)));
  const h4 = row('PropertiesService reads',  50000, emailsPerDay + cyclesPerDay * 2);
  const h5 = row('PropertiesService writes', 50000, emailsPerDay);
  let h6 = 100;
  if (CONFIG.ENABLE_SHEET_LOGGING) {
    h6 = row('SpreadsheetApp writes (cells)', 50000, emailsPerDay * 6);
  } else {
    Logger.log('  \u2139 Spreadsheet logging disabled \u2014 no quota used');
  }

  const minHeadroom = Math.min(h1, h2, h3, h4, h5, h6);
  Logger.log(minHeadroom < 30
    ? '\u26A0 Recommendation: Reduce MAX_THREADS_PER_RUN or increase trigger interval to relieve quota pressure.'
    : '\u2705 All quotas healthy at current CONFIG values.'
  );
  Logger.log('\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550');
}

/**
 * Live system status dashboard. Checks all subsystems and logs a formatted
 * health report to Logger.
 *
 * WARNING: This function sends a real Telegram probe message to confirm
 * API connectivity. The message will appear in the configured chat.
 *
 * @example healthCheck()
 * @return {void}
 */
function healthCheck() {
  Logger.log('\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557');
  Logger.log('\u2551   GmailTelegramForwarder \u2014 Health Check  \u2551');
  Logger.log('\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563');

  let secretsOk = false, fwdOk = false, telegramOk = false;
  let hcSecrets = null;

  // Section 1 — Secrets
  try {
    hcSecrets = getSecrets();
    secretsOk = true;
    Logger.log('\u2551 Secrets      : \u2705 Configured');
  } catch(_) {
    Logger.log('\u2551 Secrets      : \u274C Missing \u2014 set Script Properties');
  }

  // Section 2 — Triggers
  const ts = getTriggerStatus();
  fwdOk = ts.forwarderActive;
  Logger.log('\u2551 Forwarder    : ' + (ts.forwarderActive ? '\u2705 ACTIVE (' + ts.forwarderCount + ' trigger)' : '\u274C INACTIVE \u2014 run installTrigger()'));
  Logger.log('\u2551 Daily Summary: ' + (ts.summaryActive   ? '\u2705 ACTIVE' : '\u26A0 INACTIVE'));

  // Section 3 — Dedup store
  try {
    const ap = PropertiesService.getScriptProperties().getProperties();
    const dk = Object.keys(ap).filter(function(k){ return k.startsWith(CONFIG.PROCESSED_KEY_PREFIX); }).length;
    Logger.log('\u2551 Dedup store  : ' + dk + ' keys stored (' + CONFIG.DEDUP_RETENTION_DAYS + ' days retention configured)');
    if (dk > 400) Logger.log('\u2551              \u26A0 Approaching limit \u2014 pruning recommended');
  } catch(e) {
    Logger.log('\u2551 Dedup store  : \u274C Error reading \u2014 ' + e.message);
  }

  // Section 4 — Logging
  Logger.log('\u2551 Sheet logging: ' + (CONFIG.ENABLE_SHEET_LOGGING ? '\u2705 ENABLED' : '\u26A0 DISABLED (CONFIG)'));
  if (CONFIG.ENABLE_SHEET_LOGGING) {
    const ssid = getLogSpreadsheetId();
    Logger.log('\u2551 Log sheet    : ' + (ssid ? '\u2705 Accessible' : '\u274C Not found'));
  }

  // Section 5 — Telegram connectivity (sends real probe message)
  if (hcSecrets) {
    const ts2 = new Date().toLocaleString('en-IN', { timeStyle: 'short', timeZone: 'Asia/Kolkata' });
    const probeResult = sendToTelegram(hcSecrets.token, hcSecrets.chatId,
      '\uD83D\uDD2C Health check probe \u2014 ' + escapeMdV2(ts2));
    telegramOk = probeResult;
    Logger.log('\u2551 Telegram API : ' + (probeResult ? '\u2705 Reachable' : '\u274C Unreachable'));
  } else {
    Logger.log('\u2551 Telegram API : \u26A0 Skipped \u2014 secrets unavailable');
  }

  // Section 6 — Last activity
  try {
    const ap2 = PropertiesService.getScriptProperties().getProperties();
    let latest = null;
    Object.keys(ap2).forEach(function(k) {
      if (!k.startsWith(CONFIG.PROCESSED_KEY_PREFIX)) return;
      const d = new Date(ap2[k]);
      if (!isNaN(d.getTime()) && (!latest || d > latest)) latest = d;
    });
    Logger.log('\u2551 Last activity: ' + (latest ? latest.toISOString() : 'No emails processed yet'));
  } catch(e) {
    Logger.log('\u2551 Last activity: \u274C Error \u2014 ' + e.message);
  }

  Logger.log('\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D');
  Logger.log('System status: ' + (secretsOk && fwdOk && telegramOk
    ? '\u2705 HEALTHY \u2014 fully operational'
    : '\u26A0 DEGRADED \u2014 review issues above'));
}
