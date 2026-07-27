/*
 * ═══════════════════════════════════════════════════════
 * GmailTelegramForwarder — Operator Reference
 * Version: 2.0 (Production) | Phase: 6 of 6 (Complete)
 * ═══════════════════════════════════════════════════════
 *
 * FIRST-TIME SETUP (run once, in this order):
 *   1. Project Settings → Script Properties → Add:
 *        TELEGRAM_BOT_TOKEN = [token from @BotFather]
 *        TELEGRAM_CHAT_ID   = [chat ID from getUpdates]
 *   2. Run: testSendMessage()     → verify Telegram works
 *   3. Run: runAllTests()         → verify all components
 *   4. Run: auditSecurity()       → verify no security issues
 *   5. Run: installTrigger()      → start auto-forwarding
 *   6. Optional: installDailySummaryTrigger() → 8 AM digest
 *   7. Optional: set ENABLE_SHEET_LOGGING: true for audit trail
 *
 * DAILY OPERATIONS:
 *   healthCheck()          → full system status in Logger
 *   getTriggerStatus()     → verify triggers are active
 *   auditQuota()           → check quota headroom
 *
 * PAUSING / STOPPING:
 *   removeTrigger()        → pause all automatic execution
 *   installTrigger()       → resume (idempotent, safe to re-run)
 *
 * TROUBLESHOOTING:
 *   Duplicate messages     → run pruneOldProcessedKeys() manually
 *   Emails not forwarding  → run healthCheck() + auditSecurity()
 *   Telegram 400 error     → subject/body has unescaped MarkdownV2
 *                            chars — check escapeMdV2() patch notes
 *   PropertiesService full → run pruneOldProcessedKeys() manually
 *   Trigger not firing     → check Apps Script quota in
 *                            console.cloud.google.com
 *
 * MULTI-ACCOUNT SETUP:
 *   For each additional Gmail account:
 *   Gmail Settings → Forwarding → Add forwarding address
 *   → Forward to: [your main Gmail address]
 *   → Confirm the verification email
 *
 * QUOTA LIMITS (free tier):
 *   Gmail reads       : 20,000 / day
 *   URL fetches       : 20,000 / day
 *   Script exec time  : 90 minutes / day
 *   Properties reads  : 50,000 / day
 *   Properties writes : 50,000 / day
 *   Max properties    : 500 keys (pruning manages this)
 *
 * ═══════════════════════════════════════════════════════
 */

/**
 * @file Config.gs
 * @description Central configuration object for the GmailTelegramForwarder.
 *              All tuneable parameters live here. No secrets are stored here —
 *              sensitive values (bot token, chat ID) are loaded at runtime from
 *              Script Properties via getSecrets() in Code.gs.
 *
 * @author      Ajit
 * @version     2.0
 * @phase       6 of 6 (Complete)
 */

/**
 * Global configuration for GmailTelegramForwarder.
 * Modify values here to change runtime behaviour without touching logic files.
 *
 * @const {Object} CONFIG
 */
const CONFIG = {

  // ─────────────────────────────────────────────────────────────────────────
  // Gmail Settings
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Gmail search query used to fetch threads each run.
   * Supports any Gmail search operator (e.g. 'is:unread', 'is:unread from:boss@example.com').
   * Keep this as narrow as possible to limit API quota usage.
   * @type {string}
   */
  GMAIL_SEARCH_QUERY: 'is:unread newer_than:1d',

  /**
   * Maximum number of Gmail threads to process in a single trigger execution.
   * Must be between 1 and 20. Values above 20 risk hitting Apps Script's
   * 6-minute execution time limit and Gmail API rate limits.
   * @type {number}
   */
  MAX_THREADS_PER_RUN: 10,

  /**
   * Number of characters to include in the email body preview sent to Telegram.
   * 280 mirrors a tweet-length snippet; increase for more context,
   * decrease to keep Telegram messages compact.
   * @type {number}
   */
  BODY_PREVIEW_CHARS: 280,

  // ─────────────────────────────────────────────────────────────────────────
  // Label Settings
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Name of the Gmail label applied to threads after successful forwarding.
   * The label is created automatically if it does not already exist.
   * Rename to any valid Gmail label string (e.g. 'Forwarded/Telegram').
   * @type {string}
   */
  PROCESSED_LABEL: '',

  // ─────────────────────────────────────────────────────────────────────────
  // Deduplication Settings
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Prefix for keys stored in Script Properties to track processed message IDs.
   * Combined with a message ID it forms a unique key, e.g. 'processed_msg_18abc123'.
   * Change only if you need to namespace multiple forwarder instances.
   * @type {string}
   */
  PROCESSED_KEY_PREFIX: 'processed_msg_',

  /**
   * Number of days to retain processed-message keys in Script Properties.
   * Keys older than this are pruned by pruneOldProcessedKeys() to prevent
   * hitting the 9 KB Script Properties storage limit.
   * Valid range: 1–30 days.
   * @type {number}
   */
  DEDUP_RETENTION_DAYS: 7,

  // ─────────────────────────────────────────────────────────────────────────
  // Logging Settings
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Set to true to write structured log rows to a Google Sheet on every run.
   * Requires LOG_SPREADSHEET_ID to be set in Script Properties (Phase 5).
   * When false, logging is written only to Apps Script's built-in Logger.
   * @type {boolean}
   */
  ENABLE_SHEET_LOGGING: false,

  /**
   * Name of the worksheet tab used for structured logging.
   * The tab is created automatically if ENABLE_SHEET_LOGGING is true and
   * the sheet does not already contain a tab with this name.
   * @type {string}
   */
  LOG_SHEET_NAME: 'ForwarderLog',

  // ─────────────────────────────────────────────────────────────────────────
  // Filtering Settings
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Allowlist of sender email addresses to forward.
   * If the array is empty, emails from ALL senders are eligible.
   * If populated, only messages whose 'From' address matches one of the
   * listed addresses (case-insensitive) will be forwarded.
   * Example: ['ajit.info999@gmail.com', 'ajitbro111@gmail.com']
   * @type {string[]}
   */
  ALLOWED_SENDERS: [],

  /**
   * List of keywords that must appear (case-insensitive) in the email subject
   * for the message to be forwarded.
   * If the array is empty, no subject filtering is applied.
   * All keywords in the list must be present (AND logic).
   * Example: ['URGENT', 'ACTION REQUIRED']
   * @type {string[]}
   */
  REQUIRED_SUBJECT_KEYWORDS: [],

  // ─────────────────────────────────────────────────────────────────────────
  // Telegram Settings
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Telegram Bot API parse mode for outgoing messages.
   * Valid values: 'MarkdownV2' | 'Markdown' | 'HTML'
   * 'MarkdownV2' is recommended; it supports richer formatting and is the
   * current Telegram standard. If switching to 'HTML', update
   * formatTelegramMessage() accordingly.
   * @type {string}
   */
  TELEGRAM_PARSE_MODE: 'MarkdownV2',

  /**
   * When true, Telegram will not generate a link preview for URLs in messages.
   * Recommended: true — previews can make forwarded emails look cluttered.
   * @type {boolean}
   */
  DISABLE_WEB_PAGE_PREVIEW: true,

  // ─────────────────────────────────────────────────────────────────────────
  // Attachment Forwarding Settings
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Master on/off switch for forwarding email attachments to Telegram.
   * When true, attachments are sent via sendDocument after the text notification.
   * When false, attachment forwarding is completely disabled.
   * @type {boolean}
   */
  ENABLE_ATTACHMENT_FORWARDING: true,

  /**
   * Maximum attachment size in megabytes that will be uploaded to Telegram.
   * Attachments exceeding this limit are skipped and logged, never uploaded.
   * Must never exceed 50 — the Telegram Bot API hard limit for sendDocument.
   * Recommended: 25 (conservative margin below the API ceiling).
   * @type {number}
   */
  MAX_ATTACHMENT_MB: 25,

  /**
   * When true, inline images embedded in the email body (e.g. signature logos,
   * tracking pixels) are excluded from attachment forwarding. Only genuine
   * file attachments visible to the recipient are forwarded.
   * When false, all attachments including inline images are forwarded.
   * @type {boolean}
   */
  EXCLUDE_INLINE_IMAGES: true,
};


/*
 * ═══════════════════════════════════════════════════════════════════════════
 * SCRIPT PROPERTIES SETUP — READ BEFORE FIRST RUN
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Secrets and environment-specific values are stored as Script Properties,
 * NOT in this file. Follow the steps below to configure them.
 *
 * NAVIGATION PATH:
 *   Apps Script Editor
 *     → Project Settings (gear ⚙ icon, left sidebar)
 *     → Script Properties section
 *     → "Add row" for each key-value pair below
 *
 * ───────────────────────────────────────────────────────────────────────────
 * REQUIRED PROPERTIES  (the forwarder will not run without these)
 * ───────────────────────────────────────────────────────────────────────────
 *
 *   Key: TELEGRAM_BOT_TOKEN
 *   Value: <your bot token from @BotFather, e.g. 7123456789:AAFxyz...>
 *
 *   Key: TELEGRAM_CHAT_ID
 *   Value: <numeric chat/channel ID, e.g. -1001234567890>
 *         Tip: send a message to your bot, then call
 *         https://api.telegram.org/bot<TOKEN>/getUpdates
 *         to find your chat ID.
 *
 * ───────────────────────────────────────────────────────────────────────────
 * OPTIONAL PROPERTIES  (leave unset if the feature is not used)
 * ───────────────────────────────────────────────────────────────────────────
 *
 *   Key: ANTHROPIC_API_KEY
 *   Value: <API key from console.anthropic.com>
 *          Only required if AI-powered email summarisation is enabled
 *          (implemented in Phase 4).
 *
 *   Key: LOG_SPREADSHEET_ID
 *   Value: <Google Sheets file ID>
 *          Required only when ENABLE_SHEET_LOGGING is true.
 *          The spreadsheet is auto-created during Phase 5 setup;
 *          paste the resulting ID here afterwards.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 */

/**
 * Freeze CONFIG to prevent accidental mutation at runtime.
 * All configuration changes must be made in this file only.
 */
Object.freeze(CONFIG);
