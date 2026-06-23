/**
 * Timestamped progress logging for CLI output.
 * Logs are written to stderr so stdout remains available for JSON summaries.
 */

/**
 * @param {string} message Progress message.
 */
export function logStep(message) {
  const timestamp = new Date().toISOString().slice(11, 19);
  console.error(`[${timestamp}] ${message}`);
}

/**
 * @param {string} message Warning message.
 */
export function logWarn(message) {
  const timestamp = new Date().toISOString().slice(11, 19);
  console.error(`[${timestamp}] WARN ${message}`);
}

/**
 * Logs AI agent activity without mixing it into generic pipeline steps.
 * @param {string} message Agent progress message.
 */
export function logProgress(message) {
  const timestamp = new Date().toISOString().slice(11, 19);
  console.error(`[${timestamp}] AI ${message}`);
}

/**
 * Emits periodic heartbeat logs while a long-running step has no other output.
 * @param {string} label Human-readable step label.
 * @param {number} [intervalSec=20] Seconds between heartbeat logs.
 * @returns {() => void} Call to stop the heartbeat timer.
 */
export function startProgressHeartbeat(label, intervalSec = 20) {
  const startedAt = Date.now();
  const interval = setInterval(() => {
    const elapsedSec = Math.round((Date.now() - startedAt) / 1000);
    logProgress(`${label}... still running (${elapsedSec}s elapsed)`);
  }, intervalSec * 1000);
  interval.unref?.();
  return () => clearInterval(interval);
}
