/**
 * Lambda@Edge - Header Rewrite
 *
 * Trigger:  CloudFront viewer-request
 * Purpose:  (1) Strip internal-only headers that should never reach origin
 *               (defence in depth against SSRF and trusted-header abuse).
 *           (2) Inject a tracing correlation ID (X-Correlation-Id) on every
 *               request so downstream services can follow a viewer's session.
 *           (3) Normalise certain common headers (e.g. Accept-Encoding) to
 *               improve cache hit ratio.
 *
 * Notes on Lambda@Edge constraints:
 *   - viewer-request runs in EVERY edge POP (highest cost, lowest latency).
 *   - Function size <= 1 MB compressed.
 *   - Cannot use environment variables; bake config into the bundle.
 *   - No external network calls (timeout 5s, but discouraged).
 */

'use strict';

const crypto = require('crypto');

// --- Headers stripped from inbound requests ----------------------------------
// These are set by internal services and must not be trusted from the public
// internet. Removing them at the very edge prevents header smuggling.
const FORBIDDEN_INBOUND_HEADERS = [
  'x-internal-trace',
  'x-internal-user-id',
  'x-internal-tenant',
  'x-aws-id-token',
  'x-amzn-oidc-data',
  'x-amzn-oidc-identity',
  'x-amzn-oidc-accesstoken',
  'x-forwarded-server',
  'x-real-ip'
];

// Headers used purely for diagnostics that we accept but normalise.
const TRACE_HEADER = 'x-correlation-id';
const TRACE_HEADER_KEY = 'X-Correlation-Id';

/**
 * Generates a UUIDv4-style hex correlation ID using the crypto module.
 * Avoids the `uuid` package to keep the deployment bundle tiny.
 *
 * @returns {string} 32-char hex correlation id
 */
function newCorrelationId() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Very loose validation of an incoming correlation ID. Accepts hex or
 * dash-separated hex up to 64 chars. Anything else gets replaced.
 */
function isValidCorrelationId(value) {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > 64) return false;
  return /^[a-zA-Z0-9-]+$/.test(value);
}

/**
 * Normalises Accept-Encoding so CloudFront can cache one variant per
 * meaningful compression family rather than a separate entry for every
 * idiosyncratic browser ordering.
 */
function normaliseAcceptEncoding(headers) {
  const ae = headers['accept-encoding'];
  if (!ae || ae.length === 0) return;
  const value = ae[0].value.toLowerCase();
  let normalised;
  if (value.includes('br')) {
    normalised = 'br';
  } else if (value.includes('gzip')) {
    normalised = 'gzip';
  } else {
    normalised = 'identity';
  }
  headers['accept-encoding'] = [
    { key: 'Accept-Encoding', value: normalised }
  ];
}

exports.handler = (event, context, callback) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers || {};

  // --- 1. Strip forbidden inbound headers ----------------------------------
  for (const name of FORBIDDEN_INBOUND_HEADERS) {
    if (headers[name]) {
      delete headers[name];
    }
  }

  // --- 2. Inject (or preserve) a correlation ID ----------------------------
  let correlationId;
  const existing = headers[TRACE_HEADER];
  if (existing && existing.length > 0 && isValidCorrelationId(existing[0].value)) {
    correlationId = existing[0].value;
  } else {
    correlationId = newCorrelationId();
  }
  headers[TRACE_HEADER] = [{ key: TRACE_HEADER_KEY, value: correlationId }];

  // --- 3. Normalise Accept-Encoding for cache friendliness -----------------
  normaliseAcceptEncoding(headers);

  // --- 4. Tag the request as having passed the edge filter -----------------
  // Origin services can assert this header and reject requests that bypass
  // the CloudFront/edge layer.
  headers['x-edge-validated'] = [{ key: 'X-Edge-Validated', value: '1' }];

  request.headers = headers;
  callback(null, request);
};

// Exported for unit tests.
module.exports.newCorrelationId = newCorrelationId;
module.exports.isValidCorrelationId = isValidCorrelationId;
module.exports.normaliseAcceptEncoding = normaliseAcceptEncoding;
