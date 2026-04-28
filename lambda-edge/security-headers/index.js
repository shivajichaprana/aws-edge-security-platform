/**
 * Lambda@Edge - Security Headers
 *
 * Trigger:  CloudFront viewer-response
 * Purpose:  Inject a hardened set of security headers onto every response
 *           returned to the viewer. Centralising this at the edge guarantees
 *           consistent posture regardless of which origin (ALB, S3, etc.)
 *           served the underlying object.
 *
 * Headers set:
 *   - Strict-Transport-Security  (HSTS, 2 years, subdomains, preload)
 *   - Content-Security-Policy    (locked-down baseline; relax per app)
 *   - X-Frame-Options            (DENY - clickjacking protection)
 *   - X-Content-Type-Options     (nosniff)
 *   - Referrer-Policy            (strict-origin-when-cross-origin)
 *   - Permissions-Policy         (deny dangerous features by default)
 *   - X-XSS-Protection           (legacy browsers)
 *   - Cross-Origin-Opener-Policy (same-origin)
 *   - Cross-Origin-Resource-Policy (same-site)
 *
 * Headers removed (information disclosure):
 *   - Server, X-Powered-By, X-AspNet-Version
 *
 * Notes on Lambda@Edge constraints:
 *   - Must be a Node.js 18.x function deployed in us-east-1.
 *   - Cannot use environment variables (use code constants).
 *   - Function must be a published version (not $LATEST) when associated.
 *   - Response size <= 1 MB (viewer-response).
 */

'use strict';

// CSP: a tight baseline. Relax by replacing 'self' tokens with allowed origins
// for production. Keep it strict for the edge-platform reference distribution.
const CSP =
  "default-src 'self'; " +
  "script-src 'self' 'strict-dynamic'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data: https:; " +
  "font-src 'self' data:; " +
  "connect-src 'self'; " +
  "frame-ancestors 'none'; " +
  "form-action 'self'; " +
  "base-uri 'self'; " +
  "object-src 'none'; " +
  "upgrade-insecure-requests";

const PERMISSIONS_POLICY = [
  'accelerometer=()',
  'autoplay=()',
  'camera=()',
  'cross-origin-isolated=()',
  'display-capture=()',
  'encrypted-media=()',
  'fullscreen=(self)',
  'geolocation=()',
  'gyroscope=()',
  'keyboard-map=()',
  'magnetometer=()',
  'microphone=()',
  'midi=()',
  'payment=()',
  'picture-in-picture=()',
  'publickey-credentials-get=()',
  'screen-wake-lock=()',
  'sync-xhr=()',
  'usb=()',
  'web-share=()',
  'xr-spatial-tracking=()'
].join(', ');

// Headers the origin may leak that we want stripped before the response leaves
// the edge.
const HEADERS_TO_STRIP = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version'
];

/**
 * Sets a single header on the CloudFront response object using the
 * Lambda@Edge canonical header shape: { key, value }.
 */
function setHeader(headers, name, value) {
  headers[name.toLowerCase()] = [{ key: name, value: String(value) }];
}

exports.handler = (event, context, callback) => {
  const response = event.Records[0].cf.response;
  const headers = response.headers || {};

  // --- Strip information-disclosure headers from origin ----------------------
  for (const name of HEADERS_TO_STRIP) {
    if (headers[name]) {
      delete headers[name];
    }
  }

  // --- Inject hardened security header set -----------------------------------
  setHeader(
    headers,
    'Strict-Transport-Security',
    'max-age=63072000; includeSubDomains; preload'
  );
  setHeader(headers, 'Content-Security-Policy', CSP);
  setHeader(headers, 'X-Frame-Options', 'DENY');
  setHeader(headers, 'X-Content-Type-Options', 'nosniff');
  setHeader(headers, 'Referrer-Policy', 'strict-origin-when-cross-origin');
  setHeader(headers, 'Permissions-Policy', PERMISSIONS_POLICY);
  setHeader(headers, 'X-XSS-Protection', '1; mode=block');
  setHeader(headers, 'Cross-Origin-Opener-Policy', 'same-origin');
  setHeader(headers, 'Cross-Origin-Resource-Policy', 'same-site');
  setHeader(headers, 'X-DNS-Prefetch-Control', 'off');

  // Cache-Control fallback for HTML - stop intermediaries holding sensitive
  // pages. Static assets keep whatever Cache-Control the origin set.
  const contentType =
    (headers['content-type'] && headers['content-type'][0].value) || '';
  if (contentType.toLowerCase().startsWith('text/html')) {
    setHeader(
      headers,
      'Cache-Control',
      'no-store, no-cache, must-revalidate, proxy-revalidate'
    );
  }

  response.headers = headers;
  callback(null, response);
};
