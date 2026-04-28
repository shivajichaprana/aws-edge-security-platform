/**
 * Lambda@Edge - Geo Router
 *
 * Trigger:  CloudFront origin-request
 * Purpose:  Route incoming requests to the closest regional origin based on
 *           the viewer's country (CloudFront-Viewer-Country header), reducing
 *           latency and supporting data-residency requirements (EU traffic
 *           must terminate at the EU origin).
 *
 * Event shape: origin-request gives us the Records[0].cf.request object with
 * a mutable `origin` field that we can rewrite to point at a different ALB.
 *
 * Required headers (auto-added by CloudFront when the cache policy allows):
 *   - cloudfront-viewer-country
 *
 * Region resolution table:
 *   EU member states + UK + EFTA -> eu-west-1 origin
 *   APAC                          -> ap-southeast-2 origin
 *   default                       -> us-east-1 origin (primary)
 *
 * Notes on Lambda@Edge constraints:
 *   - Origin replacement must keep the same protocol/port semantics.
 *   - Custom origin requires `domainName` and `customOriginConfig` block.
 *   - Cache key MUST include `cloudfront-viewer-country` (configure via the
 *     associated cache policy) or all viewers share one cached object.
 */

'use strict';

// --- Region origin table -----------------------------------------------------
// Replace these domains with the regional ALB DNS names in your environment.
// They are placeholders for the reference implementation.
const ORIGINS = {
  'us-east-1': {
    domainName: 'origin-us.example.internal',
    region: 'us-east-1'
  },
  'eu-west-1': {
    domainName: 'origin-eu.example.internal',
    region: 'eu-west-1'
  },
  'ap-southeast-2': {
    domainName: 'origin-apac.example.internal',
    region: 'ap-southeast-2'
  }
};

// --- Country -> region map ---------------------------------------------------
// EU/EEA + UK + EFTA route to eu-west-1.
const EU_COUNTRIES = new Set([
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR',
  'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK',
  'SI', 'ES', 'SE',
  // UK + EFTA
  'GB', 'CH', 'NO', 'IS', 'LI'
]);

// APAC region — anything outside this and the EU set falls back to US.
const APAC_COUNTRIES = new Set([
  'AU', 'NZ', 'SG', 'JP', 'KR', 'HK', 'TW', 'IN', 'ID', 'MY', 'TH', 'VN',
  'PH'
]);

/**
 * Maps an ISO-3166-1 alpha-2 country code to a target AWS region.
 *
 * @param {string} country two-letter country code from CloudFront
 * @returns {string} AWS region key into the ORIGINS table
 */
function regionForCountry(country) {
  if (!country) return 'us-east-1';
  const cc = country.toUpperCase();
  if (EU_COUNTRIES.has(cc)) return 'eu-west-1';
  if (APAC_COUNTRIES.has(cc)) return 'ap-southeast-2';
  return 'us-east-1';
}

/**
 * Replaces the request's origin block with the chosen regional origin.
 * Preserves headers, path, and query string.
 */
function setCustomOrigin(request, origin) {
  request.origin = {
    custom: {
      domainName: origin.domainName,
      port: 443,
      protocol: 'https',
      path: '',
      sslProtocols: ['TLSv1.2'],
      readTimeout: 30,
      keepaliveTimeout: 5,
      customHeaders: {}
    }
  };
  // CloudFront uses the Host header to forward to the origin; align it with
  // the new origin domain to avoid TLS SNI mismatches.
  request.headers['host'] = [{ key: 'host', value: origin.domainName }];
}

exports.handler = (event, context, callback) => {
  const request = event.Records[0].cf.request;
  const headers = request.headers || {};

  // CloudFront populates this header when the cache policy or origin request
  // policy enables it. If absent, we cannot route - default to primary.
  const countryHeader = headers['cloudfront-viewer-country'];
  const country =
    countryHeader && countryHeader.length > 0 ? countryHeader[0].value : null;

  const region = regionForCountry(country);
  const origin = ORIGINS[region];

  // Inject diagnostic headers so downstream services / logs can see the
  // routing decision. These are forwarded to the origin only, not the viewer.
  request.headers['x-edge-routed-region'] = [
    { key: 'X-Edge-Routed-Region', value: region }
  ];
  request.headers['x-edge-viewer-country'] = [
    { key: 'X-Edge-Viewer-Country', value: country || 'unknown' }
  ];

  setCustomOrigin(request, origin);
  callback(null, request);
};

// Exported for unit tests.
module.exports.regionForCountry = regionForCountry;
