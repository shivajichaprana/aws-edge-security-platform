/**
 * CloudFront Function - URL Rewrite
 *
 * Trigger:  viewer-request (CloudFront Functions only support viewer-* events)
 * Purpose:  Lightweight, sub-millisecond URL normalisation done at every edge
 *           POP. CloudFront Functions are MUCH cheaper and faster than
 *           Lambda@Edge for simple rewrites - they have no cold start, no
 *           network calls, and a 1 ms execution budget.
 *
 * What it does:
 *   1. Appends `index.html` to URIs that look like a directory (end in `/`).
 *   2. Appends `.html` to clean URLs (no extension, no trailing slash).
 *   3. Lower-cases the path component to ensure cache key consistency.
 *   4. Rewrites legacy `/api/v0/*` paths to `/api/v1/*` (deprecation shim).
 *   5. Strips duplicate slashes that some clients emit (`//foo` -> `/foo`).
 *
 * IMPORTANT: CloudFront Functions runtime is a restricted ECMAScript-5.1+
 * environment. No ES modules, no async/await, no third-party packages, no
 * crypto, no fetch. Keep it small and synchronous.
 *
 * Function size limit: 10 KB. Execution time limit: 1 ms CPU.
 */

function handler(event) {
    var request = event.request;
    var uri = request.uri;

    // 1. Collapse duplicate slashes (e.g. //about//team -> /about/team).
    //    Use a manual loop — CloudFront Functions runtime does not support
    //    String.prototype.replaceAll().
    while (uri.indexOf('//') !== -1) {
        uri = uri.replace('//', '/');
    }

    // 2. Lowercase the path. Query strings keep their original case because
    //    they may carry case-sensitive tokens (signatures, IDs).
    uri = uri.toLowerCase();

    // 3. Legacy API rewrite: /api/v0/foo -> /api/v1/foo
    if (uri.indexOf('/api/v0/') === 0) {
        uri = '/api/v1/' + uri.substring('/api/v0/'.length);
    }

    // 4. Append index.html for directory-style URIs.
    if (uri.endsWith('/')) {
        uri = uri + 'index.html';
    } else {
        // 5. Append .html for clean URLs (no trailing slash, no extension).
        //    We detect "no extension" by looking for a '.' in the last path
        //    segment.
        var lastSlash = uri.lastIndexOf('/');
        var lastSegment = uri.substring(lastSlash + 1);
        if (lastSegment.length > 0 && lastSegment.indexOf('.') === -1) {
            uri = uri + '.html';
        }
    }

    request.uri = uri;
    return request;
}
