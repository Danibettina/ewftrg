'use strict';

const crypto = require('node:crypto');
const { isIP } = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { verifyVisitor, crawlerPattern, automationPattern } = require('./verification');
const secretFile = path.join(__dirname, 'visit-secret.key');

// A per-process random secret would reset every visit cookie on restart, so the secret is kept in a local file unless VISIT_COOKIE_SECRET is set.
function loadVisitSecret() {
    if (process.env.VISIT_COOKIE_SECRET) return process.env.VISIT_COOKIE_SECRET;
    try {
        const saved = fs.readFileSync(secretFile, 'utf8').trim();
        if (saved) return saved;
    } catch {}
    const secret = crypto.randomBytes(32).toString('hex');
    try {
        fs.writeFileSync(secretFile, secret, { mode: 0o600, flag: 'wx' });
        return secret;
    } catch {
        // Could not write (read-only disk or another process just created it): use that file if it exists, else keep a per-process secret.
        try { return fs.readFileSync(secretFile, 'utf8').trim() || secret; } catch { return secret; }
    }
}
const visitSecret = loadVisitSecret();
const cookieName = 'srhost_visit';
const ipApiFields = 'status,message,country,countryCode,region,regionName,city,zip,timezone,isp,org,as,asname,hosting,query';
let ipApiResumeAt = 0;
const ipApiCache = new Map();
const ipApiTtlMs = 3600000;

function cacheIpApi(ip, result) {
    if (ipApiCache.size >= 10000) ipApiCache.delete(ipApiCache.keys().next().value);
    ipApiCache.set(ip, { result, until: Date.now() + ipApiTtlMs });
}

async function V100000234983(req) {
    const address = req.socket?.remoteAddress || '';
    const ip = address.startsWith('::ffff:') && isIP(address.slice(7)) === 4 ? address.slice(7) : address;
    if (!isIP(ip)) return { ip: ip || null, error: 'Visitor IP is unavailable or invalid', response: null };
    const cached = ipApiCache.get(ip);
    if (cached && cached.until > Date.now()) return cached.result;
    if (Date.now() < ipApiResumeAt) {
        return { ip, error: 'IP API rate limit cooldown', response: null, retryAfterSeconds: Math.ceil((ipApiResumeAt - Date.now()) / 1000) };
    }

    const url = new URL(`http://ip-api.com/json/${encodeURIComponent(ip)}`);
    url.searchParams.set('fields', ipApiFields);
    try {
        const result = await fetch(url, { signal: AbortSignal.timeout(5000), redirect: 'error' });
        if (result.headers.get('x-rl') === '0' || result.status === 429) {
            const ttl = Number(result.headers.get('x-ttl'));
            ipApiResumeAt = Date.now() + (Number.isFinite(ttl) && ttl > 0 ? ttl : 60) * 1000;
        }
        const response = await result.json();
        const out = { ip, httpStatus: result.status, response };
        if (result.status === 200) cacheIpApi(ip, out);
        return out;
    } catch (error) {
        return { ip, response: null, error: error.name === 'TimeoutError' ? 'IP API request timed out' : 'IP API request failed' };
    }
}

function signVisit(value) {
    return crypto.createHmac('sha256', visitSecret).update(value).digest('hex');
}

// This only recognizes this site's cookie; it cannot inspect browser history.
function getVisitStatus(req, res) {
    const cookies = String(req.headers?.cookie || '').split(';');
    const entry = cookies.map(value => value.trim()).find(value => value.startsWith(cookieName + '='));
    const token = entry ? entry.slice(cookieName.length + 1) : '';
    let returning = false;
    if (/^[a-f0-9]{32}\.[a-f0-9]{64}$/.test(token)) {
        const [value, signature] = token.split('.');
        returning = crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(signVisit(value), 'hex'));
    }

    if (!returning) {
        const value = crypto.randomBytes(16).toString('hex');
        const secure = req.socket?.encrypted ? '; Secure' : '';
        res.setHeader('Set-Cookie', `${cookieName}=${value}.${signVisit(value)}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax${secure}`);
    }

    return { returning, message: returning ? 'Welcome' : 'Fresh browser' };
}

// These headers are spoofable hints, not proof that a visitor is human or a bot.
function checkVisitor(req) {
    const userAgent = String(req.headers?.['user-agent'] || '').trim();
    const signals = [];
    const crawlerClaim = crawlerPattern.test(userAgent);

    if (!userAgent) signals.push('missing-user-agent');
    if (crawlerClaim) signals.push('claimed-crawler');
    if (automationPattern.test(userAgent)) {
        signals.push('automation-user-agent');
    }

    return {
        signals,
        crawlerClaim,
        requiresFurtherChecks: signals.length > 0,
        // An ordinary User-Agent must never be treated as verification.
        verifiedHuman: false,
    };
}

function getVisitorDetails(req) {
    return {
        ip: req.socket?.remoteAddress || null,
        method: req.method,
        path: req.url,
        userAgent: req.headers['user-agent'] || null,
        accept: req.headers.accept || null,
        language: req.headers['accept-language'] || null,
        encoding: req.headers['accept-encoding'] || null,
        fetchSite: req.headers['sec-fetch-site'] || null,
        fetchMode: req.headers['sec-fetch-mode'] || null,
        fetchDest: req.headers['sec-fetch-dest'] || null,
        browserHints: req.headers['sec-ch-ua'] || null,
        mobileHint: req.headers['sec-ch-ua-mobile'] || null,
        platformHint: req.headers['sec-ch-ua-platform'] || null,
        assessment: checkVisitor(req),
        note: 'b = bot/crawler-related signal, o = no matching signal, f = failed or unavailable. o does not verify humanity. Header and PTR-only matches can be spoofed. IP is the direct connection address, not an untrusted forwarded header.',
    };
}

// Exposes the detection rules, so it stays off unless VISITOR_DEBUG=1 (never enable on a public site).
async function showVisitorDetails(req, res) {
    if (process.env.VISITOR_DEBUG !== '1') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Not found');
        return;
    }
    try {
        const details = getVisitorDetails(req);
        const [ipInfo, checks] = await Promise.all([V100000234983(req), verifyVisitor(req)]);
        details.checks = checks;
        details.verifications = { V100000234983: ipInfo };
        res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
        });
        res.end(JSON.stringify(details, null, 2));
    } catch {
        if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify({ error: 'Visitor details unavailable' }));
    }
}

module.exports = { checkVisitor, getVisitStatus, getVisitorDetails, showVisitorDetails, V100000234983 };
