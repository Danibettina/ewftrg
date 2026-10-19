'use strict';

const { BlockList, isIP } = require('node:net');
const { Resolver } = require('node:dns').promises;

const sources = [
    'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
    'https://developers.google.com/static/crawling/ipranges/special-crawlers.json',
    'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json',
    'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json',
    'https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json',
    'https://www.bing.com/toolbox/bingbot.json',
];
const crawlerPattern = /googlebot|googleother|google-inspectiontool|adsbot-google|mediapartners-google|storebot-google|bingbot|bingpreview|duckduckbot|baiduspider|yandexbot|applebot|gptbot|claudebot|bytespider|crawler|spider/i;
const automationPattern = /headlesschrome|phantomjs|selenium|playwright|puppeteer|python-requests|python-urllib|curl\/|wget\/|go-http-client/i;

function normalizeIp(address = '') {
    return address.startsWith('::ffff:') && isIP(address.slice(7)) === 4 ? address.slice(7) : address;
}

function approvedHostname(name) {
    const host = name.toLowerCase().replace(/\.$/, '');
    return host.endsWith('.googlebot.com') ||
        (/^(?:rate-limited-proxy-|google-proxy-)/.test(host) && host.endsWith('.google.com')) ||
        host.endsWith('.gae.googleusercontent.com') || host.endsWith('.search.msn.com');
}

// Bad entries are skipped so one malformed prefix cannot disable the whole list.
function parseRanges(data) {
    if (!Array.isArray(data.prefixes) || !data.prefixes.length) throw new Error('Invalid IP list');
    const list = new BlockList();
    let added = 0;
    for (const entry of data.prefixes) {
        const prefix = entry?.ipv4Prefix || entry?.ipv6Prefix;
        const [address, bits, extra] = typeof prefix === 'string' ? prefix.split('/') : [];
        const version = isIP(address);
        if (!version || extra !== undefined || !/^\d+$/.test(bits) || Number(bits) > (version === 4 ? 32 : 128)) continue;
        list.addSubnet(address, Number(bits), version === 4 ? 'ipv4' : 'ipv6');
        added++;
    }
    if (!added) throw new Error('No valid CIDR entries');
    return list;
}

// Loopback/private connections cannot establish an internet crawler identity.
const nonPublicRanges = parseRanges({ prefixes: [
    { ipv4Prefix: '0.0.0.0/8' }, { ipv4Prefix: '10.0.0.0/8' },
    { ipv4Prefix: '100.64.0.0/10' }, { ipv4Prefix: '127.0.0.0/8' },
    { ipv4Prefix: '169.254.0.0/16' }, { ipv4Prefix: '172.16.0.0/12' },
    { ipv4Prefix: '192.0.0.0/24' }, { ipv4Prefix: '192.168.0.0/16' },
    { ipv4Prefix: '198.18.0.0/15' }, { ipv4Prefix: '224.0.0.0/3' },
    { ipv6Prefix: '::/128' }, { ipv6Prefix: '::1/128' },
    { ipv6Prefix: 'fc00::/7' }, { ipv6Prefix: 'fe80::/10' }, { ipv6Prefix: 'ff00::/8' },
] });

function sameIp(left, right) {
    left = normalizeIp(left);
    right = normalizeIp(right);
    const version = isIP(left);
    if (!version || version !== isIP(right)) return false;
    const list = new BlockList();
    list.addAddress(left, version === 4 ? 'ipv4' : 'ipv6');
    return list.check(right, version === 4 ? 'ipv4' : 'ipv6');
}

function headerCheck(headers, ua) {
    if (!ua || !headers.accept) return 'f';
    const mode = headers['sec-fetch-mode'];
    const dest = headers['sec-fetch-dest'];
    const site = headers['sec-fetch-site'];
    if (mode && !['navigate', 'same-origin', 'no-cors', 'cors', 'websocket'].includes(mode)) return 'b';
    if (site && !['same-origin', 'same-site', 'cross-site', 'none'].includes(site)) return 'b';
    if (dest === 'document' && mode && mode !== 'navigate') return 'b';
    if (mode === 'navigate' && dest && !['document', 'iframe', 'frame', 'fencedframe'].includes(dest)) return 'b';
    if (mode === 'navigate' && /Mozilla\//i.test(ua) && !/text\/html|application\/xhtml\+xml|\*\/\*/i.test(headers.accept)) return 'b';
    return 'o';
}

function hintsCheck(headers, ua) {
    const brands = headers['sec-ch-ua'];
    const mobile = headers['sec-ch-ua-mobile'];
    const platform = headers['sec-ch-ua-platform'];
    if (!ua || (!brands && !mobile && !platform)) return 'f';
    if (mobile && !['?0', '?1'].includes(mobile)) return 'b';
    if (brands && !/^\s*"[^"\r\n]+";v="[\d.]+"(?:\s*,\s*"[^"\r\n]+";v="[\d.]+")*\s*$/.test(brands)) return 'f';
    if (platform && !/^"[^"\r\n]*"$/.test(platform)) return 'f';
    const expected = /Android/i.test(ua) ? 'Android' : /Windows/i.test(ua) ? 'Windows' : /iPhone|iPad|iPod/i.test(ua) ? 'iOS' : /CrOS/i.test(ua) ? 'Chrome OS' : /Macintosh|Mac OS X/i.test(ua) ? 'macOS' : /Linux/i.test(ua) ? 'Linux' : null;
    if (expected && platform && platform !== '""' && platform !== `"${expected}"`) return 'b';
    if (brands && /"Chromium"/i.test(brands) && /Firefox\//i.test(ua) && !/Chrome\//i.test(ua)) return 'b';
    if (brands && /"Google Chrome"/i.test(brands) && !/Chrome\//i.test(ua)) return 'b';
    return 'o';
}

function createVerifier({ fetcher = (...args) => fetch(...args), resolver = new Resolver({ timeout: 2000, tries: 1 }), now = Date.now } = {}) {
    const cache = new Map();
    async function loadSource(url) {
        const entry = cache.get(url);
        if (entry && entry.until > now()) return entry.promise;
        const item = { until: now() + 3600000 };
        item.promise = (async () => {
            try {
                const response = await fetcher(url, { signal: AbortSignal.timeout(5000), redirect: 'error' });
                if (!response.ok) throw new Error('IP list unavailable');
                return parseRanges(await response.json());
            } catch (error) {
                item.until = now() + 60000;
                throw error;
            }
        })();
        cache.set(url, item);
        return item.promise;
    }

    // Reverse DNS is cached per IP so repeat visits do not trigger a fresh lookup each time.
    const reverseCache = new Map();
    function reverseLookup(ip) {
        const entry = reverseCache.get(ip);
        if (entry && entry.until > now()) return entry.promise;
        if (reverseCache.size >= 10000) reverseCache.delete(reverseCache.keys().next().value);
        const item = { until: now() + 600000 };
        item.promise = Promise.resolve()
            .then(() => resolver.reverse(ip))
            .then(hosts => ({ hosts }), () => {
                item.until = now() + 60000;
                return { failed: true };
            });
        reverseCache.set(ip, item);
        return item.promise;
    }

    return async function verifyVisitor(req) {
        const headers = req.headers || {};
        const ua = String(headers['user-agent'] || '').trim();
        const ip = normalizeIp(req.socket?.remoteAddress || '');
        const result = {
            '1_user_agent': ua ? (crawlerPattern.test(ua) ? 'b' : 'o') : 'f',
            '2_official_ip_range': 'f',
            '3_reverse_dns': 'f',
            '4_hostname': 'f',
            '5_forward_dns': 'f',
            '6_automation_user_agent': ua ? (automationPattern.test(ua) ? 'b' : 'o') : 'f',
            '7_header_consistency': headerCheck(headers, ua),
            '8_client_hints_consistency': hintsCheck(headers, ua),
        };
        const version = isIP(ip);
        if (!version || nonPublicRanges.check(ip, version === 4 ? 'ipv4' : 'ipv6')) return result;

        const [ranges, reverse] = await Promise.all([
            Promise.allSettled(sources.map(loadSource)),
            reverseLookup(ip),
        ]);
        if (ranges.some(item => item.status === 'fulfilled' && item.value.check(ip, version === 4 ? 'ipv4' : 'ipv6'))) {
            result['2_official_ip_range'] = 'b';
        } else if (ranges.every(item => item.status === 'fulfilled')) {
            result['2_official_ip_range'] = 'o';
        }
        if (reverse.failed || !reverse.hosts.length) return result;
        const hosts = reverse.hosts.slice(0, 8).map(host => host.toLowerCase().replace(/\.$/, ''));
        const approved = hosts.filter(approvedHostname);
        // A PTR name is controlled by whoever owns the IP block, so it only counts once forward DNS confirms it.
        result['3_reverse_dns'] = approved.length ? 'b' : 'o';
        if (!approved.length) {
            result['4_hostname'] = 'o';
            result['5_forward_dns'] = 'o';
            return result;
        }
        const queries = approved.flatMap(host => [
            () => resolver.resolve4(host),
            () => resolver.resolve6(host),
        ]);
        const forward = await Promise.allSettled(queries.map(run => Promise.resolve().then(run)));
        if (forward.some(item => item.status === 'fulfilled' && item.value.some(address => sameIp(ip, address)))) {
            result['4_hostname'] = 'b';
            result['5_forward_dns'] = 'b';
        } else {
            result['4_hostname'] = 'o';
            if (forward.every(item => item.status === 'fulfilled' || ['ENODATA', 'ENOTFOUND'].includes(item.reason?.code))) {
                result['5_forward_dns'] = 'o';
            }
        }
        return result;
    };
}

const verifyVisitor = createVerifier();
module.exports = { verifyVisitor, createVerifier, parseRanges, sameIp, approvedHostname, crawlerPattern, automationPattern };
