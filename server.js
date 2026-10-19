'use strict';
const http = require('node:http');
const { getVisitStatus, showVisitorDetails } = require('./bot');

const port = Number(process.env.PORT) || 3000;

const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://localhost').pathname;

    if (pathname === '/visitor') {
        // Sets the visit cookie, then returns the detection report (only when VISITOR_DEBUG=1).
        getVisitStatus(req, res);
        return showVisitorDetails(req, res);
    }

    if (pathname === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end('<!doctype html><meta charset="utf-8"><title>Visitor check</title><p><a href="/visitor">/visitor</a> - visitor detection report</p>');
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
});

server.listen(port, () => {
    console.log(`Listening on http://localhost:${port}`);
});
