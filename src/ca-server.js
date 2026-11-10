const crypto = require('crypto');
const http = require('http');
const { generateKeyPair, createRootCertificate, signCsr } = require('./certificates');

const PORT = Number(process.env.CA_PORT) || 4000;
const ROOT_NAME = 'RGR Root CA';

const rootKeys = generateKeyPair();
const rootPem = createRootCertificate(ROOT_NAME, rootKeys);
const root = new crypto.X509Certificate(rootPem);

const issued = new Map();
let nextSerial = 0x10;

function verifyCertificate(certificatePem, expectedName) {
    let certificate;
    try {
        certificate = new crypto.X509Certificate(certificatePem);
    } catch (e) {
        return { valid: false, reason: 'certificate cannot be parsed' };
    }

    const commonName = certificate.subject.match(/CN=([^\n]+)/)?.[1];
    const details = { subject: commonName, issuer: certificate.issuer.match(/CN=([^\n]+)/)?.[1], serial: certificate.serialNumber, validTo: certificate.validTo };
    const now = Date.now();

    if (!certificate.checkIssued(root) || !certificate.verify(root.publicKey)) {
        return { valid: false, reason: `not signed by ${ROOT_NAME}`, ...details };
    }
    if (now < Date.parse(certificate.validFrom) || now > Date.parse(certificate.validTo)) {
        return { valid: false, reason: 'certificate is expired or not yet valid', ...details };
    }
    if (issued.get(certificate.serialNumber)?.revoked) {
        return { valid: false, reason: 'certificate is revoked', ...details };
    }
    if (expectedName && commonName !== expectedName) {
        return { valid: false, reason: `certificate is issued to ${commonName}, expected ${expectedName}`, ...details };
    }
    return { valid: true, ...details };
}

const routes = {
    'GET /root': () => ({ certificate: rootPem }),

    'POST /sign': ({ csr }) => {
        const serial = (nextSerial++).toString(16).toUpperCase();
        const { commonName, certificate } = signCsr(csr, { rootName: ROOT_NAME, rootKeys, serial });
        issued.set(new crypto.X509Certificate(certificate).serialNumber, { commonName, revoked: false });
        console.log(`issued certificate #${serial} for ${commonName}`);
        return { certificate };
    },

    'POST /verify': ({ certificate, expectedName }) => {
        const result = verifyCertificate(certificate, expectedName);
        console.log(`verify ${result.subject ?? '?'} (expected ${expectedName}): ${result.valid ? 'valid' : `invalid, ${result.reason}`}`);
        return result;
    },

    'POST /revoke': ({ name }) => {
        const revoked = [...issued.values()].filter((entry) => entry.commonName === name);
        revoked.forEach((entry) => { entry.revoked = true; });
        console.log(`revoked ${revoked.length} certificate(s) of ${name}`);
        return { revoked: revoked.length };
    },
};

const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
        const route = routes[`${req.method} ${req.url}`];
        res.setHeader('Content-Type', 'application/json');
        if (!route) {
            res.statusCode = 404;
            return res.end(JSON.stringify({ error: 'not found' }));
        }
        try {
            res.end(JSON.stringify(route(body ? JSON.parse(body) : {})));
        } catch (e) {
            res.statusCode = 400;
            res.end(JSON.stringify({ error: e.message }));
        }
    });
});

server.listen(PORT, () => {
    console.log(`${ROOT_NAME} listening on http://localhost:${PORT}`);
    console.log(`root certificate fingerprint ${root.fingerprint256}`);
});
