const crypto = require('crypto');
const forge = require('node-forge');

const { pki } = forge;

function generateKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
}

const subject = (commonName) => [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: 'KPI RGR' },
];

function createCsr(commonName, keys) {
    const csr = pki.createCertificationRequest();
    csr.publicKey = pki.publicKeyFromPem(keys.publicKey);
    csr.setSubject(subject(commonName));
    csr.sign(pki.privateKeyFromPem(keys.privateKey), forge.md.sha256.create());
    return pki.certificationRequestToPem(csr);
}

function buildCertificate({ publicKey, subjectName, issuerName, signingKey, serial, days, ca }) {
    const certificate = pki.createCertificate();
    certificate.publicKey = publicKey;
    certificate.serialNumber = serial;
    certificate.validity.notBefore = new Date(Date.now() - 60 * 1000);
    certificate.validity.notAfter = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    certificate.setSubject(subject(subjectName));
    certificate.setIssuer(subject(issuerName));
    certificate.setExtensions(ca
        ? [{ name: 'basicConstraints', cA: true }, { name: 'keyUsage', keyCertSign: true, cRLSign: true }]
        : [{ name: 'basicConstraints', cA: false }, { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
            { name: 'extKeyUsage', serverAuth: true, clientAuth: true }, { name: 'subjectAltName', altNames: [{ type: 2, value: subjectName }] }]);
    certificate.sign(pki.privateKeyFromPem(signingKey), forge.md.sha256.create());
    return pki.certificateToPem(certificate);
}

function createRootCertificate(name, keys) {
    return buildCertificate({
        publicKey: pki.publicKeyFromPem(keys.publicKey),
        subjectName: name,
        issuerName: name,
        signingKey: keys.privateKey,
        serial: '01',
        days: 365,
        ca: true,
    });
}

function signCsr(csrPem, { rootName, rootKeys, serial }) {
    const csr = pki.certificationRequestFromPem(csrPem);
    if (!csr.verify()) {
        throw new Error('CSR signature is invalid');
    }
    const commonName = csr.subject.getField('CN').value;
    return {
        commonName,
        certificate: buildCertificate({
            publicKey: csr.publicKey,
            subjectName: commonName,
            issuerName: rootName,
            signingKey: rootKeys.privateKey,
            serial,
            days: 30,
            ca: false,
        }),
    };
}

function createSelfSignedCertificate(commonName, keys) {
    return buildCertificate({
        publicKey: pki.publicKeyFromPem(keys.publicKey),
        subjectName: commonName,
        issuerName: commonName,
        signingKey: keys.privateKey,
        serial: '7f',
        days: 30,
        ca: false,
    });
}

const commonNameOf = (certificatePem) => new crypto.X509Certificate(certificatePem).subject.match(/CN=([^\n]+)/)?.[1];

module.exports = { generateKeyPair, createCsr, createRootCertificate, signCsr, createSelfSignedCertificate, commonNameOf };
