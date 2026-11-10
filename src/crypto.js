const crypto = require('crypto');

const OAEP = { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' };

const randomHex = (bytes) => crypto.randomBytes(bytes).toString('hex');

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

function encryptPremaster(premaster, certificatePem) {
    const { publicKey } = new crypto.X509Certificate(certificatePem);
    return crypto.publicEncrypt({ key: publicKey, ...OAEP }, premaster).toString('base64');
}

function decryptPremaster(encrypted, privateKey) {
    return crypto.privateDecrypt({ key: privateKey, ...OAEP }, Buffer.from(encrypted, 'base64'));
}

function deriveSessionKeys(premaster, clientRandom, serverRandom) {
    const salt = Buffer.from(clientRandom + serverRandom, 'hex');
    const material = Buffer.from(crypto.hkdfSync('sha256', premaster, salt, 'rgr session keys', 64));
    return { client: material.subarray(0, 32), server: material.subarray(32) };
}

class RecordCipher {
    constructor(key) {
        this.key = key;
        this.seq = 0n;
    }

    nonce(seq) {
        const nonce = Buffer.alloc(12);
        nonce.writeBigUInt64BE(seq, 4);
        return nonce;
    }

    seal(payload) {
        const seq = this.seq++;
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, this.nonce(seq));
        const encrypted = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final(), cipher.getAuthTag()]);
        return { seq: Number(seq), data: encrypted.toString('base64') };
    }

    open({ seq, data }) {
        if (BigInt(seq) !== this.seq) {
            throw new Error(`unexpected record sequence ${seq}, expected ${this.seq}`);
        }
        const encrypted = Buffer.from(data, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, this.nonce(this.seq));
        decipher.setAuthTag(encrypted.subarray(-16));
        const plaintext = Buffer.concat([decipher.update(encrypted.subarray(0, -16)), decipher.final()]);
        this.seq++;
        return JSON.parse(plaintext.toString('utf8'));
    }
}

module.exports = { randomHex, sha256, encryptPremaster, decryptPremaster, deriveSessionKeys, RecordCipher };
