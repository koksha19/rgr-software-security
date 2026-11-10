const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { Link } = require('./link');
const { generateKeyPair, createCsr, createSelfSignedCertificate, commonNameOf } = require('./certificates');
const { randomHex, sha256, encryptPremaster, decryptPremaster, deriveSessionKeys, RecordCipher } = require('./crypto');

const VERSION = 'RGR-TLS 1.0';
const CIPHER_SUITE = 'RSA_WITH_AES_256_GCM_SHA256';
const HANDSHAKE_TIMEOUT_MS = 120 * 1000;
const fingerprint = (key) => sha256(key).slice(0, 16);
const short = (hex) => `${hex.slice(0, 16)}…`;
const packetsText = (count) => `${count} packet${count === 1 ? '' : 's'}`;

async function postJson(url, body) {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || response.statusText);
    }
    return data;
}

class NetworkNode {
    constructor({ id, port, topology, caUrl, rogue, log, receivedDir }) {
        this.id = id;
        this.port = port;
        this.topology = topology;
        this.caUrl = caUrl;
        this.rogue = rogue;
        this.log = log;
        this.receivedDir = receivedDir;

        this.links = new Map();
        this.sessions = new Map();
        this.pendingHandshakes = new Map();
        this.serverHandshakes = new Map();
        this.waiters = new Map();
        this.seenBroadcasts = new Set();
        this.neighbors = this.neighborsOf(id);
    }

    neighborsOf(id) {
        return this.topology.links
            .filter((link) => link.includes(id))
            .map(([a, b]) => (a === id ? b : a))
            .sort();
    }

    shortestTree(origin) {
        const parent = new Map([[origin, null]]);
        const queue = [origin];
        while (queue.length) {
            const current = queue.shift();
            for (const next of this.neighborsOf(current)) {
                if (!parent.has(next)) {
                    parent.set(next, current);
                    queue.push(next);
                }
            }
        }
        return parent;
    }

    pathTo(destination) {
        const parent = this.shortestTree(this.id);
        if (!parent.has(destination)) {
            throw new Error(`no route from ${this.id} to ${destination}`);
        }
        const route = [destination];
        while (route[0] !== this.id) {
            route.unshift(parent.get(route[0]));
        }
        return route;
    }

    treeChildren(origin) {
        const parent = this.shortestTree(origin);
        return this.neighbors.filter((neighbor) => parent.get(neighbor) === this.id);
    }

    async start() {
        this.keys = generateKeyPair();
        if (this.rogue) {
            this.certificate = createSelfSignedCertificate(this.id, this.keys);
            this.log(`generated RSA-2048 keys and a self-signed certificate (not issued by the CA)`);
        } else {
            const { certificate } = await postJson(`${this.caUrl}/sign`, { csr: createCsr(this.id, this.keys) });
            this.certificate = certificate;
            this.log(`generated RSA-2048 keys, certificate for CN=${commonNameOf(certificate)} issued by the CA`);
        }

        this.server = net.createServer((socket) => this.accept(socket));
        await new Promise((resolve) => this.server.listen(this.port, resolve));
    }

    accept(socket) {
        const link = new Link(socket, this.topology);
        link.once('message', (message) => {
            if (message.kind === 'link_hello' && this.neighbors.includes(message.from)) {
                this.attach(message.from, link);
            } else {
                socket.destroy();
            }
        });
    }

    async connect(neighbor, port) {
        const socket = await new Promise((resolve, reject) => {
            const connection = net.connect(port, 'localhost', () => resolve(connection));
            connection.once('error', reject);
        });
        const link = new Link(socket, this.topology);
        await link.send({ kind: 'link_hello', from: this.id });
        this.attach(neighbor, link);
    }

    attach(neighbor, link) {
        this.links.set(neighbor, link);
        link.on('message', (message) => this.receive(message, neighbor));
        link.on('oversize', () => this.log(`dropped a packet from ${neighbor} larger than MTU`));
        link.on('close', () => this.links.delete(neighbor));
    }

    async transmit(destination, kind, body) {
        return this.forward({ src: this.id, dst: destination, ttl: 16, kind, body });
    }

    async forward(message) {
        const nextHop = this.pathTo(message.dst)[1];
        const link = this.links.get(nextHop);
        if (!link) {
            throw new Error(`link ${this.id} — ${nextHop} is down`);
        }
        const { bytes, packets } = await link.send(message);
        return { nextHop, bytes, packets };
    }

    receive(message, neighbor) {
        if (message.dst !== this.id) {
            return this.relay(message, neighbor);
        }

        const waiter = this.waiters.get(`${message.src}:${message.kind}`);
        if (waiter) {
            this.waiters.delete(`${message.src}:${message.kind}`);
            return waiter.resolve(message.body);
        }

        const handlers = {
            client_hello: () => this.onClientHello(message.src, message.body),
            key_exchange: () => this.onKeyExchange(message.src, message.body),
            finished: () => this.onClientFinished(message.src, message.body),
            alert: () => this.onAlert(message.src, message.body),
            record: () => this.onRecord(message.src, message.body),
        };
        Promise.resolve(handlers[message.kind]?.()).catch((e) => this.log(`error handling ${message.kind} from ${message.src}: ${e.message}`));
    }

    relay(message, neighbor) {
        if (--message.ttl <= 0) {
            return this.log(`dropped ${message.kind} ${message.src} → ${message.dst}: TTL expired`);
        }
        this.forward(message)
            .then(({ nextHop, bytes, packets }) => this.log(`relay ${message.kind} ${message.src} → ${message.dst}: ${neighbor} → ${nextHop} (${bytes} B, ${packetsText(packets)})`))
            .catch((e) => this.log(`cannot relay ${message.kind} to ${message.dst}: ${e.message}`));
    }

    waitFor(peer, kind) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.waiters.delete(`${peer}:${kind}`);
                reject(new Error(`timeout waiting for ${kind} from ${peer}`));
            }, HANDSHAKE_TIMEOUT_MS);
            this.waiters.set(`${peer}:${kind}`, {
                resolve: (body) => {
                    clearTimeout(timer);
                    resolve(body);
                },
            });
        });
    }

    handshake(peer) {
        if (this.sessions.has(peer)) {
            return Promise.resolve(this.sessions.get(peer));
        }
        if (!this.pendingHandshakes.has(peer)) {
            const pending = this.clientHandshake(peer).finally(() => this.pendingHandshakes.delete(peer));
            this.pendingHandshakes.set(peer, pending);
        }
        return this.pendingHandshakes.get(peer);
    }

    async clientHandshake(peer) {
        const route = this.pathTo(peer);
        this.log(`handshake with ${peer} as client, route ${route.join(' → ')} (${route.length - 1} hop(s))`);
        const transcript = [];

        const clientHello = { version: VERSION, random: randomHex(32), cipherSuites: [CIPHER_SUITE] };
        transcript.push(['client_hello', clientHello]);
        const serverHelloReceived = this.waitFor(peer, 'server_hello');
        const sent = await this.transmit(peer, 'client_hello', clientHello);
        this.log(`1. ClientHello → ${peer}: client random ${short(clientHello.random)} (${sent.bytes} B, ${packetsText(sent.packets)})`);

        const serverHello = await serverHelloReceived;
        transcript.push(['server_hello', serverHello]);
        this.log(`2. ServerHello ← ${peer}: server random ${short(serverHello.random)}, certificate CN=${commonNameOf(serverHello.certificate)}`);

        const verification = await postJson(`${this.caUrl}/verify`, { certificate: serverHello.certificate, expectedName: peer });
        if (!verification.valid) {
            this.log(`3. CA verification FAILED: ${verification.reason}, handshake aborted`);
            await this.transmit(peer, 'alert', { reason: `bad certificate: ${verification.reason}` });
            throw new Error(`certificate of ${peer} rejected: ${verification.reason}`);
        }
        this.log(`3. CA verification OK: CN=${verification.subject}, issuer ${verification.issuer}, serial ${verification.serial}, valid to ${verification.validTo}`);

        const premaster = crypto.randomBytes(48);
        const keyExchange = { premaster: encryptPremaster(premaster, serverHello.certificate) };
        transcript.push(['key_exchange', keyExchange]);
        await this.transmit(peer, 'key_exchange', keyExchange);
        this.log(`4. premaster secret (48 B) encrypted with ${peer}'s public key (RSA-OAEP) → ${peer}`);

        const keys = deriveSessionKeys(premaster, clientHello.random, serverHello.random);
        this.log(`5. session keys derived with HKDF-SHA256: client_write ${fingerprint(keys.client)}, server_write ${fingerprint(keys.server)}`);

        const session = { peer, role: 'client', send: new RecordCipher(keys.client), receive: new RecordCipher(keys.server), transcriptHash: sha256(JSON.stringify(transcript)) };
        const finishedReceived = this.waitFor(peer, 'finished');
        await this.transmit(peer, 'finished', session.send.seal({ type: 'ready', transcript: session.transcriptHash }));
        this.log(`6. Finished "ready" encrypted with client_write key → ${peer}`);

        const ready = session.receive.open(await finishedReceived);
        if (ready.type !== 'ready' || ready.transcript !== session.transcriptHash) {
            throw new Error(`Finished from ${peer} does not match the handshake transcript`);
        }
        this.log(`6. Finished "ready" ← ${peer}: decrypted with server_write key, transcript hash ${short(ready.transcript)} matches`);

        this.sessions.set(peer, session);
        this.log(`7. handshake with ${peer} complete, secure channel ${CIPHER_SUITE} established`);
        return session;
    }

    async onClientHello(peer, clientHello) {
        const serverHello = { version: VERSION, random: randomHex(32), cipherSuite: CIPHER_SUITE, certificate: this.certificate };
        this.serverHandshakes.set(peer, { clientHello, serverHello, transcript: [['client_hello', clientHello], ['server_hello', serverHello]] });
        this.log(`1. ClientHello ← ${peer}: client random ${short(clientHello.random)}`);
        const sent = await this.transmit(peer, 'server_hello', serverHello);
        this.log(`2. ServerHello → ${peer}: server random ${short(serverHello.random)} + X.509 certificate (${sent.bytes} B, ${packetsText(sent.packets)})`);
    }

    onKeyExchange(peer, keyExchange) {
        const state = this.serverHandshakes.get(peer);
        if (!state) {
            throw new Error('unexpected key_exchange');
        }
        state.transcript.push(['key_exchange', keyExchange]);
        const premaster = decryptPremaster(keyExchange.premaster, this.keys.privateKey);
        this.log(`4. premaster secret ← ${peer}: decrypted with own private key (${premaster.length} B)`);

        const keys = deriveSessionKeys(premaster, state.clientHello.random, state.serverHello.random);
        state.session = { peer, role: 'server', send: new RecordCipher(keys.server), receive: new RecordCipher(keys.client), transcriptHash: sha256(JSON.stringify(state.transcript)) };
        this.log(`5. session keys derived with HKDF-SHA256: client_write ${fingerprint(keys.client)}, server_write ${fingerprint(keys.server)}`);
    }

    async onClientFinished(peer, record) {
        const state = this.serverHandshakes.get(peer);
        if (!state?.session) {
            throw new Error('unexpected finished');
        }
        const { session } = state;
        const ready = session.receive.open(record);
        if (ready.type !== 'ready' || ready.transcript !== session.transcriptHash) {
            throw new Error(`Finished from ${peer} does not match the handshake transcript`);
        }
        this.log(`6. Finished "ready" ← ${peer}: decrypted with client_write key, transcript hash ${short(ready.transcript)} matches`);

        this.serverHandshakes.delete(peer);
        this.sessions.set(peer, session);
        await this.transmit(peer, 'finished', session.send.seal({ type: 'ready', transcript: session.transcriptHash }));
        this.log(`6. Finished "ready" encrypted with server_write key → ${peer}`);
        this.log(`7. handshake with ${peer} complete, secure channel ${CIPHER_SUITE} established`);
    }

    onAlert(peer, { reason }) {
        this.serverHandshakes.delete(peer);
        this.log(`alert from ${peer}: ${reason}, handshake aborted`);
    }

    async sendSecure(peer, payload) {
        const session = await this.handshake(peer);
        const record = session.send.seal(payload);
        const sent = await this.transmit(peer, 'record', record);
        return { record, ...sent };
    }

    async sendChat(peer, text) {
        const { record, bytes, packets } = await this.sendSecure(peer, { type: 'chat', text });
        this.log(`chat → ${peer}: "${text}" as encrypted record #${record.seq} (${bytes} B, ${packetsText(packets)})`);
    }

    async sendFile(peer, filePath) {
        const content = fs.readFileSync(filePath);
        const { record, bytes, packets } = await this.sendSecure(peer, { type: 'file', name: path.basename(filePath), content: content.toString('base64') });
        this.log(`file → ${peer}: ${path.basename(filePath)} (${content.length} B, sha256 ${short(sha256(content))}) as encrypted record #${record.seq} (${bytes} B, ${packetsText(packets)})`);
    }

    async broadcast(text) {
        const payload = { type: 'broadcast', id: randomHex(8), origin: this.id, text };
        this.seenBroadcasts.add(payload.id);
        this.log(`broadcast "${text}" over the shortest-path tree rooted at ${this.id}`);
        await this.forwardBroadcast(payload);
    }

    async forwardBroadcast(payload) {
        const children = this.treeChildren(payload.origin);
        if (children.length) {
            this.log(`broadcast ${payload.id} forwarded to ${children.join(', ')}`);
        }
        const results = await Promise.allSettled(children.map((child) => this.sendSecure(child, payload)));
        results.forEach((result, index) => {
            if (result.status === 'rejected') {
                this.log(`broadcast ${payload.id} not delivered to ${children[index]}: ${result.reason.message}`);
            }
        });
    }

    onRecord(peer, record) {
        const session = this.sessions.get(peer);
        if (!session) {
            throw new Error('record without an established session');
        }
        const payload = session.receive.open(record);

        if (payload.type === 'chat') {
            this.log(`chat ← ${peer}: "${payload.text}" (record #${record.seq} decrypted)`);
        } else if (payload.type === 'file') {
            const content = Buffer.from(payload.content, 'base64');
            const target = path.join(this.receivedDir, this.id, payload.name);
            fs.mkdirSync(path.dirname(target), { recursive: true });
            fs.writeFileSync(target, content);
            this.log(`file ← ${peer}: ${payload.name} (${content.length} B, sha256 ${short(sha256(content))}) saved to ${path.relative(process.cwd(), target)}`);
        } else if (payload.type === 'broadcast' && !this.seenBroadcasts.has(payload.id)) {
            this.seenBroadcasts.add(payload.id);
            this.log(`broadcast ← ${peer}: "${payload.text}" from ${payload.origin}`);
            return this.forwardBroadcast(payload);
        }
    }

    get idle() {
        return this.pendingHandshakes.size === 0 && [...this.links.values()].every((link) => link.idle);
    }

    dropSessionsWith(peer) {
        this.sessions.delete(peer);
    }
}

module.exports = { NetworkNode };
