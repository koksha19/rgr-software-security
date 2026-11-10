const EventEmitter = require('events');
const crypto = require('crypto');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

class Link extends EventEmitter {
    constructor(socket, { mtu, bitrate }) {
        super();
        this.socket = socket;
        this.mtu = mtu;
        this.bitrate = bitrate;
        this.queue = Promise.resolve();
        this.partial = new Map();
        this.buffer = '';
        this.stats = { packetsSent: 0, bytesSent: 0 };
        this.inFlight = 0;

        socket.setEncoding('utf8');
        socket.on('data', (chunk) => this.receive(chunk));
        socket.on('close', () => this.emit('close'));
        socket.on('error', () => {});
    }

    send(message) {
        const bytes = Buffer.from(JSON.stringify(message), 'utf8');
        const id = crypto.randomBytes(4).toString('hex');
        const total = Math.ceil(bytes.length / this.mtu) || 1;

        this.inFlight++;
        const sending = this.queue.then(async () => {
            for (let index = 0; index < total; index++) {
                const chunk = bytes.subarray(index * this.mtu, (index + 1) * this.mtu);
                if (this.bitrate) {
                    await sleep(Math.ceil((chunk.length * 8 * 1000) / this.bitrate));
                }
                this.socket.write(JSON.stringify({ id, index, total, data: chunk.toString('base64') }) + '\n');
                this.stats.packetsSent++;
                this.stats.bytesSent += chunk.length;
            }
            return { bytes: bytes.length, packets: total };
        });
        this.queue = sending.catch(() => {}).finally(() => { this.inFlight--; });
        return sending;
    }

    get idle() {
        return this.inFlight === 0 && this.partial.size === 0 && this.buffer === '';
    }

    receive(chunk) {
        this.buffer += chunk;
        let newline;
        while ((newline = this.buffer.indexOf('\n')) >= 0) {
            const line = this.buffer.slice(0, newline);
            this.buffer = this.buffer.slice(newline + 1);
            if (line) {
                this.receivePacket(JSON.parse(line));
            }
        }
    }

    receivePacket({ id, index, total, data }) {
        if (Buffer.from(data, 'base64').length > this.mtu) {
            return this.emit('oversize', id);
        }
        const parts = this.partial.get(id) || [];
        parts[index] = Buffer.from(data, 'base64');
        this.partial.set(id, parts);

        if (parts.filter(Boolean).length === total) {
            this.partial.delete(id);
            this.emit('message', JSON.parse(Buffer.concat(parts).toString('utf8')), { packets: total });
        }
    }
}

module.exports = { Link };
