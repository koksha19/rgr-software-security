const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { NetworkNode } = require('./node');

const COLORS = [31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96];
const startedAt = Date.now();
const elapsed = () => `+${((Date.now() - startedAt) / 1000).toFixed(2)}s`.padStart(9);

function createLogger(id, index) {
    const color = COLORS[index % COLORS.length];
    return (text) => console.log(`${elapsed()} \x1b[${color}m[${id}]\x1b[0m ${text}`);
}

function printTopology(topology, nodes) {
    console.log(`\nnodes: ${Object.keys(topology.nodes).join(', ')}${topology.rogue?.length ? ` (rogue: ${topology.rogue.join(', ')})` : ''}`);
    console.log(`links: ${topology.links.map(([a, b]) => `${a}—${b}`).join(', ')}`);
    console.log(`radio link: MTU ${topology.mtu} B per packet, ${topology.bitrate ? `${topology.bitrate} bit/s` : 'no speed limit'}`);
    const first = nodes.values().next().value;
    console.log(`routes from ${first.id}: ${[...nodes.keys()].filter((id) => id !== first.id).map((id) => first.pathTo(id).join('→')).join(', ')}\n`);
}

const HELP = `commands:
  handshake <from> <to>        TLS-like handshake between any pair of nodes
  send <from> <to> <text>      chat message over the secure channel
  file <from> <to> <path>      send a text file over the secure channel
  broadcast <from> <text>      broadcast to every node over the routing tree
  route <from> <to>            show the route between two nodes
  revoke <node>                revoke the node's certificate at the CA
  topology | stats | help | exit`;

async function main() {
    const [topologyPath, flag, scriptPath] = process.argv.slice(2);
    const topology = JSON.parse(fs.readFileSync(topologyPath, 'utf8'));
    const caUrl = process.env.CA_URL || topology.caUrl || 'http://localhost:4000';
    const receivedDir = path.resolve('received');

    const nodes = new Map(Object.entries(topology.nodes).map(([id, port], index) => [id, new NetworkNode({
        id, port, topology, caUrl, receivedDir, rogue: topology.rogue?.includes(id), log: createLogger(id, index),
    })]));

    try {
        await Promise.all([...nodes.values()].map((node) => node.start()));
    } catch (e) {
        console.error(`cannot start the network: ${e.message}. Is the CA running (npm run ca)?`);
        process.exit(1);
    }
    for (const [a, b] of topology.links) {
        const [client, server] = [a, b].sort();
        await nodes.get(client).connect(server, topology.nodes[server]);
    }
    printTopology(topology, nodes);

    const node = (id) => {
        if (!nodes.has(id)) {
            throw new Error(`unknown node ${id}`);
        }
        return nodes.get(id);
    };

    const commands = {
        handshake: (from, to) => node(from).handshake(to),
        send: (from, to, ...text) => node(from).sendChat(to, text.join(' ')),
        file: (from, to, file) => node(from).sendFile(to, file),
        broadcast: (from, ...text) => node(from).broadcast(text.join(' ')),
        route: (from, to) => console.log(node(from).pathTo(to).join(' → ')),
        revoke: async (id) => {
            const response = await fetch(`${caUrl}/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: id }) });
            console.log(`CA revoked ${(await response.json()).revoked} certificate(s) of ${id}, sessions with ${id} closed`);
            nodes.forEach((other) => other.dropSessionsWith(id));
        },
        wait: (ms) => new Promise((resolve) => setTimeout(resolve, Number(ms))),
        topology: () => printTopology(topology, nodes),
        stats: () => nodes.forEach((n) => console.log(`${n.id}: sessions [${[...n.sessions.keys()].join(', ')}], ${[...n.links].map(([peer, link]) => `${n.id}→${peer} ${link.stats.packetsSent} packets/${link.stats.bytesSent} B`).join(', ')}`)),
        help: () => console.log(HELP),
        exit: () => process.exit(0),
    };

    const settle = async () => {
        let quietPolls = 0;
        while (quietPolls < 4) {
            await new Promise((resolve) => setTimeout(resolve, 50));
            quietPolls = [...nodes.values()].every((n) => n.idle) ? quietPolls + 1 : 0;
        }
    };

    const execute = async (line) => {
        const [name, ...args] = line.trim().split(/\s+/);
        if (!name || name.startsWith('#')) {
            return;
        }
        if (!commands[name]) {
            return console.log(`unknown command "${name}", type help`);
        }
        console.log(`\n> ${line.trim()}`);
        try {
            await commands[name](...args);
        } catch (e) {
            console.log(`error: ${e.message}`);
        }
        await settle();
    };

    if (flag === '--script') {
        for (const line of fs.readFileSync(scriptPath, 'utf8').split('\n')) {
            await execute(line);
        }
        process.exit(0);
    }

    console.log(HELP);
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: '> ' });
    rl.prompt();
    let busy = Promise.resolve();
    rl.on('line', (line) => {
        busy = busy.then(() => execute(line)).then(() => rl.prompt());
    });
}

main();
