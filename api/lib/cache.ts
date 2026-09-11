import fs from 'fs';
import path from 'path';
import { ScanReport } from './types';

const memoryCache = new Map<string, ScanReport>();
const TMP_FILE = path.join('/tmp', 'spider_scans.json');

function loadTmpCache(): void {
  try {
    if (fs.existsSync(TMP_FILE)) {
      const raw = fs.readFileSync(TMP_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data)) {
        for (const item of data) {
          if (item && item.id) memoryCache.set(item.id, item);
        }
      }
    }
  } catch {
    // Ignore fallback errors
  }
}

function saveTmpCache(): void {
  try {
    const list = Array.from(memoryCache.values()).slice(-100);
    fs.writeFileSync(TMP_FILE, JSON.stringify(list), 'utf8');
  } catch {
    // Ignore write errors in restricted env
  }
}

// Initial load
loadTmpCache();

export const scanCache = {
  get(id: string): ScanReport | undefined {
    if (!memoryCache.has(id)) loadTmpCache();
    return memoryCache.get(id);
  },
  set(id: string, report: ScanReport): void {
    if (memoryCache.size > 100) {
      const oldestKey = memoryCache.keys().next().value;
      if (oldestKey) memoryCache.delete(oldestKey);
    }
    memoryCache.set(id, report);
    saveTmpCache();
  },
  getAll(): ScanReport[] {
    loadTmpCache();
    return Array.from(memoryCache.values()).reverse();
  },
  size(): number {
    return memoryCache.size;
  },
};
