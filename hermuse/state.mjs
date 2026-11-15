import { mkdir, readFile, open, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { PolicyError } from './config.mjs';
import os from 'node:os';

// Only keyed conversation digests are stored. Never persist request/response text here.
export class PrivacyState {
  #queue = Promise.resolve();
  constructor(file, keyId) { this.file = file; this.keyId = keyId; }
  async #read() {
    try {
      const s = JSON.parse(await readFile(this.file, 'utf8'));
      if (s.version !== 1 || s.key_id !== this.keyId || !s.private || Array.isArray(s.private) || Object.entries(s.private).some(([k,v]) => !/^[a-f0-9]{64}$/.test(k) || v !== true)) throw new Error();
      return s;
    } catch (e) {
      throw new PolicyError('privacy_state_unavailable');
    }
  }
  async isPrivate(key) { await this.#queue; return (await this.#read()).private[key] === true; }
  async markPrivate(key) {
    const task = this.#queue.then(async () => {
      const s = await this.#read();
      if (s.private[key]) return;
      if (Object.keys(s.private).length >= 50000) throw new PolicyError('privacy_state_capacity');
      s.private[key] = true;
      await mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
      const temp = `${this.file}.${randomUUID()}.tmp`;
      try {
        const f = await open(temp, 'wx', 0o600);
        try { await f.writeFile(JSON.stringify(s)); await f.sync(); } finally { await f.close(); }
        await rename(temp, this.file);
        // Persist the rename itself before allowing a private request upstream.
        if (os.platform() !== 'win32') {
          const directory = await open(path.dirname(this.file), 'r');
          try { await directory.sync(); } finally { await directory.close(); }
        }
      } finally { await unlink(temp).catch(e => { if (e.code !== 'ENOENT') throw e; }); }
    });
    this.#queue = task.catch(() => {});
    try { await task; } catch (e) { if (e instanceof PolicyError) throw e; throw new PolicyError('privacy_state_unavailable'); }
  }
}

export async function initializeState(file, keyId) {
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const f = await open(file, 'wx', 0o600);
  try { await f.writeFile(JSON.stringify({ version:1, key_id:keyId, private:{} })); await f.sync(); }
  finally { await f.close(); }
}
