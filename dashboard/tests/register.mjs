// Load the real TS/TSX modules with the dashboard's installed compiler; no bundles
// or generated fixtures are written. Ordinary dashboard tests stay offline.
import { registerHooks, syncBuiltinESMExports } from 'node:module';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { transformSync } from 'rolldown/utils';

const deny = () => { throw new Error('External network disabled during dashboard tests'); };
http.request = https.request = net.connect = net.createConnection = deny;
globalThis.fetch = deny;
syncBuiltinESMExports();

registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('.') && context.parentURL) {
      const url = new URL(specifier, context.parentURL);
      for (const extension of ['.ts', '.tsx']) {
        if (existsSync(fileURLToPath(url) + extension)) {
          return { url: url.href + extension, shortCircuit: true };
        }
      }
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (/\.tsx?$/.test(url)) {
      const result = transformSync(fileURLToPath(url), readFileSync(new URL(url), 'utf8'), {
        jsx: { runtime: 'classic' },
      });
      if (result.errors.length) throw new Error(JSON.stringify(result.errors));
      return { format: 'module', source: result.code, shortCircuit: true };
    }
    return next(url, context);
  },
});
