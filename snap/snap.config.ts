import type { SnapConfig } from '@metamask/snaps-cli';

const config: SnapConfig = {
  input: 'src/index.ts',
  server: {
    port: 8000,
  },
  polyfills: {
    buffer: true,
  },
};

export default config;
