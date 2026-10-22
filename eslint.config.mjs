import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/coverage/**', '**/.next/**'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{js,mjs,cjs,ts,mts,cts}'],
    rules: {
      'no-console': 'warn',
    },
  },
  {
    files: [
      'apps/api-gateway/src/server.ts',
      'services/identity-service/src/server.ts'
    ],
    rules: {
      'no-console': 'off',
    },
  },
);
