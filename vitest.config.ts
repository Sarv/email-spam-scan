import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Deliberately `node`, not `jsdom`. A spam verdict is computed at ingest,
    // on a server or in a main process, where there is no DOM — so the default
    // environment has to be the one with no ambient `DOMParser`. Anything that
    // needs one opts in per file with a `// @vitest-environment jsdom`
    // docblock, which keeps a header rule from quietly acquiring a browser
    // dependency that a server-side consumer does not have.
    environment: 'node',
    globals: true,
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**'],
      // A barrel is `export` lines and nothing else; counting it inflates the
      // number without testing anything. `entry-points.test.ts` reads both of
      // these as TEXT and asserts what they re-export, which is the only thing
      // about them that can be wrong.
      exclude: ['src/index.ts', 'src/headers/index.ts', 'src/content/index.ts'],
      // Enforced, not aspirational. A wrong verdict here either files somebody's
      // invoice as spam or lets a phish through with a green shield, and both
      // failures are silent — nobody reports the mail they never saw. An
      // untested branch in a rule is therefore a release blocker, not a
      // cosmetic gap, and CI must be the thing that says so.
      thresholds: {
        lines: 100,
        functions: 100,
        branches: 100,
        statements: 100,
      },
    },
  },
});
