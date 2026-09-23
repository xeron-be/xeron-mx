import { defineConfig } from "vitest/config";

// Tests live in test/ rather than src/ so that `tsc -b` in the production build
// never sees them, and they can read the Go sources to check the UI against
// the API without pulling Node's types into the app.
export default defineConfig({
    test: {
        include: ["test/**/*.test.ts"],
        setupFiles: ["test/setup.ts"],
        environment: "node",
    },
});
