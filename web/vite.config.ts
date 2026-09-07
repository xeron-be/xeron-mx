import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
    plugins: [react()],
    // The Go binary embeds this directory, so the build lands straight where
    // go:embed can reach it rather than being copied around by the Makefile.
    build: {
        outDir: "../internal/ui/dist",
        // Deliberately false. Emptying the directory would delete the tracked
        // .gitkeep placeholder, and `go:embed all:dist` then fails to compile on
        // a fresh clone. `make ui` clears the previous assets instead.
        emptyOutDir: false,
    },
    server: {
        // `npm run dev` proxies the API to a daemon running locally, so the UI
        // can be developed with hot reload against the real backend.
        proxy: {
            "/api": "http://localhost:8080",
        },
    },
});
