import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

const contentSecurityPolicy = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join("; ");

function injectContentSecurityPolicy(): Plugin {
  return {
    name: "seethru:csp",
    apply: "build",
    transformIndexHtml: () => [
      {
        tag: "meta",
        attrs: { "http-equiv": "Content-Security-Policy", content: contentSecurityPolicy },
        injectTo: "head-prepend",
      },
    ],
  };
}

export default defineConfig({
  base: "./",
  plugins: [react(), injectContentSecurityPolicy()],
  server: { host: "127.0.0.1", strictPort: true },
  preview: { host: "127.0.0.1", strictPort: true },
  build: {
    sourcemap: false,
    cssCodeSplit: false,
    modulePreload: false,
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 4096,
    rolldownOptions: {
      output: {
        codeSplitting: false,
        entryFileNames: "app.js",
        assetFileNames: (asset) => (asset.names.some((name) => name.endsWith(".css")) ? "app.css" : "assets/[name]-[hash][extname]"),
      },
    },
  },
});
