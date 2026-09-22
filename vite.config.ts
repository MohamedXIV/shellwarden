import { readFileSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const version = readFileSync(fileURLToPath(new URL("./VERSION", import.meta.url)), "utf8").trim();

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  define: { __SHELLWARDEN_VERSION__: JSON.stringify(version) },
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
    watch: {
      // Cargo continuously creates/replaces locked .exe/.pdb artifacts here on Windows.
      // Vite does not need to watch Rust build output and doing so can raise EBUSY.
      ignored: ["**/src-tauri/target/**"],
    },
  },
});
