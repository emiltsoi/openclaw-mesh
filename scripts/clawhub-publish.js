import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, "..");

const token = process.env.CLAWHUB_API_TOKEN || "";
if (!token) {
  console.error("Set CLAWHUB_API_TOKEN to publish.");
  process.exit(1);
}

const configDir = path.join(os.homedir(), ".config/clawhub");
fs.mkdirSync(configDir, { recursive: true });
fs.writeFileSync(
  path.join(configDir, "config.json"),
  JSON.stringify({ registry: "https://clawhub.ai", token }, null, 2),
);

console.log(`Publishing ${path.basename(root)} to ClawHub...`);
execSync("npx -y clawhub@latest package publish .", { cwd: root, stdio: "inherit" });
