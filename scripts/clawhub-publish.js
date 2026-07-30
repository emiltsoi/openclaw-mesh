import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, "..");

const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf-8"));
const tarball = `${pkg.name.replace("@", "").replace("/", "-")}-${pkg.version}.tgz`;

console.log(`Packing ${pkg.name}@${pkg.version}...`);
execSync("npm pack", { cwd: root, stdio: "inherit" });

const clawhubUrl = process.env.CLAWHUB_URL || "";
const clawhubToken = process.env.CLAWHUB_API_TOKEN || "";

if (!clawhubUrl || !clawhubToken) {
  console.error("Set CLAWHUB_URL and CLAWHUB_API_TOKEN to publish.");
  process.exit(1);
}

const filePath = path.join(root, tarball);
if (!fs.existsSync(filePath)) {
  console.error(`Tarball not found: ${tarball}`);
  process.exit(1);
}

console.log(`Uploading ${tarball} to ${clawhubUrl}...`);
const uploadUrl = `${clawhubUrl.replace(/\/$/, "")}/api/plugins/upload`;
const result = execSync(
  `curl -sfS -H "Authorization: Bearer ${clawhubToken}" -F "package=@${tarball}" "${uploadUrl}"`,
  { cwd: root, encoding: "utf-8" },
);
console.log(result);
