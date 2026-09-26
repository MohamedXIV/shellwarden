import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const SEMVER_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

const VERSION_FILES = {
  canonical: "VERSION",
  packageJson: "package.json",
  cargo: "src-tauri/Cargo.toml",
  tauri: "src-tauri/tauri.conf.json",
  changelog: "CHANGELOG.md",
};

function read(root, relativePath) {
  return readFileSync(resolve(root, relativePath), "utf8");
}

function write(root, relativePath, content) {
  writeFileSync(resolve(root, relativePath), content, "utf8");
}

function assertSemver(version) {
  if (!SEMVER_PATTERN.test(version)) {
    throw new Error(`VERSION must be valid Semantic Versioning; received "${version}"`);
  }
}

function jsonVersion(text, label) {
  const parsed = JSON.parse(text);
  if (typeof parsed.version !== "string" || parsed.version.length === 0) {
    throw new Error(`${label} must declare a top-level version string`);
  }
  return parsed.version;
}

function cargoVersion(text) {
  const match = text.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) {
    throw new Error("src-tauri/Cargo.toml must declare a package version");
  }
  return match[1];
}

function replaceJsonVersion(text, version, label) {
  const current = jsonVersion(text, label);
  const needle = `"version": "${current}"`;
  if (!text.includes(needle)) {
    throw new Error(`${label} version must use the canonical JSON string form`);
  }
  return text.replace(needle, `"version": "${version}"`);
}

function replaceCargoVersion(text, version) {
  if (!/^version\s*=\s*"[^"]+"/m.test(text)) {
    throw new Error("src-tauri/Cargo.toml must declare a package version");
  }
  return text.replace(/^version\s*=\s*"[^"]+"/m, `version = "${version}"`);
}

function unreleasedSection(changelog) {
  const heading = "## [Unreleased]";
  const start = changelog.indexOf(heading);
  if (start === -1) {
    throw new Error("CHANGELOG.md must contain a ## [Unreleased] section");
  }

  const bodyStart = start + heading.length;
  const nextRelease = changelog.indexOf("\n## [", bodyStart);
  const bodyEnd = nextRelease === -1 ? changelog.length : nextRelease;

  return {
    start,
    bodyStart,
    bodyEnd,
    body: changelog.slice(bodyStart, bodyEnd),
  };
}

function assertMeaningfulUnreleased(changelog) {
  const { body } = unreleasedSection(changelog);
  const hasCuratedEntry = body
    .split("\n")
    .some((line) => /^-\s+\S/.test(line.trim()));

  if (!hasCuratedEntry) {
    throw new Error(
      "CHANGELOG.md [Unreleased] must contain at least one curated bullet before release preparation",
    );
  }
}

export function checkReleaseState(root = ".") {
  const canonical = read(root, VERSION_FILES.canonical).trim();
  assertSemver(canonical);

  const packageVersion = jsonVersion(read(root, VERSION_FILES.packageJson), "package.json");
  const cargo = cargoVersion(read(root, VERSION_FILES.cargo));
  const tauri = jsonVersion(read(root, VERSION_FILES.tauri), "src-tauri/tauri.conf.json");

  const drift = [
    ["package.json", packageVersion],
    ["src-tauri/Cargo.toml", cargo],
    ["src-tauri/tauri.conf.json", tauri],
  ].filter(([, version]) => version !== canonical);

  if (drift.length > 0) {
    const details = drift.map(([file, version]) => `${file}=${version}`).join(", ");
    throw new Error(`Version drift from VERSION (${canonical}): ${details}`);
  }

  unreleasedSection(read(root, VERSION_FILES.changelog));
  return canonical;
}

export function prepareRelease(root, version, date) {
  assertSemver(version);

  if (version === "0.0.0-dev") {
    throw new Error("Release version must not be the development sentinel 0.0.0-dev");
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    throw new Error("Release date must use YYYY-MM-DD");
  }

  checkReleaseState(root);

  const changelog = read(root, VERSION_FILES.changelog);
  assertMeaningfulUnreleased(changelog);

  if (changelog.includes(`## [${version}]`)) {
    throw new Error(`CHANGELOG.md already contains release ${version}`);
  }

  const packageJson = read(root, VERSION_FILES.packageJson);
  const cargo = read(root, VERSION_FILES.cargo);
  const tauri = read(root, VERSION_FILES.tauri);
  const section = unreleasedSection(changelog);
  const curatedBody = section.body.trim();

  const promoted =
    "## [Unreleased]\n\n" +
    `## [${version}] - ${date}\n` +
    curatedBody +
    "\n";

  const nextChangelog =
    changelog.slice(0, section.start) + promoted + changelog.slice(section.bodyEnd);

  write(root, VERSION_FILES.canonical, `${version}\n`);
  write(root, VERSION_FILES.packageJson, replaceJsonVersion(packageJson, version, "package.json"));
  write(root, VERSION_FILES.cargo, replaceCargoVersion(cargo, version));
  write(
    root,
    VERSION_FILES.tauri,
    replaceJsonVersion(tauri, version, "src-tauri/tauri.conf.json"),
  );
  write(root, VERSION_FILES.changelog, nextChangelog);

  checkReleaseState(root);
}

function cliArguments(argv) {
  const [command = "check", version, ...rest] = argv;
  const dateIndex = rest.indexOf("--date");
  const date = dateIndex === -1 ? undefined : rest[dateIndex + 1];
  return { command, version, date };
}

function main() {
  const { command, version, date } = cliArguments(process.argv.slice(2));

  if (command === "check") {
    const canonical = checkReleaseState(".");
    console.log(`Version consistency OK: ${canonical}`);
    return;
  }

  if (command === "prepare") {
    if (!version || !date) {
      throw new Error(
        "Usage: npm run release:prepare -- <version> --date YYYY-MM-DD",
      );
    }
    prepareRelease(".", version, date);
    console.log(`Prepared ShellWarden ${version} for ${date}`);
    return;
  }

  throw new Error(`Unknown release command "${command}"`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
