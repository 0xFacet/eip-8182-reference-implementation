// Loads the protocol's domain tags from build/domain_tags.json (regenerated
// by scripts/circom/gen_domain_tags.js). All values are BigInt.
const fs = require("fs");
const path = require("path");

const FILE = path.join(__dirname, "..", "..", "build", "domain_tags.json");
const raw = JSON.parse(fs.readFileSync(FILE, "utf8"));
const tags = {};
for (const [k, v] of Object.entries(raw)) tags[k] = BigInt(v);

module.exports = tags;
