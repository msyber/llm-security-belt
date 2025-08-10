import fs from "fs/promises";

const GATEWAY_URL = process.env.GATEWAY_URL || "http://localhost:8787";
const { tests } = JSON.parse(await fs.readFile("evals/tests.json", "utf8"));

async function runOne(t) {
  const body = {
    prompt: t.request?.prompt || "",
    tools: t.request?.tools || [],
    expect_json: !!t.request?.expect_json
  };
  const r = await fetch(`${GATEWAY_URL}/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const okHttp = r.status === 200;
  const expect = t.expect?.status;
  return expect === "blocked" ? !okHttp : okHttp;
}

let failed = [];
for (const t of tests) {
  const ok = await runOne(t);
  console.log(`[${ok ? "PASS" : "FAIL"}] ${t.name}`);
  if (!ok) failed.push(t.name);
}
if (failed.length) {
  console.error("\nFailed:", failed.join(", "));
  process.exit(1);
} else {
  console.log("\nAll tests passed.");
}
