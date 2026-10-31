const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const JWT = require("../site/js/jwt.js");

const b64url = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
function makeHS(header, payload, secret, bits = 256) {
  const h = b64url(JSON.stringify({ alg: `HS${bits}`, typ: "JWT", ...header }));
  const p = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac(`sha${bits}`, secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64url(sig)}`;
}
const unsigned = (header, payload) => `${b64url(JSON.stringify({ alg: "none", ...header }))}.${b64url(JSON.stringify(payload))}.`;
const NOW = 1_700_000_000;

test("decode: separa encabezado, payload y firma", () => {
  const t = makeHS({ kid: "key-1" }, { sub: "123", name: "Ada" }, "s3cr3t");
  const d = JWT.decode(t);
  assert.equal(d.alg, "HS256");
  assert.equal(d.header.kid, "key-1");
  assert.equal(d.payload.name, "Ada");
  assert.ok(d.signature.length > 0);
});

test("decode: acepta prefijo Bearer y rechaza tokens malformados", () => {
  assert.equal(JWT.decode("Bearer " + makeHS({}, { a: 1 }, "x")).payload.a, 1);
  assert.throws(() => JWT.decode("a.b"), /3 partes/);
  assert.throws(() => JWT.decode(""), /vac/);
  assert.throws(() => JWT.decode("!!!.!!!.x"), /base64url|JSON/);
});

test("verifyHS: valida la firma con el secreto correcto y la rechaza con el incorrecto", async () => {
  for (const bits of [256, 384, 512]) {
    const t = makeHS({}, { sub: "1" }, "correct horse", bits);
    assert.equal(await JWT.verifyHS(t, "correct horse"), true, `HS${bits} correcto`);
    assert.equal(await JWT.verifyHS(t, "wrong"), false, `HS${bits} incorrecto`);
  }
});

test("checkWeakSecret: encuentra un secreto débil y no da falsos positivos", async () => {
  const weak = makeHS({}, { sub: "1" }, "secret");
  const strong = makeHS({}, { sub: "1" }, crypto.randomBytes(32).toString("hex"));
  const list = ["123456", "password", "secret", "admin"];
  assert.deepEqual((await JWT.checkWeakSecret(weak, list)).found, "secret");
  assert.equal((await JWT.checkWeakSecret(strong, list)).found, null);
});

test("audit: detecta alg none", () => {
  const r = JWT.audit(unsigned({}, { sub: "admin", exp: NOW + 3600, iss: "x", aud: "y" }), NOW);
  const f = r.findings.find((x) => x.id === "alg-none");
  assert.ok(f && f.severity === "critical");
  assert.ok(r.score.value < 70);
});

test("audit: detecta confusión de algoritmos en tokens asimétricos", () => {
  const t = `${b64url(JSON.stringify({ alg: "RS256" }))}.${b64url(JSON.stringify({ exp: NOW + 3600, iss: "x", aud: "y" }))}.AAAA`;
  assert.ok(JWT.audit(t, NOW).findings.some((f) => f.id === "alg-confusion"));
});

test("audit: detecta kid sospechoso y claves remotas (jku)", () => {
  const kid = JWT.audit(makeHS({ kid: "../../etc/passwd" }, { exp: NOW + 3600, iss: "x", aud: "y" }, "s"), NOW);
  assert.ok(kid.findings.some((f) => f.id === "kid-injection" && f.severity === "high"));
  const jku = JWT.audit(makeHS({ jku: "https://evil.example/keys" }, { exp: NOW + 3600, iss: "x", aud: "y" }, "s"), NOW);
  assert.ok(jku.findings.some((f) => f.id === "remote-key"));
});

test("audit: expiración — ausente, vencido y vida larga", () => {
  const no = JWT.audit(makeHS({}, { sub: "1", iss: "x", aud: "y" }, "s"), NOW);
  assert.ok(no.findings.some((f) => f.id === "no-exp" && f.severity === "high"));
  const exp = JWT.audit(makeHS({}, { exp: NOW - 10, iss: "x", aud: "y" }, "s"), NOW);
  assert.ok(exp.findings.some((f) => f.id === "expired"));
  const long = JWT.audit(makeHS({}, { iat: NOW, exp: NOW + 86400 * 30, iss: "x", aud: "y" }, "s"), NOW);
  assert.ok(long.findings.some((f) => f.id === "long-lived" && f.severity === "medium"));
});

test("audit: detecta datos sensibles anidados en el payload", () => {
  const r = JWT.audit(makeHS({}, { sub: "1", exp: NOW + 3600, iss: "x", aud: "y", data: { password: "hunter2" } }, "s"), NOW);
  const f = r.findings.find((x) => x.id === "sensitive-data");
  assert.ok(f && f.severity === "high");
  assert.match(f.detail, /data\.password/);
});

test("audit: señala iss y aud ausentes", () => {
  const r = JWT.audit(makeHS({}, { sub: "1", exp: NOW + 3600 }, "s"), NOW);
  assert.ok(r.findings.some((f) => f.id === "no-iss"));
  assert.ok(r.findings.some((f) => f.id === "no-aud"));
});

test("un token bien configurado obtiene una calificación alta", () => {
  const good = makeHS({}, { sub: "1", iss: "https://auth.example", aud: "api", iat: NOW, exp: NOW + 900 }, crypto.randomBytes(32).toString("hex"));
  const r = JWT.audit(good, NOW);
  assert.ok(!r.findings.some((f) => ["critical", "high", "medium"].includes(f.severity)), JSON.stringify(r.findings));
  assert.ok(r.score.value >= 90 && r.score.grade === "A");
});

test("scoreOf: penaliza según la severidad", () => {
  assert.equal(JWT.scoreOf([]).value, 100);
  assert.equal(JWT.scoreOf([{ severity: "critical" }]).value, 60);
  assert.equal(JWT.scoreOf([{ severity: "critical" }, { severity: "high" }]).grade, "D");
});
