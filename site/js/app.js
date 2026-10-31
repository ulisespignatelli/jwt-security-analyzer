/* JWT Security Analyzer – interfaz. Todo corre en el navegador: el token nunca sale de tu equipo. */
(function () {
  "use strict";
  const { JWT, WEAK_SECRETS } = window;
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const SEV = ["critical", "high", "medium", "low", "info"];
  const SEV_COLOR = { critical: "#e5484d", high: "#f76b1c", medium: "#f5c518", low: "#4c9aff", info: "#8b95a8" };
  const GRADE_COLOR = { A: "#3fb950", B: "#86b300", C: "#f5c518", D: "#f76b1c", F: "#e5484d" };

  const T = {
    es: {
      intro: "Pegá un <b>JSON Web Token</b> para decodificarlo y auditar su configuración de seguridad. Todo se procesa en tu navegador: <b>el token nunca se envía a ningún servidor</b>.",
      inputTitle: "Token", example: "Ejemplos", exVuln: "Vulnerable", exNone: "alg: none", exGood: "Bien configurado", clear: "Limpiar",
      placeholder: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.…",
      header: "Encabezado (header)", payload: "Contenido (payload)", signature: "Firma (signature)",
      sigNote: "La firma no se puede \"abrir\": sirve para verificar que el token no fue alterado. Verificala abajo si tenés el secreto.",
      score: "Puntaje de seguridad", findings: "Hallazgos", noFindings: "Sin problemas detectados en la estructura del token. 👍",
      issues: (n) => `${n} ${n === 1 ? "configuración observada" : "configuraciones observadas"}`,
      emptyOut: "El análisis aparece acá cuando pegás un token.",
      weakTitle: "Verificar secreto (sólo HS256/384/512)", weakIntro: "Probá si la firma usa un secreto débil de una lista de valores comunes. Muestra por qué un secreto trivial permite falsificar tokens.",
      weakRun: "Probar lista de secretos", weakCustom: "…o probá un secreto propio", weakCheck: "Verificar",
      weakFound: (s) => `Secreto encontrado: <code>${esc(s)}</code>. Con este secreto, cualquiera puede firmar tokens falsos. Es crítico.`,
      weakNotFound: (n) => `Ninguno de los ${n} secretos comunes coincidió. Eso no prueba que el secreto sea fuerte, solo que no es trivial.`,
      weakNA: "Esta prueba solo aplica a tokens firmados con HMAC (HS256/384/512).",
      weakMatch: "El token es válido con ese secreto. En producción, eso sería crítico.",
      weakNoMatch: "El token NO es válido con ese secreto.",
      customPh: "mi-secreto",
      export: "Exportar hallazgos", copyFb: "Copiar para Findings Builder", copyMd: "Copiar Markdown", copied: "¡Copiado!",
      aboutTitle: "Sobre los JWT y su seguridad",
      claims: JWT.REG_CLAIMS,
      sevName: { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja", info: "Info" },
      scoreSub: (g) => ({ A: "Configuración sólida", B: "Buena, con detalles menores", C: "Mejorable", D: "Varios problemas", F: "Problemas graves" }[g]),
    },
    en: {
      intro: "Paste a <b>JSON Web Token</b> to decode it and audit its security configuration. Everything runs in your browser: <b>the token is never sent to any server</b>.",
      inputTitle: "Token", example: "Examples", exVuln: "Vulnerable", exNone: "alg: none", exGood: "Well configured", clear: "Clear",
      placeholder: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.…",
      header: "Header", payload: "Payload", signature: "Signature",
      sigNote: "The signature cannot be \"opened\": it verifies the token was not tampered with. Check it below if you have the secret.",
      score: "Security score", findings: "Findings", noFindings: "No structural issues detected in the token. 👍",
      issues: (n) => `${n} ${n === 1 ? "observation" : "observations"}`,
      emptyOut: "The analysis shows up here once you paste a token.",
      weakTitle: "Check secret (HS256/384/512 only)", weakIntro: "Test whether the signature uses a weak secret from a list of common values. Shows why a trivial secret lets anyone forge tokens.",
      weakRun: "Try common secrets", weakCustom: "…or try your own secret", weakCheck: "Check",
      weakFound: (s) => `Secret found: <code>${esc(s)}</code>. With this secret, anyone can sign forged tokens. This is critical.`,
      weakNotFound: (n) => `None of the ${n} common secrets matched. That does not prove the secret is strong, only that it is not trivial.`,
      weakNA: "This check only applies to HMAC-signed tokens (HS256/384/512).",
      weakMatch: "The token is valid with that secret. In production that would be critical.",
      weakNoMatch: "The token is NOT valid with that secret.",
      customPh: "my-secret",
      export: "Export findings", copyFb: "Copy for Findings Builder", copyMd: "Copy Markdown", copied: "Copied!",
      aboutTitle: "About JWTs and their security",
      claims: { iss: "Issuer", sub: "Subject", aud: "Audience", exp: "Expiration", nbf: "Not Before", iat: "Issued At", jti: "JWT ID" },
      sevName: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
      scoreSub: (g) => ({ A: "Solid configuration", B: "Good, minor details", C: "Could be improved", D: "Several issues", F: "Serious issues" }[g]),
    },
  };

  let lang = (navigator.language || "es").toLowerCase().startsWith("es") ? "es" : "en";
  let current = null; // último resultado de audit

  // tokens de ejemplo (secreto "secret"; generados para esta demo)
  const EXAMPLES = {
    vuln: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsInBhc3N3b3JkIjoiaHVudGVyMiIsImlhdCI6MTUxNjIzOTAyMn0.kHKwktb82hWBji00uYtiRghl9Hyr_2sNkNTLddXwmQI",
    none: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
    good: "", // se genera al vuelo
  };

  const t = () => T[lang];
  function toast(msg) { const el = document.createElement("div"); el.textContent = msg; el.style.cssText = "position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:#182030;border:1px solid #30405f;border-radius:10px;padding:9px 15px;z-index:60"; document.body.appendChild(el); setTimeout(() => el.remove(), 1600); }

  // ---- sintaxis JSON con colores y descripciones de claims
  function jsonHTML(obj, claims) {
    const json = JSON.stringify(obj, null, 2);
    let html = esc(json).replace(/&quot;([^&]+?)&quot;(\s*:)/g, '<span class="k">&quot;$1&quot;</span>$2')
      .replace(/:\s*&quot;(.*?)&quot;/g, ': <span class="str">&quot;$1&quot;</span>')
      .replace(/:\s*(-?\d+\.?\d*)/g, ': <span class="num">$1</span>')
      .replace(/:\s*(true|false|null)/g, ': <span class="bool">$1</span>');
    // anotar claims registrados con su significado y fechas legibles
    for (const [k, desc] of Object.entries(claims)) {
      if (obj[k] === undefined) continue;
      let extra = desc;
      if (["exp", "iat", "nbf"].includes(k) && typeof obj[k] === "number") {
        const dt = new Date(obj[k] * 1000);
        extra += " → " + (isNaN(dt) ? "?" : dt.toISOString().replace("T", " ").slice(0, 19) + " UTC");
      }
      html = html.replace(new RegExp(`(<span class="k">&quot;${k}&quot;</span>)`), `$1<span class="claim-tip"> // ${esc(extra)}</span>`);
    }
    return html;
  }

  function render() {
    const T_ = t();
    $("#intro").innerHTML = T_.intro;
    $("#inputTitle").textContent = T_.inputTitle;
    $("#input").placeholder = T_.placeholder;
    $("#aboutLink").href = "#about";
    $("#exBtns").innerHTML = `<button class="btn sm" data-ex="vuln">${T_.exVuln}</button><button class="btn sm" data-ex="none">${T_.exNone}</button><button class="btn sm" data-ex="good">${T_.exGood}</button><button class="btn sm ghost" data-ex="clear">${T_.clear}</button>`;
    renderAbout();
    renderFoot();
    analyze();
  }

  function analyze() {
    const T_ = t();
    const raw = $("#input").value.trim();
    const errEl = $("#inputErr");
    if (!raw) {
      errEl.hidden = true; current = null;
      $("#output").innerHTML = `<div class="empty">${T_.emptyOut}</div>`;
      $("#scoreCard").innerHTML = ""; $("#secretCard").innerHTML = "";
      return;
    }
    let res;
    try { res = JWT.audit(raw); } catch (e) {
      errEl.hidden = false; errEl.textContent = "⚠ " + e.message; current = null;
      $("#output").innerHTML = ""; $("#scoreCard").innerHTML = ""; $("#secretCard").innerHTML = "";
      return;
    }
    errEl.hidden = true; current = res;
    renderScore(res);
    renderOutput(res);
    renderSecret(res);
  }

  function renderScore(res) {
    const T_ = t(), g = res.score.grade;
    const counts = Object.fromEntries(SEV.map((s) => [s, res.findings.filter((f) => f.severity === s).length]));
    $("#scoreCard").innerHTML = `<div class="card"><div class="card-h"><h2>${T_.score}</h2></div>
      <div class="score"><div class="grade" style="background:${GRADE_COLOR[g]}">${g}</div>
      <div class="meta"><div class="n">${res.score.value}/100 · ${esc(T_.scoreSub(g))}</div>
        <div class="sub">${T_.issues(res.findings.filter((f) => f.severity !== "info").length)}</div>
        <div class="sevline">${SEV.filter((s) => counts[s]).map((s) => `<span class="pill" style="background:${SEV_COLOR[s]}${s === "medium" ? ";color:#1d1600" : ""}">${counts[s]} ${esc(T_.sevName[s])}</span>`).join("")}</div>
      </div></div></div>`;
  }

  function renderOutput(res) {
    const T_ = t(), d = res.decoded;
    const tok = esc(d.raw.header) + '<span class="dot">.</span>' + esc(d.raw.payload) + '<span class="dot">.</span>' + (d.raw.signature || "");
    const colored = `<div class="jwt-colored"><span class="h">${esc(d.raw.header)}</span><span class="dot">.</span><span class="p">${esc(d.raw.payload)}</span><span class="dot">.</span><span class="s">${esc(d.raw.signature)}</span></div>`;
    const findings = res.findings.length
      ? `<div class="findings">${res.findings.map((f, i) => `
        <div class="finding ${f.severity === "critical" || f.severity === "high" ? "open" : ""}" data-i="${i}">
          <div class="fh b-${f.severity}"><span class="caret">▸</span><span class="badge sev-${f.severity}">${esc(T_.sevName[f.severity])}</span><span class="ft">${esc(f.title)}</span></div>
          <div class="fb"><p>${esc(f.detail)}</p><div class="rem"><b>→</b> ${esc(f.remediation)}</div></div>
        </div>`).join("")}</div>`
      : `<div class="empty">${T_.noFindings}</div>`;
    $("#output").innerHTML = `
      ${colored}
      <div class="seg-h"><span class="dotc" style="background:#ff6b81"></span>${T_.header}</div>
      <pre class="json">${jsonHTML(d.header, T_.claims)}</pre>
      <div class="seg-h"><span class="dotc" style="background:#c08cff"></span>${T_.payload}</div>
      <pre class="json">${jsonHTML(d.payload, T_.claims)}</pre>
      <div class="seg-h"><span class="dotc" style="background:#4cc9f0"></span>${T_.signature}</div>
      <p class="claim-tip" style="margin:2px 0 0;font-size:12.5px">${T_.sigNote}</p>
      <div class="seg-h">${T_.findings}</div>
      ${findings}
      ${res.findings.length ? `<div class="export-bar"><button class="btn sm" id="copyFb">${T_.copyFb}</button><button class="btn sm" id="copyMd">${T_.copyMd}</button></div>` : ""}`;
    $("#output").querySelectorAll(".finding").forEach((el) => { el.querySelector(".fh").onclick = () => el.classList.toggle("open"); });
    const fb = $("#copyFb"), md = $("#copyMd");
    if (fb) fb.onclick = () => copy(exportForFindingsBuilder(res), T_.copied);
    if (md) md.onclick = () => copy(exportMarkdown(res), T_.copied);
    void tok;
  }

  // ---- verificación de secreto
  function renderSecret(res) {
    const T_ = t();
    if (!/^HS\d+$/.test(res.decoded.alg)) { $("#secretCard").innerHTML = ""; return; }
    $("#secretCard").innerHTML = `<div class="card"><div class="card-h"><h2>${T_.weakTitle}</h2></div>
      <p class="claim-tip" style="margin:0 0 10px;font-size:12.5px">${T_.weakIntro}</p>
      <div class="secret-run"><button class="btn pri sm" id="runWeak">${T_.weakRun}</button><span id="weakStatus" class="claim-tip"></span></div>
      <div id="weakRes"></div>
      <div class="secret-run" style="margin-top:12px"><input class="token-in" id="customSecret" style="min-height:auto;flex:1;padding:7px 10px" placeholder="${esc(T_.customPh)}"><button class="btn sm" id="checkCustom">${T_.weakCheck}</button></div>
      <div id="customRes"></div>`;
    $("#runWeak").onclick = runWeak;
    $("#checkCustom").onclick = checkCustom;
    $("#customSecret").onkeydown = (e) => { if (e.key === "Enter") checkCustom(); };
  }

  async function runWeak() {
    const T_ = t(), btn = $("#runWeak"), status = $("#weakStatus"), out = $("#weakRes");
    btn.disabled = true; out.innerHTML = "";
    const res = await JWT.checkWeakSecret($("#input").value.trim(), WEAK_SECRETS, async (n) => { status.textContent = `${n}/${WEAK_SECRETS.length}`; });
    status.textContent = "";
    btn.disabled = false;
    if (!res.applicable) { out.innerHTML = `<div class="secret-res na">${T_.weakNA}</div>`; return; }
    out.innerHTML = res.found
      ? `<div class="secret-res bad">🔓 ${T_.weakFound(res.found)}</div>`
      : `<div class="secret-res good">🔒 ${T_.weakNotFound(WEAK_SECRETS.length)}</div>`;
  }
  async function checkCustom() {
    const T_ = t(), s = $("#customSecret").value, out = $("#customRes");
    if (!s) return;
    const ok = await JWT.verifyHS($("#input").value.trim(), s).catch(() => false);
    out.innerHTML = ok ? `<div class="secret-res bad">🔓 ${T_.weakMatch}</div>` : `<div class="secret-res na">${T_.weakNoMatch}</div>`;
  }

  // ---- exportación
  function exportMarkdown(res) {
    const T_ = t(), L = [`## JWT – ${T_.findings}`, "", `**${T_.score}:** ${res.score.value}/100 (${res.score.grade})`, ""];
    for (const f of res.findings) {
      L.push(`### [${T_.sevName[f.severity].toUpperCase()}] ${f.title}`, "", f.detail, "", `**→ ${lang === "es" ? "Recomendación" : "Remediation"}:** ${f.remediation}`, "");
    }
    return L.join("\n");
  }
  function exportForFindingsBuilder(res) {
    // Formato compatible para pegar como evidencia/hallazgo en Pentest Findings Builder
    const real = res.findings.filter((f) => f.severity !== "info");
    const top = real[0];
    return JSON.stringify({
      source: "jwt-security-analyzer",
      title: lang === "es" ? "Configuración insegura de JWT" : "Insecure JWT configuration",
      severity: top ? top.severity : "info",
      score: res.score,
      findings: res.findings.map((f) => ({ id: f.id, severity: f.severity, title: f.title, detail: f.detail, remediation: f.remediation })),
    }, null, 2);
  }
  function copy(text, okMsg) {
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(() => toast(okMsg)).catch(() => {
      const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); toast(okMsg); } catch { } ta.remove();
    });
  }

  // ---- ejemplos
  function goodToken() {
    // HS256 firmado con un secreto fuerte; sólo para mostrar un token "A".
    // header {"alg":"HS256","typ":"JWT"} payload bien formado
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tIiwiYXVkIjoiYXBpLmV4YW1wbGUuY29tIiwiaWF0IjoxOTAwMDAwMDAwLCJleHAiOjE5MDAwMDA5MDB9.y-OmTnbAekDMbjSoHUqQ7IWkkKim4jqZ3s1Eh5WJ7RQ";
  }

  function setExample(kind) {
    if (kind === "clear") { $("#input").value = ""; analyze(); $("#input").focus(); return; }
    $("#input").value = kind === "good" ? goodToken() : EXAMPLES[kind];
    analyze();
  }

  function renderAbout() {
    const T_ = t();
    $("#about").innerHTML = lang === "es" ? `
      <h2 style="font-size:17px" id="aboutH">${T_.aboutTitle}</h2>
      <p>Un <b>JSON Web Token (JWT)</b> tiene tres partes separadas por puntos: <code>encabezado.payload.firma</code>. Las dos primeras son JSON codificado en <b>base64url</b> (no cifrado): cualquiera con el token puede leerlas. La firma es lo único que garantiza que el token no fue modificado.</p>
      <h3>Debilidades más comunes</h3>
      <ul>
        <li><b>alg: none</b> — el token dice que no está firmado. Si el servidor lo acepta, se puede falsificar cualquier contenido.</li>
        <li><b>Confusión de algoritmos</b> — un token RS256 (asimétrico) reenviado como HS256 usando la clave pública como secreto, si el servidor no fija el algoritmo.</li>
        <li><b>Secreto débil</b> — en HMAC, si el secreto es trivial o un valor por defecto, se puede obtener y firmar tokens falsos.</li>
        <li><b>Sin expiración</b> — un token sin <code>exp</code> sirve para siempre si se filtra.</li>
        <li><b>Datos sensibles en el payload</b> — recordá: el payload no está cifrado.</li>
        <li><b>Inyección en <code>kid</code> / claves remotas (<code>jku</code>)</b> — campos del encabezado usados sin validar.</li>
      </ul>
      <div class="warn-box">⚖️ Esta herramienta es para auditar tus propios tokens, aprender y evaluar sistemas que tengas <b>autorización</b> para probar. La verificación de secretos se limita a una lista corta de valores comunes, con fin educativo.</div>
      <p>Más información: <a href="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html" target="_blank" rel="noopener">OWASP JWT Cheat Sheet</a> · <a href="https://portswigger.net/web-security/jwt" target="_blank" rel="noopener">PortSwigger: JWT attacks</a>.</p>`
      : `
      <h2 style="font-size:17px" id="aboutH">${T_.aboutTitle}</h2>
      <p>A <b>JSON Web Token (JWT)</b> has three dot-separated parts: <code>header.payload.signature</code>. The first two are base64url-encoded JSON (<b>not encrypted</b>): anyone with the token can read them. Only the signature guarantees the token was not modified.</p>
      <h3>Most common weaknesses</h3>
      <ul>
        <li><b>alg: none</b> — the token claims it is unsigned. If the server accepts it, any content can be forged.</li>
        <li><b>Algorithm confusion</b> — an RS256 (asymmetric) token replayed as HS256 using the public key as the secret, when the server does not pin the algorithm.</li>
        <li><b>Weak secret</b> — with HMAC, a trivial or default secret can be recovered and used to forge tokens.</li>
        <li><b>No expiration</b> — a token with no <code>exp</code> lasts forever if leaked.</li>
        <li><b>Sensitive data in the payload</b> — remember: the payload is not encrypted.</li>
        <li><b><code>kid</code> injection / remote keys (<code>jku</code>)</b> — header fields used without validation.</li>
      </ul>
      <div class="warn-box">⚖️ This tool is for auditing your own tokens, learning, and assessing systems you are <b>authorized</b> to test. The secret check is limited to a short list of common values, for educational purposes.</div>
      <p>More: <a href="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html" target="_blank" rel="noopener">OWASP JWT Cheat Sheet</a> · <a href="https://portswigger.net/web-security/jwt" target="_blank" rel="noopener">PortSwigger: JWT attacks</a>.</p>`;
  }
  function renderFoot() {
    $("#foot").innerHTML = lang === "es"
      ? '🔒 Todo se procesa en tu navegador. Ningún token se envía a ningún servidor. · <a href="https://github.com/ulisespignatelli/jwt-security-analyzer" target="_blank" rel="noopener">Código</a>'
      : '🔒 Everything runs in your browser. No token is sent to any server. · <a href="https://github.com/ulisespignatelli/jwt-security-analyzer" target="_blank" rel="noopener">Source</a>';
  }

  // ---- eventos
  $("#input").addEventListener("input", analyze);
  $("#exBtns") && document.addEventListener("click", (e) => { const b = e.target.closest("[data-ex]"); if (b) setExample(b.dataset.ex); });
  $("#lang").addEventListener("change", (e) => { lang = e.target.value; render(); });
  $("#lang").value = lang;
  render();
})();
