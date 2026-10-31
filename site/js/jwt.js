/*
 * Motor de análisis de JWT para JWT Security Analyzer.
 *  - decode(token): parsea las tres partes (sin verificar firma).
 *  - audit(token): detecta configuraciones inseguras a partir del encabezado y el payload.
 *  - verifyHS(token, secret): verifica la firma HMAC (async; Web Crypto en navegador, crypto en Node).
 *  - checkWeakSecret(token, list): prueba una lista de secretos comunes para demostrar el riesgo.
 * Funciona en el navegador (window.JWT) y en Node (module.exports) para los tests.
 * Es defensivo y educativo: audita y explica. No ataca sistemas remotos.
 */
(function (root) {
  "use strict";

  // --------------------------------------------------- base64url
  function b64urlToBytes(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    const pad = s.length % 4;
    if (pad === 1) throw new Error("base64url inválido");
    if (pad) s += "=".repeat(4 - pad);
    const bin = typeof atob === "function" ? atob(s) : Buffer.from(s, "base64").toString("binary");
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToUtf8(bytes) {
    if (typeof TextDecoder === "function") return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return Buffer.from(bytes).toString("utf-8");
  }
  function b64urlToString(s) { return bytesToUtf8(b64urlToBytes(s)); }

  // --------------------------------------------------- decode
  const REG_CLAIMS = {
    iss: "Issuer (emisor)", sub: "Subject (sujeto)", aud: "Audience (destinatario)",
    exp: "Expiration (vencimiento)", nbf: "Not Before (válido desde)", iat: "Issued At (emitido)",
    jti: "JWT ID (identificador único)",
  };

  function decode(token) {
    if (typeof token !== "string" || !token.trim()) throw new Error("Token vacío");
    const parts = token.trim().replace(/^Bearer\s+/i, "").split(".");
    if (parts.length !== 3) throw new Error(`Un JWT tiene 3 partes separadas por puntos; este tiene ${parts.length}`);
    const [h, p, sig] = parts;
    let header, payload;
    try { header = JSON.parse(b64urlToString(h)); } catch { throw new Error("El encabezado no es JSON válido en base64url"); }
    try { payload = JSON.parse(b64urlToString(p)); } catch { throw new Error("El payload no es JSON válido en base64url"); }
    if (typeof header !== "object" || header === null) throw new Error("El encabezado no es un objeto JSON");
    if (typeof payload !== "object" || payload === null) throw new Error("El payload no es un objeto JSON");
    return {
      header, payload,
      signature: sig,
      raw: { header: h, payload: p, signature: sig },
      signingInput: `${h}.${p}`,
      alg: String(header.alg || ""),
      typ: header.typ,
    };
  }

  // --------------------------------------------------- HMAC (async)
  async function verifyHS(token, secret) {
    const d = typeof token === "string" ? decode(token) : token;
    const bits = /^HS(\d+)$/.exec(d.alg);
    if (!bits) throw new Error("verifyHS solo aplica a algoritmos HMAC (HS256/384/512)");
    const hash = "SHA-" + bits[1];
    const enc = (s) => (typeof TextEncoder === "function" ? new TextEncoder().encode(s) : Uint8Array.from(Buffer.from(s, "utf-8")));
    const expected = d.raw.signature;
    const subtle = root.crypto && root.crypto.subtle;
    if (subtle) {
      const key = await subtle.importKey("raw", enc(secret), { name: "HMAC", hash }, false, ["sign"]);
      const mac = new Uint8Array(await subtle.sign("HMAC", key, enc(d.signingInput)));
      return bytesToB64url(mac) === expected;
    }
    // Node
    const nodeCrypto = require("crypto");
    const mac = nodeCrypto.createHmac(hash.replace("-", "").toLowerCase(), secret).update(d.signingInput).digest();
    return mac.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") === expected;
  }

  function bytesToB64url(bytes) {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    const b64 = typeof btoa === "function" ? btoa(bin) : Buffer.from(bin, "binary").toString("base64");
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /** Prueba una lista de secretos comunes contra un token HMAC. Devuelve el secreto si alguno coincide, o null.
   *  Objetivo didáctico: mostrar por qué un secreto débil permite falsificar tokens. */
  async function checkWeakSecret(token, list, onProgress) {
    const d = decode(token);
    if (!/^HS\d+$/.test(d.alg)) return { applicable: false };
    let i = 0;
    for (const secret of list) {
      if (await verifyHS(d, secret)) return { applicable: true, found: secret, tried: i + 1 };
      if (onProgress && ++i % 50 === 0) await onProgress(i);
    }
    return { applicable: true, found: null, tried: list.length };
  }

  // --------------------------------------------------- auditoría
  const SENSITIVE_KEYS = ["password", "passwd", "pwd", "secret", "apikey", "api_key", "token",
    "ssn", "creditcard", "credit_card", "cardnumber", "cvv", "pin", "privatekey", "private_key"];

  function num(v) { return typeof v === "number" && isFinite(v) ? v : null; }

  /**
   * Audita un token y devuelve hallazgos. `now` permite fijar la hora en los tests.
   * Cada hallazgo: {id, severity, title, detail, remediation}.
   */
  function audit(token, now = Math.floor(Date.now() / 1000)) {
    const d = decode(token);
    const F = [];
    const add = (id, severity, title, detail, remediation) => F.push({ id, severity, title, detail, remediation });
    const alg = d.alg;

    // 1. alg: none
    if (/^none$/i.test(alg)) {
      add("alg-none", "critical", 'Algoritmo "none" (sin firma)',
        'El token declara alg:"none", es decir, no está firmado. Si el servidor lo acepta, cualquiera puede crear un token con el contenido que quiera.',
        'Rechazar "none" explícitamente. Mantener una lista fija de algoritmos permitidos y verificar siempre la firma.');
    } else if (!alg) {
      add("alg-missing", "high", "Encabezado sin algoritmo",
        "El encabezado no declara el campo alg. Un parser permisivo podría tratarlo como un token sin firma.",
        "Exigir un alg explícito dentro de una lista de algoritmos permitidos.");
    }

    // 2. Confusión de algoritmos (HS vs RS/ES/PS)
    if (/^HS\d+$/.test(alg)) {
      add("alg-hmac", "info", "Firma simétrica (HMAC)",
        `El token usa ${alg}: firma simétrica con un secreto compartido. Su seguridad depende por completo de que ese secreto sea largo y aleatorio.`,
        "Usar un secreto de alta entropía (32 bytes o más). Para sistemas distribuidos, preferir claves asimétricas (RS256/ES256).");
    }
    if (/^(RS|ES|PS)\d+$/.test(alg)) {
      add("alg-confusion", "info", "Riesgo de confusión de algoritmos",
        `El token usa ${alg} (asimétrico). Si el servidor no fija el algoritmo esperado, un atacante podría reenviar el token como HS256 usando la clave pública como secreto HMAC.`,
        "Fijar el algoritmo esperado en la verificación. Nunca derivar el algoritmo del encabezado del token.");
    }

    // 3. Claim kid peligroso (inyección)
    if (d.header.kid !== undefined) {
      const kid = String(d.header.kid);
      if (/[^A-Za-z0-9_\-:.]/.test(kid) || /\.\.|\/|\\/.test(kid)) {
        add("kid-injection", "high", 'Valor sospechoso en "kid"',
          `El encabezado incluye kid="${kid}", con caracteres que podrían usarse para inyección (path traversal o SQL) si el servidor lo usa sin sanitizar para buscar la clave.`,
          "Validar kid contra una lista de valores permitidos; nunca usarlo directamente en rutas de archivos ni en consultas SQL.");
      }
    }
    if (d.header.jku !== undefined || d.header.x5u !== undefined) {
      add("remote-key", "high", "Clave cargada desde una URL (jku/x5u)",
        "El encabezado referencia una clave remota. Si el servidor la descarga sin validar el dominio, un atacante podría apuntar a una clave controlada por él.",
        "Deshabilitar jku/x5u o restringirlos a una lista fija de URLs de confianza.");
    }

    // 4. Expiración
    const exp = num(d.payload.exp), iat = num(d.payload.iat), nbf = num(d.payload.nbf);
    if (exp === null) {
      add("no-exp", "high", "Sin fecha de expiración (exp)",
        "El token no tiene el claim exp, por lo que no vence nunca. Si se filtra, un atacante puede usarlo indefinidamente.",
        "Incluir siempre exp con una vida corta (minutos u horas) y usar refresh tokens para renovar la sesión.");
    } else if (exp < now) {
      add("expired", "info", "Token vencido",
        `El token venció el ${new Date(exp * 1000).toISOString()}. Un servidor correcto debería rechazarlo.`,
        "Verificar exp en cada petición y rechazar los tokens vencidos.");
    } else if (iat !== null && exp - iat > 86400) {
      const days = Math.round((exp - iat) / 86400);
      add("long-lived", "medium", "Vida útil muy larga",
        `El token es válido durante unos ${days} día(s). Una vida tan larga amplía la ventana de uso si se filtra.`,
        "Reducir la vida útil a minutos u horas y delegar la renovación en refresh tokens.");
    }
    if (nbf !== null && iat !== null && nbf < iat) {
      add("nbf-before-iat", "info", "nbf anterior a iat",
        "El claim nbf (válido desde) es anterior a iat (emitido), lo cual es inconsistente.",
        "Revisar la generación del token para que las marcas de tiempo sean coherentes.");
    }

    // 5. Datos sensibles en el payload (no está cifrado, solo codificado)
    const found = [];
    (function scan(obj, path) {
      if (!obj || typeof obj !== "object") return;
      for (const k of Object.keys(obj)) {
        const key = k.toLowerCase().replace(/[^a-z]/g, "");
        if (SENSITIVE_KEYS.includes(key)) found.push(path + k);
        if (obj[k] && typeof obj[k] === "object") scan(obj[k], path + k + ".");
      }
    })(d.payload, "");
    if (found.length) {
      add("sensitive-data", "high", "Datos sensibles en el payload",
        `El payload incluye campos que parecen sensibles (${found.join(", ")}). El payload de un JWT solo está codificado en base64, no cifrado: cualquiera que tenga el token puede leerlo.`,
        "No incluir secretos ni datos personales sensibles en el payload. Si es imprescindible, usar JWE (JWT cifrado).");
    }

    // 6. Claims de verificación ausentes
    if (d.payload.iss === undefined) {
      add("no-iss", "low", "Sin emisor (iss)",
        "El token no declara quién lo emitió. Validar iss ayuda a rechazar tokens de otra fuente.",
        "Incluir iss y validarlo contra el emisor esperado.");
    }
    if (d.payload.aud === undefined) {
      add("no-aud", "low", "Sin destinatario (aud)",
        "El token no declara para qué servicio es. Sin aud, un token válido para un servicio podría reutilizarse en otro.",
        "Incluir aud y validarlo contra el identificador del servicio.");
    }

    return { decoded: d, findings: F, score: scoreOf(F) };
  }

  const SEV_WEIGHT = { critical: 40, high: 25, medium: 12, low: 5, info: 0 };
  function scoreOf(findings) {
    const penalty = findings.reduce((a, f) => a + (SEV_WEIGHT[f.severity] || 0), 0);
    const score = Math.max(0, 100 - penalty);
    const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 55 ? "C" : score >= 35 ? "D" : "F";
    return { value: score, grade };
  }

  const api = { decode, audit, verifyHS, checkWeakSecret, scoreOf, b64urlToString, bytesToB64url, REG_CLAIMS, SENSITIVE_KEYS, SEV_WEIGHT };
  root.JWT = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
