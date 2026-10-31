/*
 * Lista corta de secretos HMAC frecuentes, para demostrar por qué un secreto débil es peligroso.
 * NO es una herramienta de cracking: es una muestra educativa de valores que nunca deberían usarse
 * como clave de firma (valores por defecto de frameworks, ejemplos de tutoriales, claves triviales).
 */
(function (root) {
  "use strict";
  const WEAK_SECRETS = [
    "secret", "secretkey", "secret_key", "your-256-bit-secret", "your_jwt_secret", "jwt_secret",
    "jwtsecret", "mysecret", "mysecretkey", "supersecret", "supersecretkey", "topsecret",
    "password", "password123", "123456", "12345678", "qwerty", "admin", "administrator",
    "changeme", "change_me", "default", "test", "testing", "testkey", "dev", "development",
    "key", "private", "privatekey", "token", "tokensecret", "auth", "authsecret",
    "s3cr3t", "s3cret", "p@ssw0rd", "letmein", "root", "toor", "example", "demo",
    "hello", "world", "helloworld", "foo", "bar", "foobar", "abc123", "iloveyou",
    "0", "1", "a", "null", "undefined", "none", "nil", "empty",
    "jwt", "json", "web", "shhhh", "shh", "verysecret", "notsecret", "nosecret",
    "my-secret", "my_secret", "app_secret", "appsecret", "api_secret", "apisecret",
    "sign", "signing", "signkey", "signingkey", "hmac", "hmackey", "sha256",
    "security", "secure", "unsafe", "insecure", "vault", "master", "masterkey",
  ];
  root.WEAK_SECRETS = WEAK_SECRETS;
  if (typeof module !== "undefined" && module.exports) module.exports = WEAK_SECRETS;
})(typeof window !== "undefined" ? window : globalThis);
