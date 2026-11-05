'use strict';

/**
 * Body of the page blocked visitors are sent to (https://blocked.example.com/).
 *
 * The operator can replace this from the panel, so it is stored as plain HTML
 * and served as a static file by nginx — never spliced into an nginx directive.
 * The default is deliberately self-contained: no fonts, no scripts from other
 * origins, and the language is chosen in the browser, so it works for visitors
 * from any region without a server-side lookup. Unknown languages fall back to
 * English; if the operator edits the code, that is their page.
 */
const DEFAULT_FAILED_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Access restricted</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    padding: 24px; background: #f6f7f9; color: #1f2430;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", "Helvetica Neue", Arial, sans-serif;
  }
  main { max-width: 560px; width: 100%; background: #fff; border: 1px solid #e5e7eb;
    border-radius: 16px; padding: 32px; box-shadow: 0 12px 32px rgba(15, 23, 42, .06); }
  .badge { display: inline-block; font-size: 12px; letter-spacing: .08em; text-transform: uppercase;
    color: #991b1b; background: #fee2e2; border-radius: 999px; padding: 4px 10px; margin-bottom: 18px; }
  h1 { font-size: 22px; line-height: 1.35; margin: 0 0 12px; }
  p { font-size: 15px; line-height: 1.7; margin: 0 0 10px; color: #4b5563; }
  a { color: #1d4ed8; text-decoration: none; }
  a:hover { text-decoration: underline; }
  @media (prefers-color-scheme: dark) {
    body { background: #0f1115; color: #e5e7eb; }
    main { background: #171a21; border-color: #2a2f3a; box-shadow: none; }
    p { color: #a7afbd; }
    .badge { background: #3b1414; color: #fca5a5; }
    a { color: #93c5fd; }
  }
</style>
</head>
<body>
<main>
  <span class="badge" id="badge">Access restricted</span>
  <h1 id="title">This website is not yet available in your country or region</h1>
  <p id="body">We are working on expanding the regions we support. Sorry for the inconvenience.</p>
  <p><a href="https://example.com/" id="home">Back to home</a></p>
</main>
<script>
(function () {
  // Language is matched in the browser: no API call, no server-side key, and no
  // dependency on a CDN. The first two letters of navigator.language select the
  // block; anything unknown falls back to English.
  var strings = {
    en: ['Access restricted', 'This website is not yet available in your country or region',
         'We are working on expanding the regions we support. Sorry for the inconvenience.', 'Back to home'],
    zh: ['访问受限', '本网站暂未对您所在的国家或地区开放',
         '我们正在努力扩大支持的地区，给您带来不便敬请谅解。', '返回首页'],
    ja: ['アクセスが制限されています', 'このウェブサイトはお住まいの国または地域ではまだご利用いただけません',
         '対応地域を拡大するため準備を進めています。ご不便をおかけして申し訳ありません。', 'ホームへ戻る'],
    ko: ['접속이 제한되었습니다', '이 웹사이트는 현재 거주하시는 국가 또는 지역에서 이용할 수 없습니다',
         '지원 지역을 확대하기 위해 준비 중입니다. 불편을 드려 죄송합니다.', '홈으로 돌아가기'],
    ru: ['Доступ ограничен', 'Этот сайт пока недоступен в вашей стране или регионе',
         'Мы работаем над расширением списка поддерживаемых регионов. Приносим извинения за неудобства.', 'На главную'],
    es: ['Acceso restringido', 'Este sitio web aún no está disponible en tu país o región',
         'Estamos trabajando para ampliar las regiones compatibles. Sentimos las molestias.', 'Volver al inicio'],
    fr: ['Accès restreint', 'Ce site n’est pas encore disponible dans votre pays ou région',
         'Nous travaillons à étendre les régions prises en charge. Veuillez nous excuser pour la gêne occasionnée.', 'Retour à l’accueil'],
    de: ['Zugriff eingeschränkt', 'Diese Website ist in Ihrem Land oder Ihrer Region noch nicht verfügbar',
         'Wir arbeiten daran, die unterstützten Regionen zu erweitern. Wir bitten um Entschuldigung.', 'Zur Startseite'],
    pt: ['Acesso restrito', 'Este site ainda não está disponível no seu país ou região',
         'Estamos a trabalhar para alargar as regiões suportadas. Pedimos desculpa pelo incómodo.', 'Voltar ao início'],
    it: ['Accesso limitato', 'Questo sito non è ancora disponibile nel tuo paese o nella tua regione',
         'Stiamo lavorando per ampliare le regioni supportate. Ci scusiamo per il disagio.', 'Torna alla home']
  };
  var lang = String((navigator.language || navigator.userLanguage || 'en')).toLowerCase();
  var tag = lang.split('-')[0];
  var t = strings[tag] || strings.en;
  document.getElementById('badge').textContent = t[0];
  document.getElementById('title').textContent = t[1];
  document.getElementById('body').textContent = t[2];
  document.getElementById('home').textContent = t[3];
  document.documentElement.lang = strings[tag] ? tag : 'en';
})();
</script>
</body>
</html>
`;

// Generous, but bounded: the page is copied into the nginx root on every save.
const MAX_FAILED_HTML = 200 * 1024;

/** Coerce panel input into the stored HTML body, or throw a user-facing error. */
function normalizeFailedHtml(value) {
  if (value === undefined || value === null) return DEFAULT_FAILED_HTML;
  const text = String(value);
  // The helper and nginx serve bytes, not characters, so cap UTF-8 bytes — a
  // page full of CJK must obey the same 200 KB bound as an ASCII one.
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > MAX_FAILED_HTML) {
    const err = new Error(`失败页 HTML 太长，最多 ${Math.round(MAX_FAILED_HTML / 1024)} KB`);
    err.code = 'failed_page_too_long';
    err.status = 400;
    throw err;
  }
  return text;
}

module.exports = { DEFAULT_FAILED_HTML, MAX_FAILED_HTML, normalizeFailedHtml };
