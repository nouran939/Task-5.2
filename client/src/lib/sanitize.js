import DOMPurify from 'dompurify';

// Reviews are rendered as HTML so people can use light formatting (bold, links).
// This helper is the single place review HTML passes through before it is handed
// to React's dangerouslySetInnerHTML, so it is the one seam that must keep it safe.
//
// We use DOMPurify to strip anything that could execute as script — <script>
// elements, inline event handlers (onerror/onload/onclick), and javascript: URLs —
// while preserving benign formatting. This is the client-side half of our
// defense-in-depth (the server's Content-Security-Policy is the other half).
const ALLOWED_TAGS = [
  'a', 'b', 'strong', 'i', 'em', 'u', 's',
  'br', 'p', 'span', 'ul', 'ol', 'li', 'code', 'pre', 'blockquote',
];
const ALLOWED_ATTR = ['href', 'title', 'target', 'rel'];

export const sanitizeHtml = (dirty) =>
  DOMPurify.sanitize(dirty ?? '', {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    ALLOW_DATA_ATTR: false,
    // DOMPurify already rejects javascript:/data: URLs on href by default.
  });
