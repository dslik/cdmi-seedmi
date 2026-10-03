// Multipart bodies (RFC 2046), as the protocol binding reads a queue object's
// values and an HTTP export reads a form-based file upload (RFC 7578). Kept
// apart from binding.ts, which imports exports.ts, so that each may use it.

/**
 * The parts of a multipart body, each with its media type and its
 * octets. The preamble and the epilogue are discarded, as RFC 2046
 * requires.
 */
export function splitMultipart(body: Buffer, boundary: string):
  { type: string; headers: string; body: Buffer }[] {
  const sep = Buffer.from(`--${boundary}`, "utf8");
  const out: { type: string; headers: string; body: Buffer }[] = [];
  let at = body.indexOf(sep);
  if (at < 0) return out;
  while (at >= 0) {
    const start = at + sep.length;
    // The closing delimiter ends the body.
    if (body.subarray(start, start + 2).toString() === "--") break;
    const next = body.indexOf(sep, start);
    const end = next < 0 ? body.length : next;
    let piece = body.subarray(start, end);
    // Strip the CRLF that follows the delimiter and the one that
    // precedes the next.
    if (piece.subarray(0, 2).toString() === "\r\n") piece = piece.subarray(2);
    if (piece.subarray(piece.length - 2).toString() === "\r\n") {
      piece = piece.subarray(0, piece.length - 2);
    }
    const blank = piece.indexOf("\r\n\r\n");
    const headers = blank < 0 ? piece.toString("utf8") : piece.subarray(0, blank).toString("utf8");
    const content = blank < 0 ? Buffer.alloc(0) : Buffer.from(piece.subarray(blank + 4));
    const type = /^content-type:\s*(.+)$/im.exec(headers)?.[1]?.trim() ?? "";
    out.push({ type, headers, body: content });
    if (next < 0) break;
    at = next;
  }
  return out;
}

/**
 * The file of a form-based file upload: the first part whose
 * Content-Disposition is form-data with a filename (RFC 7578, section 4.2),
 * with that filename, its media type and its octets. undefined where the body
 * holds none.
 */
export function uploadedFile(body: Buffer, boundary: string):
  { filename: string; type: string; body: Buffer } | undefined {
  for (const part of splitMultipart(body, boundary)) {
    const disposition = /^content-disposition:\s*(.+)$/im.exec(part.headers)?.[1] ?? "";
    if (!/^form-data\b/i.test(disposition.trim())) continue;
    // The quoted value is taken as it stands: a browser does not escape a
    // backslash in it (it percent-encodes a quotation mark, as the HTML
    // standard's form encoding does), so that a path carrying backslashes
    // keeps its separators.
    const quoted = /(?:^|;)\s*filename="([^"]*)"/i.exec(disposition);
    const bare = /(?:^|;)\s*filename=([^;\s]+)/i.exec(disposition);
    const filename = quoted ? quoted[1].replace(/%22/g, '"') : bare?.[1];
    if (filename === undefined) continue;
    return { filename, type: part.type, body: part.body };
  }
  return undefined;
}
