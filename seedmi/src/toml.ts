// TOML, as the configuration file is written in it. Nothing may be
// installed here, so this is written by hand: the whole of TOML 1.0
// except the date and time types, which no setting of this server uses
// and which would otherwise need a calendar.
//
// Anything the parser does not understand is an error naming the line,
// rather than a value silently dropped: a configuration file holds
// credentials and keys, and a setting that is quietly ignored is the
// kind of mistake that is discovered later than it should be.

export class TOMLError extends Error {
  line: number;
  constructor(message: string, line: number) {
    super(`line ${line}: ${message}`);
    this.line = line;
  }
}

export type TOMLValue =
  | string | number | boolean | TOMLValue[] | { [key: string]: TOMLValue };

interface Table {
  [key: string]: TOMLValue;
}

/** How a table came to exist, which decides whether it may be reopened. */
type Kind = "explicit" | "implicit" | "inline" | "array";

export function parseTOML(text: string): Table {
  return new Parser(text).parse();
}

class Parser {
  private readonly s: string;
  private at = 0;
  private line = 1;
  private readonly root: Table = {};
  /** The table each key path names, and how it was made. */
  private readonly kinds = new Map<string, Kind>();
  private current: Table = this.root;
  private currentPath: string[] = [];

  constructor(text: string) {
    // A byte order mark is not part of the document.
    this.s = text.replace(/^\ufeff/, "");
  }

  parse(): Table {
    for (;;) {
      this.skipBlank();
      if (this.at >= this.s.length) break;
      const c = this.s[this.at];
      if (c === "[") {
        this.header();
      } else {
        this.keyValue();
      }
      this.endOfLine();
    }
    return this.root;
  }

  // -----------------------------------------------------------------

  private fail(message: string): never {
    throw new TOMLError(message, this.line);
  }

  private skipBlank(): void {
    for (;;) {
      const c = this.s[this.at];
      if (c === " " || c === "\t" || c === "\r") {
        this.at++;
      } else if (c === "\n") {
        this.at++;
        this.line++;
      } else if (c === "#") {
        while (this.at < this.s.length && this.s[this.at] !== "\n") this.at++;
      } else {
        return;
      }
    }
  }

  private skipInline(): void {
    for (;;) {
      const c = this.s[this.at];
      if (c === " " || c === "\t" || c === "\r") {
        this.at++;
      } else if (c === "#") {
        while (this.at < this.s.length && this.s[this.at] !== "\n") this.at++;
      } else {
        return;
      }
    }
  }

  private endOfLine(): void {
    this.skipInline();
    if (this.at >= this.s.length) return;
    if (this.s[this.at] !== "\n") {
      this.fail(`unexpected ${JSON.stringify(this.s[this.at])} after a value`);
    }
    this.at++;
    this.line++;
  }

  // -----------------------------------------------------------------
  // Tables

  private header(): void {
    const isArray = this.s.startsWith("[[", this.at);
    this.at += isArray ? 2 : 1;
    const path = this.keyPath();
    this.skipInline();
    const close = isArray ? "]]" : "]";
    if (!this.s.startsWith(close, this.at)) this.fail(`expected ${close}`);
    this.at += close.length;

    if (isArray) {
      this.openArrayTable(path);
    } else {
      this.openTable(path);
    }
  }

  private container(path: string[], forArray: boolean): Table {
    let table = this.root;
    const walked: string[] = [];
    for (const key of path) {
      walked.push(key);
      const joined = walked.join("\u0000");
      let next: TOMLValue | undefined = table[key];
      if (next === undefined) {
        next = {};
        table[key] = next;
        if (!this.kinds.has(joined)) this.kinds.set(joined, "implicit");
      } else if (Array.isArray(next)) {
        // A table within the last element of an array of tables.
        const last = next[next.length - 1];
        if (typeof last !== "object" || Array.isArray(last)) {
          this.fail(`${walked.join(".")} is not a table`);
        }
        table = last as Table;
        continue;
      } else if (typeof next !== "object") {
        this.fail(`${walked.join(".")} is not a table`);
      } else if (this.kinds.get(joined) === "inline") {
        this.fail(`${walked.join(".")} was defined as an inline table and cannot be extended`);
      }
      table = next as Table;
    }
    void forArray;
    return table;
  }

  private openTable(path: string[]): void {
    const joined = path.join("\u0000");
    const kind = this.kinds.get(joined);
    if (kind === "explicit" || kind === "inline" || kind === "array") {
      this.fail(`${path.join(".")} is defined more than once`);
    }
    this.container(path, false);
    this.kinds.set(joined, "explicit");
    this.current = this.resolve(path);
    this.currentPath = path;
  }

  private openArrayTable(path: string[]): void {
    const joined = path.join("\u0000");
    const kind = this.kinds.get(joined);
    if (kind === "explicit" || kind === "inline") {
      this.fail(`${path.join(".")} is defined more than once`);
    }
    const parent = this.container(path.slice(0, -1), true);
    const key = path[path.length - 1];
    let arr = parent[key];
    if (arr === undefined) {
      arr = [];
      parent[key] = arr;
    }
    if (!Array.isArray(arr)) this.fail(`${path.join(".")} is not an array of tables`);
    const table: Table = {};
    (arr as TOMLValue[]).push(table);
    // A new element of an array of tables begins a new scope: the
    // sub-tables of the previous element no longer stand in the way of
    // sub-tables of the same names in this one.
    const prefix = joined + "\u0000";
    for (const k of [...this.kinds.keys()]) {
      if (k.startsWith(prefix)) this.kinds.delete(k);
    }
    this.kinds.set(joined, "array");
    this.current = table;
    this.currentPath = path;
  }

  /** The table a path names, following the last element of any array. */
  private resolve(path: string[]): Table {
    let table: TOMLValue = this.root;
    for (const key of path) {
      const next: TOMLValue = (table as Table)[key];
      table = Array.isArray(next) ? (next[next.length - 1] as TOMLValue) : next;
    }
    return table as Table;
  }

  // -----------------------------------------------------------------
  // Keys and values

  private keyPath(): string[] {
    const path: string[] = [];
    for (;;) {
      this.skipInline();
      path.push(this.key());
      this.skipInline();
      if (this.s[this.at] === ".") {
        this.at++;
        continue;
      }
      return path;
    }
  }

  private key(): string {
    const c = this.s[this.at];
    if (c === '"' || c === "'") return this.stringValue();
    const start = this.at;
    while (/[A-Za-z0-9_-]/.test(this.s[this.at] ?? "")) this.at++;
    if (this.at === start) {
      this.fail(`expected a key, not ${JSON.stringify(c ?? "the end of the file")}`);
    }
    return this.s.slice(start, this.at);
  }

  private keyValue(): void {
    const path = this.keyPath();
    this.skipInline();
    if (this.s[this.at] !== "=") this.fail("expected = after a key");
    this.at++;
    this.skipInline();
    const value = this.value();
    this.assign(this.current, this.currentPath, path, value);
  }

  private assign(table: Table, base: string[], path: string[], value: TOMLValue): void {
    let t = table;
    const walked = [...base];
    for (const key of path.slice(0, -1)) {
      walked.push(key);
      const joined = walked.join("\u0000");
      const next = t[key];
      if (next === undefined) {
        const made: Table = {};
        t[key] = made;
        this.kinds.set(joined, "implicit");
        t = made;
      } else if (typeof next === "object" && !Array.isArray(next)) {
        if (this.kinds.get(joined) === "inline") {
          this.fail(`${walked.join(".")} was defined as an inline table`);
        }
        t = next as Table;
      } else {
        this.fail(`${walked.join(".")} is not a table`);
      }
    }
    const last = path[path.length - 1];
    walked.push(last);
    if (Object.prototype.hasOwnProperty.call(t, last)) {
      this.fail(`${walked.join(".")} is defined more than once`);
    }
    t[last] = value;
    if (typeof value === "object" && !Array.isArray(value)) {
      this.kinds.set(walked.join("\u0000"), "inline");
    }
  }

  private value(): TOMLValue {
    const c = this.s[this.at];
    if (c === undefined) this.fail("expected a value");
    if (c === '"' || c === "'") return this.stringValue();
    if (c === "[") return this.arrayValue();
    if (c === "{") return this.inlineTable();
    if (this.s.startsWith("true", this.at)) {
      this.at += 4;
      return true;
    }
    if (this.s.startsWith("false", this.at)) {
      this.at += 5;
      return false;
    }
    return this.numberValue();
  }

  private stringValue(): string {
    if (this.s.startsWith('"""', this.at)) return this.multiline('"""', true);
    if (this.s.startsWith("'''", this.at)) return this.multiline("'''", false);
    const quote = this.s[this.at];
    this.at++;
    let out = "";
    for (;;) {
      const c = this.s[this.at];
      if (c === undefined || c === "\n") this.fail("a string is not closed");
      if (c === quote) {
        this.at++;
        return out;
      }
      if (quote === '"' && c === "\\") {
        out += this.escape();
        continue;
      }
      out += c;
      this.at++;
    }
  }

  private multiline(fence: string, escapes: boolean): string {
    this.at += 3;
    // A newline immediately after the opening fence is not part of the
    // value.
    if (this.s[this.at] === "\r") this.at++;
    if (this.s[this.at] === "\n") {
      this.at++;
      this.line++;
    }
    let out = "";
    for (;;) {
      if (this.at >= this.s.length) this.fail("a multi-line string is not closed");
      if (this.s.startsWith(fence, this.at)) {
        this.at += 3;
        // Up to two further quotes belong to the value.
        while (this.s[this.at] === fence[0] && out.length < this.s.length) {
          out += fence[0];
          this.at++;
          if (out.endsWith(fence)) this.fail("a multi-line string is not closed");
        }
        return out;
      }
      const c = this.s[this.at];
      if (escapes && c === "\\") {
        // A backslash at the end of a line removes the newline and the
        // whitespace that follows it.
        const rest = this.s.slice(this.at + 1);
        const trimmed = rest.match(/^[ \t\r]*\n/);
        if (trimmed) {
          this.at += 1 + trimmed[0].length;
          this.line++;
          while (/[ \t\r\n]/.test(this.s[this.at] ?? "")) {
            if (this.s[this.at] === "\n") this.line++;
            this.at++;
          }
          continue;
        }
        out += this.escape();
        continue;
      }
      if (c === "\n") this.line++;
      out += c;
      this.at++;
    }
  }

  private escape(): string {
    this.at++; // the backslash
    const c = this.s[this.at];
    this.at++;
    switch (c) {
      case "b": return "\b";
      case "t": return "\t";
      case "n": return "\n";
      case "f": return "\f";
      case "r": return "\r";
      case '"': return '"';
      case "\\": return "\\";
      case "u": return this.codepoint(4);
      case "U": return this.codepoint(8);
      default: return this.fail(`\\${c} is not an escape this parser knows`);
    }
  }

  private codepoint(digits: number): string {
    const hex = this.s.slice(this.at, this.at + digits);
    if (!new RegExp(`^[0-9A-Fa-f]{${digits}}$`).test(hex)) {
      this.fail("an escape of a code point is not well formed");
    }
    this.at += digits;
    return String.fromCodePoint(Number.parseInt(hex, 16));
  }

  private arrayValue(): TOMLValue[] {
    this.at++; // [
    const out: TOMLValue[] = [];
    for (;;) {
      this.skipBlank();
      if (this.s[this.at] === "]") {
        this.at++;
        return out;
      }
      out.push(this.value());
      this.skipBlank();
      if (this.s[this.at] === ",") {
        this.at++;
        continue;
      }
      this.skipBlank();
      if (this.s[this.at] === "]") {
        this.at++;
        return out;
      }
      this.fail("expected , or ] in an array");
    }
  }

  private inlineTable(): Table {
    this.at++; // {
    const table: Table = {};
    this.skipInline();
    if (this.s[this.at] === "}") {
      this.at++;
      return table;
    }
    for (;;) {
      this.skipInline();
      const path = this.keyPath();
      this.skipInline();
      if (this.s[this.at] !== "=") this.fail("expected = in an inline table");
      this.at++;
      this.skipInline();
      const value = this.value();
      let t = table;
      for (const key of path.slice(0, -1)) {
        const next = t[key];
        if (next === undefined) {
          const made: Table = {};
          t[key] = made;
          t = made;
        } else if (typeof next === "object" && !Array.isArray(next)) {
          t = next as Table;
        } else {
          this.fail(`${key} is not a table`);
        }
      }
      const last = path[path.length - 1];
      if (Object.prototype.hasOwnProperty.call(t, last)) {
        this.fail(`${path.join(".")} is defined more than once`);
      }
      t[last] = value;
      this.skipInline();
      if (this.s[this.at] === ",") {
        this.at++;
        continue;
      }
      if (this.s[this.at] === "}") {
        this.at++;
        return table;
      }
      this.fail("expected , or } in an inline table");
    }
  }

  private numberValue(): number {
    const start = this.at;
    // A date or a time is not supported, and is refused rather than
    // read as the number it begins with.
    const ahead = this.s.slice(this.at, this.at + 32);
    if (/^\d{4}-\d{2}-\d{2}/.test(ahead) || /^\d{2}:\d{2}:\d{2}/.test(ahead)) {
      this.fail("this parser does not read a date or a time");
    }
    const radix = /^[+-]?0x/.test(ahead)
      ? 16
      : /^[+-]?0o/.test(ahead) ? 8 : /^[+-]?0b/.test(ahead) ? 2 : 10;
    if (radix !== 10) {
      this.at += this.s[this.at] === "+" || this.s[this.at] === "-" ? 3 : 2;
      const from = this.at;
      while (/[0-9A-Fa-f_]/.test(this.s[this.at] ?? "")) this.at++;
      const digits = this.s.slice(from, this.at).replace(/_/g, "");
      if (digits === "") this.fail("a number has no digits");
      const sign = this.s[start] === "-" ? -1 : 1;
      return sign * Number.parseInt(digits, radix);
    }
    while (/[0-9+\-_.eE]/.test(this.s[this.at] ?? "")) this.at++;
    const raw = this.s.slice(start, this.at);
    if (/^[+-]?(inf|nan)$/.test(raw)) this.fail("inf and nan are not read by this parser");
    const cleaned = raw.replace(/_/g, "");
    const value = Number(cleaned);
    if (cleaned === "" || !Number.isFinite(value)) {
      this.fail(`${JSON.stringify(raw)} is not a number`);
    }
    return value;
  }
}
