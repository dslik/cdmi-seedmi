// Multipart uploads of an S3 export.
//
// An upload begins with a CreateMultipartUpload request naming a
// key, continues with UploadPart requests carrying a part number and
// the bytes of that part, and ends with a CompleteMultipartUpload
// request listing the parts to assemble, or with an abort.
//
// An upload in progress is not a CDMI object. The parts are held in
// storage of this CDMI server's own and are presented through no
// protocol binding, no export and no listing: a CDMI client observes
// only the aggregate counts of the export entry.

import { createHash, randomUUID } from "node:crypto";

/** The limits this CDMI server reports through its capabilities. */
export const MAX_PARTS = 10000;
export const MAX_PART_SIZE = 5 * 1024 * 1024 * 1024;
export const MIN_PART_SIZE = 5 * 1024 * 1024;
/** The period after which an upload that has not ended is aborted. */
export const DEFAULT_EXPIRY = "P7D";

/** One part received for an upload. */
export interface Part {
  number: number;
  body: Buffer;
  etag: string;
  received: number;
}

/** One upload in progress. */
export interface Upload {
  id: string;
  /** The bucket the upload belongs to, by the name of its entry. */
  bucket: string;
  key: string;
  /** The principal that initiated it, which alone may add parts. */
  initiator: string;
  mimetype: string;
  began: number;
  parts: Map<number, Part>;
}

/** The entity tag of a part, which is the hash of its bytes. */
export const etagOf = (body: Buffer): string =>
  createHash("md5").update(body).digest("hex");

/**
 * The uploads in progress. They are held in memory: an upload in
 * progress is not a CDMI object, and one that does not survive a
 * restart is one a client re-initiates, which is what an S3 client
 * does where a server reports NoSuchUpload.
 */
export class Uploads {
  private readonly held = new Map<string, Upload>();

  /** Begins an upload, returning its identifier. */
  begin(bucket: string, key: string, initiator: string, mimetype: string,
    now = Date.now()): Upload {
    const upload: Upload = {
      id: randomUUID().replace(/-/g, ""),
      bucket,
      key,
      initiator,
      mimetype,
      began: now,
      parts: new Map(),
    };
    this.held.set(upload.id, upload);
    return upload;
  }

  /** The upload of an identifier, where it is in progress. */
  get(id: string): Upload | undefined {
    return this.held.get(id);
  }

  /** Ends an upload, discarding its parts. */
  end(id: string): void {
    this.held.delete(id);
  }

  /** The uploads in progress for a bucket, oldest first. */
  forBucket(bucket: string): Upload[] {
    return [...this.held.values()]
      .filter((u) => u.bucket === bucket)
      .sort((a, b) => a.began - b.began);
  }

  /**
   * Adds a part, replacing the part most recently received under
   * that number. A request may arrive in any order, concurrently,
   * and more than once for one number.
   */
  addPart(upload: Upload, number: number, body: Buffer, now = Date.now()): Part {
    const part: Part = { number, body, etag: etagOf(body), received: now };
    upload.parts.set(number, part);
    return part;
  }

  /** The number of uploads in progress, which the entry reports. */
  count(bucket: string): number {
    return this.forBucket(bucket).length;
  }

  /** The total size of the parts held, which the entry reports. */
  size(bucket: string): number {
    let total = 0;
    for (const u of this.forBucket(bucket)) {
      for (const p of u.parts.values()) total += p.body.length;
    }
    return total;
  }

  /**
   * Aborts every upload of a bucket that has outlived the period,
   * and every upload of a bucket whose export has gone. The period
   * in effect at the time the expiry is evaluated is the one
   * applied, so reducing it aborts uploads already older than the
   * new value.
   */
  expire(bucket: string, period: string | undefined, now = Date.now()): number {
    const ms = durationMillis(period ?? DEFAULT_EXPIRY);
    let ended = 0;
    for (const u of this.forBucket(bucket)) {
      if (now - u.began < ms) continue;
      this.end(u.id);
      ended += 1;
    }
    return ended;
  }

  /** Aborts every upload of a bucket, for an export that is removed. */
  abortAll(bucket: string): void {
    for (const u of this.forBucket(bucket)) this.end(u.id);
  }
}

/**
 * The milliseconds of a duration. Only the designators a period of
 * this kind uses are read: a year is 365 days and a month 30, which
 * is the approximation a period measured from an instant needs.
 */
export function durationMillis(period: string): number {
  const m = /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/
    .exec(period);
  if (m === null) return durationMillis(DEFAULT_EXPIRY);
  const [, y, mo, w, d, h, mi, s] = m.map((x) => (x === undefined ? 0 : Number(x)));
  return ((((Number(y) * 365 + Number(mo) * 30 + Number(w) * 7 + Number(d)) * 24 +
    Number(h)) * 60 + Number(mi)) * 60 + Number(s)) * 1000;
}

/** The body of a CreateMultipartUpload response. */
export function initiateBody(bucket: string, key: string, id: string): string {
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
    `<Bucket>${xml(bucket)}</Bucket><Key>${xml(key)}</Key>` +
    `<UploadId>${xml(id)}</UploadId></InitiateMultipartUploadResult>\n`;
}

/** The body of a CompleteMultipartUpload response. */
export function completeBody(location: string, bucket: string, key: string,
  etag: string): string {
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
    `<Location>${xml(location)}</Location><Bucket>${xml(bucket)}</Bucket>` +
    `<Key>${xml(key)}</Key><ETag>&quot;${xml(etag)}&quot;</ETag>` +
    "</CompleteMultipartUploadResult>\n";
}

/** The body of a ListParts response. */
export function partsBody(bucket: string, upload: Upload): string {
  const parts = [...upload.parts.values()].sort((a, b) => a.number - b.number);
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
    `<Bucket>${xml(bucket)}</Bucket><Key>${xml(upload.key)}</Key>` +
    `<UploadId>${xml(upload.id)}</UploadId>` +
    "<IsTruncated>false</IsTruncated>" +
    parts.map((p) =>
      `<Part><PartNumber>${p.number}</PartNumber>` +
      `<ETag>&quot;${xml(p.etag)}&quot;</ETag>` +
      `<Size>${p.body.length}</Size>` +
      `<LastModified>${new Date(p.received).toISOString().replace(/\.\d+Z$/, ".000Z")}` +
      "</LastModified></Part>").join("") +
    "</ListPartsResult>\n";
}

/** The body of a ListMultipartUploads response. */
export function uploadsBody(bucket: string, uploads: Upload[]): string {
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
    `<Bucket>${xml(bucket)}</Bucket><IsTruncated>false</IsTruncated>` +
    uploads.map((u) =>
      `<Upload><Key>${xml(u.key)}</Key><UploadId>${xml(u.id)}</UploadId>` +
      `<Initiated>${new Date(u.began).toISOString().replace(/\.\d+Z$/, ".000Z")}` +
      "</Initiated></Upload>").join("") +
    "</ListMultipartUploadsResult>\n";
}

/** The parts a CompleteMultipartUpload request lists. */
export function parseCompleteBody(body: string):
  { number: number; etag: string }[] | undefined {
  const parts: { number: number; etag: string }[] = [];
  const re = /<Part>([\s\S]*?)<\/Part>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const number = /<PartNumber>\s*(\d+)\s*<\/PartNumber>/.exec(m[1]);
    // The entity tag is quoted, and the quotation marks may be
    // written as characters or as references.
    const etag = /<ETag>\s*(?:&quot;|")?([^<"&]*)(?:&quot;|")?\s*<\/ETag>/
      .exec(m[1]);
    if (number === null || etag === null) return undefined;
    parts.push({ number: Number(number[1]), etag: etag[1] });
  }
  return parts.length === 0 ? undefined : parts;
}

function xml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&apos;",
  })[c] as string);
}
