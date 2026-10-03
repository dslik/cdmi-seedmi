// The NFSv4.1 protocol: the constants and the attribute encoding of
// RFC 8881. The operations themselves are in nfs-server.ts.

import { XDRWriter } from "./xdr.ts";

export const NFS4_FHSIZE = 128;
export const NFS4_VERIFIER_SIZE = 8;
export const NFS4_SESSIONID_SIZE = 16;
export const NFS4_OTHER_SIZE = 12;

/** The operations, from the nfs_opnum4 enumeration. */
export const OP = {
  ACCESS: 3,
  CLOSE: 4,
  COMMIT: 5,
  CREATE: 6,
  DELEGPURGE: 7,
  DELEGRETURN: 8,
  GETATTR: 9,
  GETFH: 10,
  LINK: 11,
  LOCK: 12,
  LOCKT: 13,
  LOCKU: 14,
  LOOKUP: 15,
  LOOKUPP: 16,
  NVERIFY: 17,
  OPEN: 18,
  OPENATTR: 19,
  OPEN_DOWNGRADE: 21,
  PUTFH: 22,
  PUTPUBFH: 23,
  PUTROOTFH: 24,
  READ: 25,
  READDIR: 26,
  READLINK: 27,
  REMOVE: 28,
  RENAME: 29,
  RESTOREFH: 31,
  SAVEFH: 32,
  SECINFO: 33,
  SETATTR: 34,
  VERIFY: 37,
  WRITE: 38,
  BACKCHANNEL_CTL: 40,
  BIND_CONN_TO_SESSION: 41,
  EXCHANGE_ID: 42,
  CREATE_SESSION: 43,
  DESTROY_SESSION: 44,
  FREE_STATEID: 45,
  GETDEVICEINFO: 47,
  SECINFO_NO_NAME: 52,
  SEQUENCE: 53,
  TEST_STATEID: 55,
  DESTROY_CLIENTID: 57,
  RECLAIM_COMPLETE: 58,
  // The extended attribute operations of RFC 8276, which are of the
  // second minor version.
  GETXATTR: 72,
  SETXATTR: 73,
  LISTXATTRS: 74,
  REMOVEXATTR: 75,
  ILLEGAL: 10044,
} as const;

export const OP_NAME: Record<number, string> = Object.fromEntries(
  Object.entries(OP).map(([name, n]) => [n, name]));

/** The status values this server returns, from nfsstat4. */
export const NFS4 = {
  OK: 0,
  PERM: 1,
  NOENT: 2,
  IO: 5,
  ACCESS: 13,
  EXIST: 17,
  NOTDIR: 20,
  ISDIR: 21,
  INVAL: 22,
  FBIG: 27,
  NOSPC: 28,
  ROFS: 30,
  NAMETOOLONG: 63,
  NOTEMPTY: 66,
  DQUOT: 69,
  STALE: 70,
  BADHANDLE: 10001,
  BAD_COOKIE: 10003,
  NOTSUPP: 10004,
  TOOSMALL: 10005,
  SERVERFAULT: 10006,
  BADTYPE: 10007,
  OLD_STATEID: 10024,
  BAD_STATEID: 10025,
  NOFILEHANDLE: 10020,
  MINOR_VERS_MISMATCH: 10021,
  OP_ILLEGAL: 10044,
  BADOWNER: 10039,
  STALE_CLIENTID: 10022,
  BADSESSION: 10052,
  BADSLOT: 10053,
  SEQ_MISORDERED: 10063,
  SEQUENCE_POS: 10064,
  REQ_TOO_BIG: 10065,
  REP_TOO_BIG: 10066,
  NOT_ONLY_OP: 10081,
  WRONG_TYPE: 10083,
  DEADSESSION: 10078,
  OP_NOT_IN_SESSION: 10071,
  TOO_MANY_OPS: 10070,
  OPENMODE: 10038,
  SYMLINK: 10029,
  /** No extended attribute of that name exists (RFC 8276). */
  NOXATTR: 10095,
  /** The extended attribute is larger than the server will hold. */
  XATTR2BIG: 10096,
} as const;

/** The file types of nfs_ftype4. */
export const NF4REG = 1;
export const NF4DIR = 2;

/** The bits of the ACCESS operation. */
export const ACCESS4 = {
  READ: 0x0001,
  LOOKUP: 0x0002,
  MODIFY: 0x0004,
  EXTEND: 0x0008,
  DELETE: 0x0010,
  EXECUTE: 0x0020,
} as const;

/** The attribute numbers this server knows. */
export const FATTR4 = {
  SUPPORTED_ATTRS: 0,
  TYPE: 1,
  FH_EXPIRE_TYPE: 2,
  CHANGE: 3,
  SIZE: 4,
  LINK_SUPPORT: 5,
  SYMLINK_SUPPORT: 6,
  NAMED_ATTR: 7,
  FSID: 8,
  UNIQUE_HANDLES: 9,
  LEASE_TIME: 10,
  RDATTR_ERROR: 11,
  FILEHANDLE: 19,
  FILEID: 20,
  MAXFILESIZE: 27,
  MAXNAME: 29,
  MAXREAD: 30,
  MAXWRITE: 31,
  MODE: 33,
  NUMLINKS: 35,
  OWNER: 36,
  OWNER_GROUP: 37,
  SPACE_USED: 45,
  TIME_ACCESS: 47,
  TIME_METADATA: 52,
  TIME_MODIFY: 53,
  MOUNTED_ON_FILEID: 55,
  SUPPATTR_EXCLCREAT: 75,
  /** Whether the file system of the object supports extended attributes. */
  XATTR_SUPPORT: 82,
} as const;

/** A file handle does not expire while the server runs. */
export const FH4_VOLATILE_ANY = 0x00000001;
export const FH4_PERSISTENT = 0x00000000;

/** The flags of EXCHANGE_ID this server sets. */
export const EXCHGID4_FLAG_USE_NON_PNFS = 0x00010000;
export const EXCHGID4_FLAG_CONFIRMED_R = 0x80000000;

/** The flags of CREATE_SESSION. */
export const CREATE_SESSION4_FLAG_PERSIST = 0x00000001;

/** The share access and deny bits of OPEN. */
export const OPEN4_SHARE_ACCESS_READ = 0x00000001;
export const OPEN4_SHARE_ACCESS_WRITE = 0x00000002;
export const OPEN4_SHARE_ACCESS_BOTH = 0x00000003;
export const OPEN4_SHARE_DENY_NONE = 0x00000000;

/** The open types and the creation modes of OPEN. */
export const OPEN4_NOCREATE = 0;
export const OPEN4_CREATE = 1;
export const UNCHECKED4 = 0;
export const GUARDED4 = 1;
export const EXCLUSIVE4 = 2;
export const EXCLUSIVE4_1 = 3;

/** The claim types; this server performs CLAIM_NULL alone. */
export const CLAIM_NULL = 0;

/** The delegation types; this server grants none. */
export const OPEN_DELEGATE_NONE = 0;

/** How far a write has been committed. */
export const UNSTABLE4 = 0;
export const DATA_SYNC4 = 1;
export const FILE_SYNC4 = 2;

/** The file types a CREATE may ask for. */
export const NF4LNK = 5;
export const NF4BLK = 3;
export const NF4CHR = 4;
export const NF4SOCK = 6;
export const NF4FIFO = 7;

/** SP4_NONE, the only state protection this server offers. */
export const SP4_NONE = 0;

export const NFS4_INT64_MAX = 0x7fffffffffffffffn;

/** A time, as nfstime4: seconds since the epoch and nanoseconds. */
export function writeTime(w: XDRWriter, ms: number): void {
  const seconds = Math.floor(ms / 1000);
  w.hyper(BigInt(seconds));
  w.uint((ms - seconds * 1000) * 1_000_000);
}

/** What an object looks like to NFS, gathered before its attributes are written. */
export interface NfsAttrs {
  /** Whether the object holds extended attributes. */
  xattrSupport?: boolean;
  type: number;
  /** The change attribute: it moves whenever the object changes. */
  change: bigint;
  size: bigint;
  fileid: bigint;
  fsid: { major: bigint; minor: bigint };
  handle: Buffer;
  mode: number;
  numlinks: number;
  owner: string;
  ownerGroup: string;
  atime: number;
  mtime: number;
  ctime: number;
  /** Where an attribute cannot be obtained, the error to report for it. */
  rdattrError?: number;
}

/** The attributes this server is able to return. */
export const SUPPORTED_ATTRS: number[] = [
  FATTR4.SUPPORTED_ATTRS, FATTR4.TYPE, FATTR4.FH_EXPIRE_TYPE, FATTR4.CHANGE,
  FATTR4.SIZE, FATTR4.LINK_SUPPORT, FATTR4.SYMLINK_SUPPORT, FATTR4.NAMED_ATTR,
  FATTR4.FSID, FATTR4.UNIQUE_HANDLES, FATTR4.LEASE_TIME, FATTR4.RDATTR_ERROR,
  FATTR4.FILEHANDLE, FATTR4.FILEID, FATTR4.MAXFILESIZE, FATTR4.MAXNAME,
  FATTR4.MAXREAD, FATTR4.MAXWRITE, FATTR4.MODE, FATTR4.NUMLINKS, FATTR4.OWNER,
  FATTR4.OWNER_GROUP, FATTR4.SPACE_USED, FATTR4.TIME_ACCESS, FATTR4.TIME_METADATA,
  FATTR4.TIME_MODIFY, FATTR4.MOUNTED_ON_FILEID, FATTR4.SUPPATTR_EXCLCREAT,
  FATTR4.XATTR_SUPPORT,
];

/** The attributes a client may set, which is the size alone. */
export const SETTABLE_ATTRS: number[] = [FATTR4.SIZE];

export const LEASE_TIME = 90;
export const MAXREAD = 1 << 20;
export const MAXWRITE = 1 << 20;
export const MAXNAME = 255;

/**
 * Encodes a fattr4: the bitmap of the attributes returned, followed by
 * their values packed in increasing order of attribute number. An
 * attribute the server does not support is not returned, and the client
 * discovers that from the bitmap rather than from an error.
 */
export function writeAttrs(w: XDRWriter, requested: number[], a: NfsAttrs): void {
  const wanted = requested.filter((bit) => SUPPORTED_ATTRS.includes(bit)).sort((x, y) =>
    x - y);
  const values = new XDRWriter();
  const returned: number[] = [];
  for (const bit of wanted) {
    switch (bit) {
      case FATTR4.SUPPORTED_ATTRS: values.bitmap(SUPPORTED_ATTRS); break;
      case FATTR4.TYPE: values.uint(a.type); break;
      // A handle remains valid while the server runs, and is not
      // guaranteed across a restart.
      case FATTR4.FH_EXPIRE_TYPE: values.uint(FH4_VOLATILE_ANY); break;
      case FATTR4.CHANGE: values.uhyper(a.change); break;
      case FATTR4.SIZE: values.uhyper(a.size); break;
      case FATTR4.LINK_SUPPORT: values.bool(false); break;
      case FATTR4.SYMLINK_SUPPORT: values.bool(false); break;
      case FATTR4.NAMED_ATTR: values.bool(false); break;
      case FATTR4.FSID:
        values.uhyper(a.fsid.major);
        values.uhyper(a.fsid.minor);
        break;
      case FATTR4.UNIQUE_HANDLES: values.bool(true); break;
      case FATTR4.LEASE_TIME: values.uint(LEASE_TIME); break;
      case FATTR4.RDATTR_ERROR: values.uint(a.rdattrError ?? NFS4.OK); break;
      case FATTR4.FILEHANDLE: values.opaque(a.handle); break;
      case FATTR4.FILEID: values.uhyper(a.fileid); break;
      case FATTR4.MAXFILESIZE: values.uhyper(NFS4_INT64_MAX); break;
      case FATTR4.MAXNAME: values.uint(MAXNAME); break;
      case FATTR4.MAXREAD: values.uhyper(BigInt(MAXREAD)); break;
      case FATTR4.MAXWRITE: values.uhyper(BigInt(MAXWRITE)); break;
      case FATTR4.MODE: values.uint(a.mode); break;
      case FATTR4.NUMLINKS: values.uint(a.numlinks); break;
      case FATTR4.OWNER: values.string(a.owner); break;
      case FATTR4.OWNER_GROUP: values.string(a.ownerGroup); break;
      case FATTR4.SPACE_USED: values.uhyper(a.size); break;
      case FATTR4.TIME_ACCESS: writeTime(values, a.atime); break;
      case FATTR4.TIME_METADATA: writeTime(values, a.ctime); break;
      case FATTR4.TIME_MODIFY: writeTime(values, a.mtime); break;
      case FATTR4.MOUNTED_ON_FILEID: values.uhyper(a.fileid); break;
      case FATTR4.SUPPATTR_EXCLCREAT: values.bitmap([]); break;
      // Every object of the store holds user metadata, which is what
      // an extended attribute presents.
      case FATTR4.XATTR_SUPPORT: values.bool(a.xattrSupport ?? false); break;
      default: continue;
    }
    returned.push(bit);
  }
  w.bitmap(returned);
  w.opaque(values.bytes());
}

/** The option of a SETXATTR, as RFC 8276 defines it. */
export const SETXATTR4_EITHER = 0;
export const SETXATTR4_CREATE = 1;
export const SETXATTR4_REPLACE = 2;

/**
 * The minor versions of NFSv4 this server answers. The extended
 * attribute operations belong to the second, so a client that wants
 * them asks for it in the COMPOUND.
 */
export const MINOR_VERSIONS = [1, 2];

/**
 * The namespace of the extended attributes that carry user metadata.
 * RFC 8276 carries a key neither the client nor the server interprets,
 * so the name a POSIX client uses arrives here with its prefix.
 */
export const XATTR_PREFIX = "user.";
