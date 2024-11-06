/// <reference path="./types.d.ts" />
import { CryptoHasher, write, file } from "bun";
import { randomBytes } from "node:crypto";
import { promises as fr, existsSync, mkdirSync } from "node:fs";
import { Brioche, PGCache, is } from "./index";
import { sign, verify } from "jsonwebtoken";
import { Client } from "pg";

type sessionConfig = {
  COOKIE_NAME: string;
  COOKIE_DOMAIN: string;
  COOKIE_PATH: null;
  COOKIE_HTTPONLY: boolean;
  COOKIE_SECURE: boolean;
  REFRESH_EACH_REQUEST: boolean;
  COOKIE_SAMESITE: string;
  KEY_PREFIX: string;
  PERMANENT: boolean;
  USE_SIGNER: boolean;
  ID_LENGTH: number;
  FILE_THRESHOLD: number;
  LIFETIME: number;
  MAX_COOKIE_SIZE: number;
  INTERFACE: string;
  STORAGE: string;
  JWT_STORAGE: string;
  SUPABASE_CLIENT: any;
  SUPABASE_TABLE: string;
};
// -----------------------------

class callBack {
  data: obj<string>;
  modified: boolean;
  accessed: boolean;
  new: boolean = true;
  length = 0;
  constructor(initial: obj<string> = {}) {
    this.modified = true;
    this.accessed = true;
    this.data = {};
    if (Object.entries(initial).length) {
      this.new = false;
    }
    Object.assign(this.data, initial);
  }
  set(target: any, prop: string, val: string) {
    if (target.data[prop] != val) {
      this.modified = true;
      target.data[prop] = val;
      this.length++;
    }
    return target;
  }
  get(target: any, prop: string) {
    if (prop in target) {
      return target[prop];
    }
    return target.data[prop];
  }
  has(target: any, prop: string) {
    if (prop in target.data) {
      return true;
    }
    return false;
  }
  deleteProperty(target: any, val: string) {
    if (val in target.data) {
      this.modified = true;
      delete target.data[val];
    }
    return true;
  }
}
// --------------
export class serverSide extends callBack {
  [Key: string]: any;
  modified: boolean;
  sid: string;
  permanent: boolean;
  constructor(
    sid: string = "",
    permanent: boolean = false,
    initial: obj<string> = {},
  ) {
    super(initial);
    this.modified = false;
    this.sid = sid;
    this.permanent = permanent;
  }
  get session() {
    return new Proxy<serverSide>(this, this);
  }
}

export class Session extends serverSide {}

// --------------
function str2Buffer(str: string): Buffer {
  const encoder = new TextEncoder();

  return Buffer.from(str);
}
function buff2Str(str: Uint8Array): string {
  const decoder = new TextDecoder();
  return decoder.decode(str);
}
function getSignature(key: Uint8Array, vals: Buffer) {
  //   const hmac = createHmac("sha1", key, vals);
  const hmac = new CryptoHasher("sha1", key);

  return hmac.digest();
}
export function timeDelta(date1: number, date2: number | null = null) {
  if (date2) {
    let diff = Math.abs(date2 - date1);
    return new Date(diff);
  } else {
    const now = new Date();
    const later = new Date();
    later.setDate(now.getDate() + date1);
    let diff = Math.abs(later.getTime() - now.getTime());
    return new Date(now.getTime() + diff);
  }
}
export function cookieDump(
  key: string,
  value: string = "",
  //
  {
    maxAge,
    expires,
    path = "/",
    domain,
    secure,
    httpOnly,
    sameSite,
  }: {
    maxAge?: Date | number;
    expires?: Date | string | number;
    path?: string | null;
    domain?: string;
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: string | null;
    sync_expires?: boolean;
    max_size?: number;
  },
) {
  if (maxAge instanceof Date) {
    maxAge = maxAge.getSeconds();
  }

  if (expires instanceof Date) {
    expires = expires.toUTCString();
  } else if (expires === 0) {
    expires = new Date().toUTCString();
  }

  const buf = [`${key}=${value}`];
  const cprops = [
    ["Domain", domain],
    ["Expires", expires],
    ["Max-Age", maxAge],
    ["Secure", secure],
    ["HttpOnly", httpOnly],
    ["Path", path],
    ["SameSite", sameSite],
  ];

  Object.entries(cprops).forEach(([k, [kk, v]]) => {
    if (v) {
      buf.push(`${kk}=${v}`);
    }
  });

  return buf.join("; ");
}
export function hashedToken(len = 64) {
  return new CryptoHasher("sha1").update(randomBytes(64)).digest("hex");
}

// --------------

class signer {
  secret: string;
  salt: string;
  constructor(secret: string, salt: string) {
    this.secret = secret;
    this.salt = salt;
  }
  getSignature(val: string) {
    const vals = str2Buffer(val);
    const key = this.deriveKey();
    const sig = getSignature(vals, key);
    return sig.toString("base64");
  }
  deriveKey() {
    const skey = str2Buffer(this.secret);
    // const hmac = createHmac("sha1", skey);
    const hmac = new CryptoHasher("sha1", skey);
    hmac.update(this.salt);
    return hmac.digest();
  }
  sign(val: string) {
    const sig = this.getSignature(val);
    const vals = str2Buffer(val + "." + sig);
    return buff2Str(vals);
  }
  unsign(signedVal: string) {
    if (!(signedVal.indexOf(".") > -1)) {
      throw Error("No sep found");
    }
    const isept = signedVal.indexOf(".");
    const val = signedVal.slice(0, isept);
    const sig = signedVal.slice(isept + 1);
    return this.verifySignature(val, sig);
  }
  loadUnsign(vals: string) {
    if (this.unsign(vals)) {
      const sval = str2Buffer(vals);
      const sept = str2Buffer(".")[0];
      if (!(sept in sval)) {
        throw Error("No sep found");
      }
      const isept = sval.indexOf(sept);
      const val = sval.subarray(0, isept);

      return Buffer.from(val.toString(), "base64").toString("utf-8");
    }
  }
  verifySignature(val: string, sig: string) {
    return this.getSignature(val) == sig ? true : false;
  }
}

export class sidGenerator {
  signer: signer;
  secret: string;
  constructor(secret: string) {
    this.secret = secret;
    this.signer = new signer(secret, secret + "_salty");
  }
  generate(len = 21) {
    const rbyte = randomBytes(len);
    let lbyte = rbyte.toString("base64");
    if (lbyte.endsWith("=")) {
      lbyte = lbyte.slice(0, -1);
    }
    return this.signer.sign(lbyte);
  }
  _sign(sid: string) {
    return this.signer.sign(sid);
  }
  _unsign(sid: string) {
    return this.signer.unsign(sid);
  }
}

export class serverInterface extends sidGenerator {
  sclass: typeof serverSide = serverSide;
  permanent: boolean = false;
  config: sessionConfig;
  constructor(config: sessionConfig, secret: string) {
    super(secret);
    this.config = config;
    this.permanent = config.PERMANENT;
  }
  setCookie(xsesh: serverSide, life: Date | number, _sameSite = "") {
    let sameSite = null;
    if (this.config.COOKIE_SAMESITE) {
      sameSite = this.config.COOKIE_SAMESITE;
    }

    if (_sameSite) {
      sameSite = _sameSite;
    }

    return cookieDump(this.config.COOKIE_NAME!, xsesh.sid, {
      domain: "",
      path: this.config.COOKIE_PATH,
      httpOnly: this.config.COOKIE_HTTPONLY,
      secure: this.config.COOKIE_SECURE,
      sameSite: sameSite,
      expires: life,
    });
  }
  async openSession(sid: string): Promise<serverSide> {
    if (!sid) {
      return new this.sclass(this.generate(), this.permanent).session;
    }
    if (this._unsign(sid)) {
      return await this.fetchSession(sid);
    } else {
      return new this.sclass(this.generate(), this.permanent).session;
    }
  }
  async fetchSession(sid: string): Promise<serverSide> {
    return new this.sclass(this.generate(), this.permanent).session;
  }
  async saveSession(
    xsesh: serverSide,
    rsx?: any,
    deleteMe: boolean = false,
    sameSite: string = "",
  ) {
    return;
  }
  getExpiration(config: sessionConfig, xsesh: serverSide): string | null {
    if (xsesh.permanent) {
      const now = new Date();
      const lifet = config.LIFETIME;
      return now.setDate(now.getDate() + lifet).toString();
    }
    return null;
  }
  deleteBrowserSession(xsesh: serverSide, rsx?: any) {
    if (rsx) {
      const cookie = this.setCookie(xsesh, 0);
      rsx.header = { "Set-Cookie": cookie };
    }
  }
}

// Local cache
class cacher {
  path: string;
  constructor(pathName: string = ".sessions") {
    this.path = pathName;
    if (!existsSync(this.path)) {
      mkdirSync(this.path, { recursive: true });
    }
  }
  fileName(fname: string) {
    const bkey = str2Buffer(fname);
    const hash = new CryptoHasher("md5");
    hash.update(bkey);
    return hash.digest("hex");
  }
  async delete(key: string) {
    const gspot = this.path + "/" + this.fileName(key);
    try {
      const FS = await fr.stat(gspot);
      if (FS.isFile()) {
        await fr.unlink(gspot);
      }
    } catch (err) {}
  }
  //   -------------------
  async set(key: string, data: obj<any>, life: number = 0) {
    const tempFilePath = this.path + "/" + this.fileName(key);
    await is.file(tempFilePath);
    Object.assign(data, { life: timeDelta(life) });
    await write(tempFilePath, JSON.stringify(data));
  }
  async get(key: string) {
    const gspot = this.fileName(key);
    try {
      const rfile = await fr.readFile(this.path + "/" + gspot);
      const dt = await file(this.path + "/" + gspot).json();
      if (new Date(dt.life).getTime() - new Date().getTime() > 0) {
        return JSON.parse(dt.data);
      } else {
        this.delete(key);
        return null;
      }
    } catch (err) {}
  }
}

class cSession extends serverInterface {
  cacher: cacher;
  sclass = Session;
  constructor(config: sessionConfig, secret: string, cacherpath = ".sessions") {
    super(config, secret);
    this.cacher = new cacher(cacherpath);
  }
  async saveSession(xsesh: serverSide, rsx?: any, deleteMe: boolean = false) {
    const prefs = this.config.KEY_PREFIX + xsesh.sid;
    if (!Object.entries(xsesh.data).length) {
      if (xsesh.modified || deleteMe) {
        await this.cacher.delete(prefs);
        if (rsx) {
          const cookie = this.setCookie(xsesh, 0);
          rsx.header = { "Set-Cookie": cookie };
        }
      }
      return;
    }
    const life = this.config.LIFETIME;
    const data = JSON.stringify(xsesh.data);

    await this.cacher.set(prefs, { data }, life);
    if (rsx) {
      const cookie = this.setCookie(xsesh, timeDelta(life));

      rsx.header = { "Set-Cookie": cookie };
    }
  }
  async fetchSession(sid: string) {
    const prefs = this.config.KEY_PREFIX + sid;
    const data = await this.cacher.get(prefs);
    return new this.sclass(sid, this.config.PERMANENT, await data).session;
  }
}

// POSTGRESS --------------
export class postgreSession extends serverSide {}

class postgreSQL extends serverInterface {
  sclass: typeof serverSide = postgreSession;
  client: Client;
  pgc: PGCache<sesh_db>;
  constructor(client: Client, config: sessionConfig, secret: string) {
    super(config, secret);
    this.client = client;

    this.pgc = new PGCache<sesh_db>(client, "sid", `SELECT * FROM session`);
  }
  async fetchSession(sid: string) {
    const prefs = this.config.KEY_PREFIX + sid;
    const itms = await this.pgc.get(prefs);
    let data = {};
    if (itms) {
      data = JSON.parse(itms.data);
    }
    return new this.sclass(sid, this.config.PERMANENT, data).session;
  }
  async saveSession(
    xsesh: serverSide,
    rsx?: any,
    deleteMe?: boolean,
    sameSite: string = "",
  ): Promise<void> {
    const prefs = this.config.KEY_PREFIX + xsesh.sid;
    if (!Object.entries(xsesh.data).length) {
      if (xsesh.modified || deleteMe) {
        if (rsx) {
          await this.client.query({
            text: `DELETE FROM session WHERE sid = $1`,
            values: [prefs],
          });

          await this.pgc.delete(prefs);
          const cookie = this.setCookie(xsesh, 0);
          rsx.header = { "Set-Cookie": cookie };
        }
      }
      return;
    }
    const life = this.config.LIFETIME;
    const data = JSON.stringify(xsesh.data);

    if (rsx) {
      const expre = this.getExpiration(this.config, xsesh);
      await this.client.query({
        text: `INSERT INTO session(sid, data, expiration) VALUES($1, $2, $3)`,
        values: [prefs, data, expre ? expre : null],
      });
      await this.pgc.set({
        sid: prefs,
        data: data,
        expiration: expre ?? "",
      });
      const cookie = this.setCookie(xsesh, timeDelta(life), sameSite);
      rsx.header = { "Set-Cookie": cookie };
    }
  }
}

export class reSession {
  config: sessionConfig;
  secret: string;
  app: InstanceType<typeof Brioche>;
  constructor(
    app: InstanceType<typeof Brioche>,
    config: sessionConfig | obj<any>,
    secret: string,
  ) {
    this.config = config as sessionConfig;
    this.secret = secret;
    this.app = app;
  }
  get(session: string) {
    if (session == "jwt") {
      return new cSession(this.config, this.secret, this.config.JWT_STORAGE);
    } else if (session == "postgres") {
      const CLIENT = this.app.postgresClient;
      if (CLIENT) {
        try {
          return new postgreSQL(CLIENT, this.config, this.secret);
        } catch (e) {}
      }
    }

    return new cSession(this.config, this.secret, this.config.STORAGE);
  }
}

export class JWT extends callBack {
  modified: boolean;
  sid: string;
  permanent: boolean;
  constructor(
    sid: string = "",
    permanent: boolean = false,
    initial: obj<string> = {},
  ) {
    super(initial);
    this.modified = false;
    this.sid = sid;
    this.permanent = permanent;
  }
  get jwt() {
    return new Proxy(this, this);
  }
}

export class _jwt extends sidGenerator {
  secret: string;
  salt: string;
  _xjwt = JWT;
  constructor(secret: string, salt = "salty_jwt") {
    super(secret);
    this.secret = secret;
    this.salt = salt;
  }
  sign(payload: obj<any>) {
    const options = {
      issuer: this.salt, // Issuer of the token
    };
    const datax = {
      data: payload,
    };
    return sign(datax, this.secret, options);
  }
  get random() {
    const options = {
      issuer: this.salt, // Issuer of the token
    };
    const datax = {
      data: hashedToken(),
    };
    return sign(datax, this.secret, options);
  }
  verify(
    payload: string,
    time?: {
      days?: number;
      hours?: number;
      minutes?: number;
      seconds?: number;
    },
  ): obj<string> | null {
    try {
      const ever = verify(payload, this.secret);
      if (ever) {
        const { data, iat, iss } = ever as any;
        if (iss == this.salt) {
          if (time) {
            const { days, hours, minutes, seconds } = time;
            let endD = new Date(iat * 1000);
            if (days) {
              endD = new Date(endD.setDate(endD.getDate() + days));
            } else if (hours) {
              endD = new Date(endD.setHours(endD.getHours() + hours));
            } else if (minutes) {
              endD = new Date(endD.setMinutes(endD.getMinutes() + minutes));
            } else if (seconds) {
              endD = new Date(endD.setSeconds(endD.getSeconds() + seconds));
            }
            if (endD.getTime() - Date.now() > 0) {
              return data as obj<string>;
            }
          } else {
            return data as obj<string>;
          }
        }
      }
    } catch (e) {}

    return null;
  }
  open(
    token: string,
    time?: {
      days?: number;
      hours?: number;
      minutes?: number;
      seconds?: number;
    },
  ): JWT {
    if (token) {
      const tv = this.verify(token, time);
      if (tv) {
        return new this._xjwt(token, true, tv).jwt;
      }
    }
    const rid = this.generate();
    return new this._xjwt(rid).jwt;
  }
  save(xjwts: JWT) {
    const data = xjwts.data;
    if ("access_token" in data) {
      delete data["access_token"];
    }
    return this.sign(data);
  }
}

export class timedJWT {
  _xjwt: _jwt | null = null;
  new(payload: obj<any>) {
    if (this._xjwt) {
      return this._xjwt.sign(payload);
    }
    return "";
  }
  open(
    token: string,
    time: {
      days?: number;
      hours?: number;
      minutes?: number;
      seconds?: number;
    } = { minutes: 15 },
  ): obj<string> | null {
    if (this._xjwt) {
      return this._xjwt.verify(token, time);
    }
    return null;
  }
}
