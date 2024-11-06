/// <reference path="./types.d.ts" />
import {
  file,
  write,
  serve,
  SocketAddress,
  Server,
  gzipSync,
  gunzipSync,
  BunFile,
} from "bun";
import { lookup } from "mime-types";
import { mkdirSync, readFileSync, statSync } from "node:fs";
import { Client } from "pg";
import {
  _jwt,
  cookieDump,
  Session,
  reSession,
  serverInterface,
  serverSide,
  timeDelta,
  JWT,
  timedJWT,
} from "./session";

/**
 * TODO:
 * 1. Router - Done!
 * 4. Session - Done!
 * 2. Response - ip
 * 3. Request - Done
 * 3a Form data and strings -- Done
 * 5. Websocket
 * 6. CSRF
 * 8. GOOGLE Aut
 * 9. Fix the byte-range request for files - Done∫
 */
/*
-------------------------
Start from the ground and utilize BUN.serve 
-------------------------
*/

// Types -----------------------

/*
-------------------------
MISC - STATICS
-------------------------
*/

export const { $$, is, get, __ } = (function () {
  const $$ = {
    set p(a: any) {
      if (Array.isArray(a)) {
        console.log(...a);
      } else {
        console.log(a);
      }
    },
    get o() {
      return {
        vals: Object.values,
        keys: Object.keys,
        items: Object.entries,
        has: Object.hasOwn,
        define: Object.defineProperty,
        ass: Object.assign,
      };
    },
    makeID(length: number) {
      let result = "";
      const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
      const nums = "0123456789";

      let counter = 0;
      while (counter < length) {
        let chars = characters + (counter == 0 ? "" : nums);
        const charactersLength = chars.length;
        result += chars.charAt(Math.floor(Math.random() * charactersLength));
        counter += 1;
      }
      return result;
    },
    parseURL(url: string) {
      const parsed: string[] = [];
      const args: string[] = [];

      let murl = url;
      let qurl = "";
      const splitd = url.match(/(?<=\?)[^/].*=?(?=\/|$)/g);
      if (splitd?.[0]) {
        qurl = splitd?.[0];
        murl = url.slice(0, url.indexOf(qurl) - 1);
      }

      const prsed = murl.match(/(?<=\/)[^/].*?(?=\/|$)/g) ?? ["/"];
      const query: obj<string> = {};

      prsed?.forEach((pr) => {
        if (pr.indexOf("<") >= 0) {
          const tgp = pr.match(/(?<=<)[^/].*?(?=>|$)/g);
          if (tgp?.length) {
            const [_type, _arg] = tgp[0].split(":");
            parsed.push(_type);
            args.push(_arg);
          }
        } else {
          parsed.push(pr);
        }
      });

      if (url.slice(-1) == "/" && url.length > 1) {
        parsed.push("/");
      }

      if (qurl) {
        const _qq = decodeURIComponent(qurl);
        const _qstr = _qq.split("&");
        _qstr.forEach((qs) => {
          const [ak, av] = qs.split(/\=(.*)/, 2);
          query[ak] = av;
        });
      }

      return { parsed, args, query };
    },
    strip(char: string, tostrip: string) {
      if (char.startsWith(tostrip)) {
        char = char.slice(1);
      }
      if (char.endsWith(tostrip)) {
        char = char.slice(0, -1);
      }
      return char;
    },
    attr(attr: obj<string>) {
      const _attr: string[] = [""];
      $$.o.items(attr).forEach(([k, v]) => {
        let to_attr: string = "";
        if (typeof v == "boolean") {
          to_attr = k;
        } else {
          to_attr = `${k}="${v}"`;
        }
        _attr.push(to_attr);
      });
      return _attr.join(" ");
    },
    headAttr(v?: headP) {
      const XHD: string[] = [];
      if (v) {
        $$.o.items(v).forEach(([kk, vv]) => {
          if (typeof vv == "string") {
            XHD.push(`<${kk}>${vv}</${kk}>`);
          } else if (Array.isArray(vv)) {
            const rdced = vv.reduce((prv, vl) => {
              let ender = "";
              if (kk == "script") {
                let scrptbdy = "";
                if ("importmap" in vl) {
                  vl["type"] = "importmap";
                  scrptbdy = JSON.stringify(vl.importmap);
                  delete vl.importmap;
                  //
                } else if ("body" in vl) {
                  scrptbdy = vl.body;
                  delete vl.body;
                }
                ender = `${scrptbdy}</${kk}>`;
              }
              prv.push(`<${kk}${$$.attr(vl)}>${ender}`);
              return prv;
            }, []);
            XHD.push(...rdced);
          }
        });
      }
      return XHD;
    },
    rbytes: new RegExp(/(\d+)(\d*)/, "m"),
  };
  const get = {
    byteRange(fsize: number, range: string) {
      let start = 0;
      let end = fsize - 1;
      const [partialStart, partialEnd] = range.replace(/bytes=/, "").split("-");
      //
      start = parseInt(partialStart, 10);
      end = partialEnd ? parseInt(partialEnd, 10) : end;

      return [start, end, fsize];
    },
    mimeType(fileStr: string) {
      return lookup(fileStr) || "application/octet-stream";
    },
    type(wrd: string, isFinal: boolean = false) {
      let lit_type: [any, string] | [] = [];
      if (is.number(wrd)) {
        const nm = wrd;
        if (Number.isInteger(nm)) {
          lit_type = [nm, "int"];
        } else {
          lit_type = [nm, "float"];
        }
      } else {
        if (isFinal && wrd.indexOf(".") >= 1) {
          lit_type = [wrd, "file"];
        } else {
          let tps = "-";
          if (wrd.length == 36) {
            const dashy = wrd.match(/\-/g);
            if (dashy && dashy.length == 4) {
              tps = "uuid";
            } else {
              tps = "string";
            }
          } else if (wrd != "/") {
            tps = "string";
          }
          lit_type = [wrd, tps];
        }
      }

      return lit_type;
    },
    args(params: string[], vals: string[]) {
      return params.reduce<obj<string>>((k, v, i) => {
        k[v] = vals[i];
        return k;
      }, {});
    },
  };
  const is = {
    dir(path: string) {
      try {
        return statSync(path).isDirectory();
      } catch (err) {
        mkdirSync(path);
        return true;
      }
    },
    file(path: string, data: string = "") {
      try {
        return file(path).exists();
      } catch (err) {
        write(path, data);
        return true;
      }
    },
    number(value: any) {
      return !isNaN(parseFloat(value)) && isFinite(value);
    },
    KV(val: object) {
      return typeof val === "object" && val !== null && !Array.isArray(val);
    },
    arrbuff(val: any) {
      return (
        val instanceof Uint8Array ||
        val instanceof ArrayBuffer ||
        typeof val == "string"
      );
    },
  };
  // private decorators
  // Include session here and other parts
  const __ = {
    readOnly(target: any, key: string) {
      $$.o.define(target, key, {
        writable: false,
        configurable: false,
      });
    },
  };

  return { $$, is, get, __ };
})();

/*
-------------------------
ESSENTIALS
-------------------------
*/
const wssClients: obj<obj<repsWSS>> = {};
export const { session, auth_bearer, jwt, jwt_refresh, wss } = (function () {
  function session(...itm: any[]) {
    const [a, b, c] = itm;

    const OG: () => any = c.value;

    c.value = async function (args: any = {}) {
      if ("session" in args && args.session) {
        const nms: any = [args];
        return OG.apply(this, nms);
      }
      return null;
    };
    return c;
  }
  function jwt(...itm: any[]) {
    const [a, b, c] = itm;
    const OG: () => any = c.value;
    c.value = async function (args: any = {}) {
      if ("jwt" in args) {
        const nms: any = [args];
        return OG.apply(this, nms);
      }
      return null;
    };
    return c;
  }
  function jwt_refresh(...itm: any[]) {
    const [a, b, c] = itm;
    const OG: () => any = c.value;
    c.value = async function (args: any = {}) {
      if ("jwt_refresh" in args) {
        const nms: any = [args];
        return OG.apply(this, nms);
      }
      return null;
    };
    return c;
  }
  class wss {
    session = new Session().session;
    socket: null | WebSocket;
    // request = new request("", "", {}, "");
    data: obj<V> = {};
    wid: string = "";
    wssURL: string = "";
    role: "maker" | "joiner" | "alien" = "joiner";
    constructor(...args: any[]) {
      this.socket = null;
    }
    async init(...args: any[]) {}
    async onConnect(message?: string) {
      this.send = "connected!";
    }
    async onMessage(message?: string) {}
    async onClose(message?: string) {}
    set send(message: string | object) {
      if (this.socket) {
        if (typeof message == "object") {
          this.socket.send(JSON.stringify(message));
        } else {
          this.socket.send(message);
        }
      }
    }
    set broadcast(message: string | object) {
      if (this.socket) {
        let mess: string = "";
        if (typeof message == "object") {
          mess = JSON.stringify(message);
        } else {
          mess = message;
        }
        $$.o.items(wssClients[this.wssURL]).forEach(([mid, wsx]) => {
          wsx.WSS.onMessage(mess);
        });
      }
    }
    get close() {
      if (this.socket) this.socket.close();
      return;
    }
  }
  return { session, auth_bearer: jwt, jwt, jwt_refresh, wss };
})();

export const { Brioche, response, fsyt } = (function () {
  //

  class _r {
    _headattr: obj<string[]> = {};
    lang: string = "en";
    get head() {
      return this._headattr;
    }
    set head(heads: headP) {
      $$.o.items(heads).forEach(([k, v]) => {
        if (k == "title" || k == "base") {
          this._headattr[k] = v;
        } else {
          if (!(k in this._headattr)) {
            this._headattr[k] = v;
          } else {
            this._headattr[k].push(...v);
          }
        }
      });
    }
  }
  class response extends _r {
    status?: number;
    session!: serverSide;
    request!: request;
    jwt!: serverSide;
    timedJWT = new timedJWT();
    headers: obj<string> = {};
    async get?(...args: any[]): Promise<any>;
    async post?(...args: any[]): Promise<object>;
    async put?(...args: any[]): Promise<any>;
    async patch?(...args: any[]): Promise<any>;
    async error?(...args: any[]): Promise<any>;
    async eventStream?(...args: any[]): Promise<any>;
    /*
                -------------------------
                TODO
                implement
                * head
                * httpheader
                * setCookie
                * deleteCookie
                * get wssClients
                -------------------------
                */
    set header(head: obj<string>) {
      $$.o.ass(this.headers, head);
    }
    get header() {
      return this.headers;
    }
    set type(content: string) {
      this.header = { "Content-Type": content };
    }
    setCookie({
      key,
      val,
      path = "/",
      days = 31,
      httpOnly = false,
    }: {
      key: string;
      val: string;
      path?: string;
      days?: number;
      httpOnly?: boolean;
    }) {
      const cd = cookieDump(key, val, {
        expires: timeDelta(days),
        path: path,
        httpOnly: httpOnly,
        sameSite: "Strict",
      });
      this.header = { "Set-Cookie": cd };
    }
    deleteCookie(key: string) {
      this.setCookie({ key: key, val: "", days: 0 });
    }
    get wssClients() {
      return $$.o.keys(wssClients);
    }
  }
  class request {
    __form?: FormData;
    url: URL;
    path: string;
    method: string;
    headers?: Headers;
    ip?: SocketAddress;
    query: obj<string> = {};
    cookies: obj<string> = {};
    urlEncoded: obj<string> = {};
    auth: string = "";
    parsed: string[];
    contentType?: string;
    constructor({
      url,
      method,
      headers,
      ip,
    }: {
      url: string;
      method: string;
      headers?: Headers;
      ip?: SocketAddress;
    }) {
      $$.o.ass(this, { headers, ip });
      this.method = method?.toLowerCase();
      this.url = new URL(url);
      this.path = this.url.pathname;
      const { parsed, query } = $$.parseURL(this.path + this.url.search);
      this.parsed = parsed;
      this.query = query;
      this.__proc;
    }
    get boundary() {
      const ctype = this.contentType;
      if (ctype) {
        if (ctype.indexOf("multipart/form-data") >= 0) {
          const tail = ctype.split(";", 2)[1];
          return tail.trim().split("=")[1];
        }
      }
      return null;
    }
    get isForm() {
      const ctype = this.contentType;
      return ctype
        ? ctype.indexOf("multipart/form-data") >= 0 ||
            ctype.indexOf("x-www-form-urlencoded") >= 0
        : false;
    }
    get __proc() {
      const headers = this.headers;
      if (headers) {
        const cookie = headers.get("cookie");
        if (cookie) {
          cookie.split(";").forEach((d) => {
            const [key, val] = d.trim().split(/=(.*)/s);
            this.cookies[key] = val;
          });
        }
        const auth = headers.get("authorization");
        if (auth) {
          const [bear, token] = auth.split(" ", 2);
          if (bear.trim() == "Bearer") {
            this.auth = token.trim();
          }
        }
        const ct = headers.get("content-type");
        if (ct) {
          this.contentType = ct;
        }
      }

      return;
    }
    set form(frm: FormData) {
      this.__form = frm;
    }
    get form() {
      if (this.__form) {
        return this.__form;
      }
      return new FormData();
    }
  }

  const Routes: obj<any> = {};
  const FRoutes: obj<any> = {};
  const WRoutes: obj<any> = {};
  const ZFolders: obj<any> = {};

  class fsyt {
    rpath: string;
    data: string;
    constructor(rpath: string, data: any = {}) {
      this.rpath = rpath;
      this.data = JSON.stringify(data);
    }
    _head() {
      let fs = `<script type="module">`;
      fs += `\nimport x from "${this.rpath}";`;
      fs += `\nx.dom(${this.data});`;
      fs += `\n</script>`;
      return fs;
    }
  }
  class htmlx {
    heads: string[];
    lang: string;
    constructor(head: headP, lang: string) {
      this.heads = this._head([head]);
      this.lang = lang;
    }
    _head(heads: headP[]) {
      const [_h1] = heads;
      return [...$$.headAttr(_h1)];
    }
    html(ctx: string | fsyt | any = ""): string {
      let bscr = "";
      let _ctx = "";
      if (ctx instanceof fsyt) {
        bscr = ctx._head();
      } else {
        _ctx = ctx;
      }
      const _id = $$.makeID(5);
      let fin = "<!DOCTYPE html>";
      fin += `\n<html lang="${this.lang}">`;
      fin += "\n<head>\n";
      fin += this.heads.join("\n") + "\n";
      fin += bscr + "\n";
      fin += "</head>";
      fin += `\n<body id="${_id}">`;
      _ctx && (fin += _ctx);
      fin += "</body>";
      fin += "\n</html>";
      return fin;
    }
  }
  class Xurl {
    Furl: Yurl | undefined;
    status: number;
    headers: obj<string> = {};
    constructor({
      furl,
      status = 404,
      headers = {},
    }: {
      furl?: Yurl;
      status?: number;
      headers?: obj<string>;
    }) {
      this.Furl = furl;
      this.status = status;
      if (headers) {
        $$.o.ass(this.headers, headers);
      }
    }
    set header(head: obj<string>) {
      $$.o.ass(this.headers, head);
    }
    set type(content: string) {
      this.header = { "Content-Type": content };
    }
    async __reqs(app: Brioche, req: request) {
      let sid = "";
      let jwtv = "";
      let refreshjwt: any | null = null;
      if ("session" in req.cookies) {
        sid = req.cookies.session;
      }
      if (req.auth) {
        jwtv = req.auth;
      }
      if ("refresh_token" in req.urlEncoded) {
        refreshjwt = await app.jwtsession.openSession(
          req.urlEncoded.refresh_token,
        );
      }

      return { sid, jwtv, refreshjwt };
    }
    __RSP(bytes: Uint8Array | BunFile) {
      return new Response(
        is.arrbuff(bytes) ? gzip(bytes, this.headers) : bytes,
        {
          headers: this.headers,
          status: this.status,
        },
      );
    }
    __RNG(
      bytes: Uint8Array | BunFile,
      start: number,
      end: number,
      size: number,
    ) {
      this.header = {
        "Content-Range": `bytes ${start}-${end}/${size}`,
        "Content-Length": size.toString(),
      };
      return new Response(bytes, {
        headers: this.headers,
        status: 206,
      });
    }
    __CTX(CTX: any, head: headP, lang: string): string | Response | undefined {
      // If the CTX is instanceof JWT, then send the refresh and id

      if (CTX instanceof Xurl) {
        const { status, headers } = CTX;
        return new Response("", { status, headers });
      } else if (CTX instanceof Response) {
        return CTX;
      } else if (!(CTX instanceof fsyt) && is.KV(CTX)) {
        this.header = { "Content-Type": "application/json" };
        const { status, headers } = this;
        return new Response(gzip(JSON.stringify(CTX), this.headers), {
          status,
          headers,
        });
      } else {
        this.header = { "Content-Type": "text/html" };
        return new htmlx(head, lang).html(CTX);
      }
    }
    async __file(range?: string | null) {
      const { url, bytes, fileType } = this.Furl!;
      if (bytes) {
        this.type = fileType;
        this.header = { "Cache-Control": "max-age=31536000" };
        if (range) {
          const [_s, _e, _z] = get.byteRange(bytes.byteLength, range);
          return this.__RNG(bytes.slice(_s, _e + 1), _s, _e, _z);
        } else {
          return this.__RSP(bytes);
        }
      } else {
        const fl = file(url);
        if (await fl.exists()) {
          this.type = fileType;
          this.header = { "Cache-Control": "max-age=31536000" };
          if (range) {
            const [_s, _e, _z] = get.byteRange(fl.size, range);
            return this.__RNG(fl.slice(_s, _e + 1), _s, _e, _z);
          } else {
            const isMedia = fileType.startsWith("video/");
            return this.__RSP(isMedia ? fl : await fl.bytes());
          }
        } else {
          $$.p = url + " file not found";
        }
      }

      return new Response("", {
        status: 404,
      });
    }
    async response(
      req: request,
      app: Brioche,
    ): Promise<string | void | Response> {
      const { method } = req;
      if (this.Furl) {
        const { _class, isFile, args, x_args, withSession } = this.Furl;
        if (isFile) {
          //
          const rnge = req.headers?.get("range");
          return await this.__file(rnge);
        } else if (_class) {
          //
          const FS: any = new _class();

          if (typeof FS[method] == "function") {
            const z_args = get.args(args, x_args);
            const { sid, jwtv, refreshjwt } = await this.__reqs(app, req);
            const a_args: obj<boolean> = {};
            const sjwt = app._jwt.open(jwtv, { minutes: 30 });
            const sesh = await app.XS.openSession(sid);

            FS.timedJWT._xjwt = app._jwt;
            // only get the session if needed?

            if (!sjwt.new) {
              a_args["jwt"] = true;
              a_args["jwt_refresh"] = true;
            }
            if (sesh && !sesh.new) {
              a_args["session"] = true;
            }
            if ($$.o.keys(a_args).length) {
              Object.assign(z_args, a_args);
            }

            FS.head = app.head;

            Object.assign(FS, {
              request: req,
              session: sesh,
              jwt: sjwt,
            });

            const CTX = await FS[method](z_args);

            this.header = FS.header;

            if (FS.status) this.status = FS.status;

            if (FS.session) {
              if (FS.session.modified) {
                await app.XS.saveSession(FS.session, this, false, FS.sameSite);
              } else if (sesh && sid && sesh.new) {
                app.XS.deleteBrowserSession(FS.session, this);
              }
            }
            const { head, lang } = FS;
            if (CTX) return this.__CTX(CTX, head, lang);
            else {
              // Nulls -- how to determine
              this.status = 401;
              return;
            }
          } else {
            // Method not allowed
            this.status = 405;
            return;
          }
        }
      }
      return;
    }
  }
  class Yurl {
    _class: typeof response | null;
    url: string;
    parsedURL: string[];
    args: string[] = [];
    x_args: string[] = [];
    isFile: boolean;
    withSession: boolean = false;
    fileType: string = "text/plain";
    bytes?: Uint8Array;
    preload: boolean = false;
    constructor({
      url,
      _class = null,
      isFile = false,
      withSession = false,
      preload = false,
    }: {
      url: string;
      _class?: typeof response | null;
      isFile?: boolean;
      withSession?: boolean;
      preload?: boolean;
    }) {
      const { parsed, args } = $$.parseURL(url);
      this.url = url;
      //
      this.parsedURL = parsed;
      this.args = args;
      this._class = _class;
      this.isFile = isFile;
      if (isFile) {
        this.preload = preload;
        this.withSession = withSession;
        this.fileType = get.mimeType(url);
      }
    }

    loadbytes() {
      if (this.preload) {
        file(this.url)
          .bytes()
          .then((e) => {
            this.bytes = e;
          })
          .catch((e) => {
            throw `error: can't preload ${this.url}. File not found.`;
          });
      }
    }
  }
  class Zurl {
    id: string;
    constructor({ id }: { id: string }) {
      this.id = id;
      __.readOnly(this, "id");
    }
    set z(yurl: Yurl) {
      let RT = yurl.isFile ? FRoutes : Routes;
      const RID = this.id;
      yurl.parsedURL.forEach((v, i) => {
        if (!(v in RT)) {
          RT[v] = {};
        }
        RT = RT[v];
        if (yurl.parsedURL.length - 1 == i) {
          if (!(RID in RT)) {
            yurl.loadbytes();
            RT[RID] = yurl;
          } else {
            if (!yurl.isFile) {
              throw `URL: ${yurl.url} already used in class < ${RT[RID]._class.name} >`;
            }
          }
        }
      });
    }
    set wss(yurl: Yurl) {}
    folder(path: string, option = {}) {
      path = $$.strip(path, ".");
      path = $$.strip(path, "/");
      if (!(path in ZFolders)) {
        ZFolders[path] = option;
      }
    }
    get({
      parsed,
      wss = false,
      path,
    }: {
      parsed: string[];
      wss?: boolean;
      path?: string;
    }) {
      let isFile: boolean = false;

      let ppop = parsed.slice().pop();
      if (ppop) isFile = get.type(ppop, true).pop() == "file";

      const lenn = parsed.length;
      const args: string[] = [];
      let routeUpdate: number = 0;
      let RT = isFile ? FRoutes : Routes;

      if (wss) {
        RT = WRoutes;
      }
      parsed.forEach((v, i) => {
        const TP = get.type(v, lenn - 1 == i ? true : false);
        for (let i = 0; i < TP.length; i++) {
          let TPX = TP[i];
          if (TPX in RT) {
            RT = RT[TPX];
            routeUpdate += 1;
            break;
          } else {
            if (TPX != "/" && TPX != "-") {
              args.push(TPX);
            }
          }
        }
      });

      if (routeUpdate != lenn) {
        RT = {};
      }

      if (this.id in RT) {
        const RTT: Yurl = RT[this.id];
        RTT.x_args = args;
        return new Xurl({ furl: RTT, status: 200 });
      }
      if (isFile) {
        const pp = parsed.slice(0, -1).join("/");
        let fses = false;

        const inFolder = $$.o.items(ZFolders).some(([ff, vv]) => {
          fses = vv.session ?? false;
          return pp.startsWith(ff);
        });

        if (inFolder) {
          return new Xurl({
            furl: new Yurl({
              url: `.${path}`,
              isFile: true,
              withSession: fses,
            }),
            status: 200,
          });
        }
      }
      return new Xurl({});
    }
  }

  const Z = new Zurl({ id: $$.makeID(15) });
  //

  function gzip(ctx: Uint8Array | string | ArrayBuffer, headers: obj<string>) {
    const buffd = gzipSync(ctx);
    $$.o.ass(headers, {
      "Content-Length": buffd.byteLength,
      "Content-Encoding": "gzip",
    });

    return buffd;
  }

  class _B extends _r {
    dir = "./";
    XS: InstanceType<typeof serverInterface>;
    secret_key = $$.makeID(15);
    constructor(dir: string, env_path?: string) {
      super();
      this.dir = "./" + dir.split("/").slice(-1)[0];
      //
      const PRIV = dir + "/private";
      if (!env_path) {
        is.dir(PRIV);
        is.file(PRIV + ".env");
      }

      require("dotenv").config({
        path: (env_path ? env_path : PRIV) + "/.env",
      });

      const sk = process.env.SECRET;
      if (sk) this.secret_key = sk;
      //
      __.readOnly(this, "secret_key");
      __.readOnly(this, "dir");

      this.session.STORAGE = PRIV + "/.sessions";
      this.session.JWT_STORAGE = PRIV + "/.jwtsessions";
      this.XS = new reSession(this as any, this.session, this.secret_key).get(
        this.session.INTERFACE,
      );
    }
    init() {
      if (this.postgresClient) {
        this.sessionInterface = "postgres";
      }

      this.XS = new reSession(this as any, this.session, this.secret_key).get(
        this.session.INTERFACE,
      );
    }
    config = {
      APPLICATION_ROOT: "/",
    };
    session = {
      COOKIE_NAME: "session",
      COOKIE_DOMAIN: "127.0.0.1",
      COOKIE_PATH: null,
      COOKIE_HTTPONLY: true,
      COOKIE_SECURE: true,
      REFRESH_EACH_REQUEST: false,
      COOKIE_SAMESITE: "Strict",
      KEY_PREFIX: "session:",
      PERMANENT: true,
      USE_SIGNER: false,
      ID_LENGTH: 32,
      FILE_THRESHOLD: 500,
      LIFETIME: 31,
      MAX_COOKIE_SIZE: 4093,
      INTERFACE: "fs",
      STORAGE: ".sessions",
      JWT_STORAGE: ".jwtsessions",
    };
    postgresClient: Client | null = null;
    google = {
      id: "",
      secret: "",
    };
    set sessionInterface(intrfce: "supabase" | "postgres") {
      this.session.INTERFACE = intrfce;
    }
    get jwtsession() {
      return new reSession(this as any, this.session, this.secret_key).get(
        "jwt",
      );
    }
    ip = {
      LIMIT: false,
      RATE: 100,
      SECONDS: 60,
    };
  }

  class Brioche extends _B {
    _jwt: _jwt;
    constructor(dir: string, env_path?: string) {
      super(dir, env_path);
      this._jwt = new _jwt(this.secret_key);

      this.folder(this.dir);
      this.file("./fsyt.js", { preload: true });
    }
    //
    file(
      furl: string,
      option: { session?: boolean; preload?: boolean } = {
        session: false,
        preload: false,
      },
    ) {
      Z.z = new Yurl({
        url: furl,
        isFile: true,
        withSession: option.session,
        preload: option.preload,
      });
      return furl;
    }
    folder(
      path: string,
      option: { session?: boolean } = {
        session: false,
      },
    ) {
      Z.folder(path, option);
    }
    folders(...paths: string[]) {
      paths.forEach((pt) => {
        Z.folder(pt);
      });
    }
    /**
     *
     * string | int | float | uuid
     *
     * /url/\<string:param>
     */
    url(url: string) {
      return <T extends InstanceType<typeof response>>(
        f: new () => T,
      ): new () => T => {
        // Process here
        Z.z = new Yurl({ url: url, _class: f });

        return f;
      };
    }
    redirect(url: string) {
      return new Xurl({ status: 302, headers: { Location: url } });
    }

    async __data(ctx: string | void | Response, _Z: Xurl) {
      const { status, headers } = _Z;
      if (ctx) {
        if (ctx instanceof Response) {
          return ctx;
        } else if (typeof ctx !== "object") {
          return new Response(gzip(ctx, headers), {
            status,
            headers,
          });
        }
      }
      return new Response("", { status, headers });
    }
    async render(req: request, srv?: Server): Promise<Response> {
      const _Z = Z.get({ parsed: req.parsed, path: req.path });
      const ctx = await _Z.response(req, this);
      const _CC = await this.__data(ctx, _Z);
      if (!srv) {
        write("index.html", gunzipSync(await _CC.arrayBuffer()));
      }
      return _CC;
    }
    async serve({
      url = "",
      method = "GET",
      hostname = "localhost",
      port = 3000,
      options = {},
    }) {
      //
      this.init();
      const RN = this;
      if (url) {
        const Request = new request({
          url: `http://${hostname}:${port}${url}`,
          method,
        });
        //

        await RN.render(Request);
      } else {
        const sk = process.env.SSL_KEY;
        const sc = process.env.SSL_CERT;
        //
        if (sk && sc) {
          serve({
            key: file(sk),
            cert: file(sc),
            async fetch(req, server) {
              //
              const ip = server.requestIP(req) ?? undefined;
              const { url, method, headers } = req;

              const Request = new request({
                url,
                method,
                headers,
                ip,
              });

              if (Request.isForm) {
                Request.form = await req.formData();
              }

              return await RN.render(Request, server);
            },
          });
        }
      }
    }
  }

  return { Brioche, response, fsyt };
})();

// Single query --
export class PGCache<T extends bs> {
  client: Client;
  query: string;
  f_timed: number;
  data: Map<any, T>;
  key: string;
  constructor(client: Client, key: string, query: string) {
    this.query = query;
    this.key = key;
    this.f_timed = Date.now();
    this.data = new Map();
    this.client = client;
  }
  async init(val: string): Promise<T | null> {
    const TQ = await this.client.query({
      text: this.query + ` where ${this.key} = $1`,
      values: [val],
    });
    // Delete keys with no value
    for (const [k, v] of this.data) {
      if (!v) {
        this.data.delete(k);
      }
    }
    if (TQ.rowCount) {
      const tr = TQ.rows[0];
      tr.f_timed = Date.now();
      this.data.set(val, tr);
      return tr;
    } else {
      this.data.set(val, null as any);
      return null;
    }
  }
  async checkLast(time: number) {
    const xl = new Date(time);
    xl.setMinutes(xl.getMinutes() + 15);
    if (xl.getTime() < Date.now()) {
      return true;
    }
    return false;
  }
  async get(val: string | undefined): Promise<T | null> {
    if (val) {
      const hdat = this.data.get(val);
      if (hdat == undefined) {
        return await this.init(val);
      } else {
        if (hdat && "f_timed" in hdat) {
          const atv = await this.checkLast(hdat.f_timed!);
          if (atv) {
            return await this.init(val);
          }
        }
        return hdat;
      }
    }
    return null;
  }
  async set(data: T) {
    if (this.key in data) {
      data.f_timed = Date.now();
      this.data.set(data[this.key], data);
    }
  }
  async delete(key: string) {
    this.data.delete(key);
  }
}

// json files
export class ForFS<T extends fs> {
  fs: string;
  f_timed: number;
  data: Map<any, T>;
  key: string;
  dir: string;
  constructor({ dir, fs, key }: { dir: string; fs: string; key: string }) {
    this.dir = dir + "/ffs";
    this.key = key;
    this.f_timed = Date.now();
    this.data = new Map();
    this.fs = this.dir + `/${fs}.json`;
    if (is.dir(this.dir) && is.file(this.fs, "{}")) {
      const frr = readFileSync(this.fs);
      if (frr) {
        const FJSON = JSON.parse(frr.toString());
        this.data = new Map($$.o.items(FJSON));
      }
    }
  }
  async get(val: string | undefined): Promise<T | null> {
    const hdat = this.data.get(val);
    if (hdat) return hdat;
    return null;
  }
  async set(data: T) {
    if (this.key in data) {
      const frr = await file(this.fs).text();
      if (frr) {
        const FJSON = JSON.parse(frr);
        const dtk = data[this.key] as string;
        FJSON[dtk] = data;
        await write(this.fs, JSON.stringify(FJSON));
      }
      this.data.set(data[this.key], data);
    }
  }
  async delete(key: string) {
    if (await this.get(key)) {
      const frr = await file(this.fs).text();
      if (frr) {
        const FJSON = JSON.parse(frr.toString());
        if (key in FJSON) {
          delete FJSON[key];
          await write(this.fs, JSON.stringify(FJSON));
        }
        this.data.delete(key);
      }
    }
  }
  async json() {
    const fraw = await file(this.fs).text();
    const JPR = JSON.parse(fraw);
    return $$.o.vals(JPR);
  }
}
