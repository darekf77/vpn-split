//#region imports
import {
  _,
  path,
  fse,
  http,
  https,
  isElevated,
  crossPlatformPath,
  os,
} from 'tnp-core';
import * as express from 'express';
import * as httpProxy from 'http-proxy';
import { Helpers } from 'tnp-helpers/src';
import { config, HOST_FILE_PATH } from 'tnp-config/src';
import { URL } from 'url';
import { Hostile } from './hostile.backend';
import { EtcHosts, HostForServer, OptHostForServer } from './models';
import axios from 'axios';
import { Log, Level } from 'ng2-logger/src';
import * as crypto from 'crypto';
const log = Log.create('vpn-split', Level.INFO);
//#endregion

//#region consts

const GENERATED = '#GENERATED_BY_CLI#';

const EOL = process.platform === 'win32' ? '\r\n' : '\n';

const SERVERS_PATH = '/$$$$servers$$$$';

const HOST_FILE_PATHUSER = crossPlatformPath([
  os.userInfo().homedir,
  'hosts-file__vpn-split',
]);

const from = HostForServer.From;
const defaultHosts = {
  'localhost alias': from({
    ipOrDomain: '127.0.0.1',
    aliases: 'localhost' as any,
    isDefault: true,
  } as OptHostForServer),
  broadcasthost: from({
    ipOrDomain: '255.255.255.255',
    aliases: 'broadcasthost' as any,
    isDefault: true,
  } as OptHostForServer),
  'localhost alias ipv6': from({
    ipOrDomain: '::1',
    aliases: 'localhost' as any,
    isDefault: true,
  } as OptHostForServer),
} as EtcHosts;
//#endregion

export class VpnSplit {
  //#region getters
  get hostsArr() {
    const hosts = this.hosts;
    return _.keys(hosts).map(hostName => {
      const v = hosts[hostName] as HostForServer;
      v.name = hostName;
      return v;
    });
  }
  get hostsArrWithoutDefault() {
    return this.hostsArr.filter(f => !f.isDefault);
  }

  private get serveKeyName() {
    return 'tmp-' + config.file.server_key;
  }
  private get serveKeyPath() {
    return path.join(this.cwd, this.serveKeyName);
  }
  private get serveCertName() {
    return 'tmp-' + config.file.server_cert;
  }
  private get serveCertPath() {
    return path.join(this.cwd, this.serveCertName);
  }
  private get serveCertChainName() {
    return 'tmp-' + config.file.server_chain_cert;
  }
  private get serveCertChainPath() {
    return path.join(this.cwd, this.serveCertChainName);
  }
  //#endregion

  //#region fields
  private readonly __hostile: Hostile;
  //#endregion

  //#region singleton
  private static _instances = {};
  private constructor(
    private portsToPass: number[],
    private hosts: EtcHosts,
    private cwd: string,
  ) {
    this.__hostile = new Hostile();
  }
  public static async Instance({
    ports = [80, 443, 4443, 22, 2222, 8180, 8080, 4407, 7999],
    additionalDefaultHosts = {},
    cwd = process.cwd(),
    allowNotSudo = false,
  }: {
    ports?: number[];
    additionalDefaultHosts?: EtcHosts;
    cwd?: string;
    allowNotSudo?: boolean;
  } = {}) {
    // console.log('ports', ports)
    // console.log({
    //   allowNotSudo
    // })

    if (!(await isElevated()) && !allowNotSudo) {
      Helpers.error(
        `[vpn-split] Please run this program as sudo (or admin on windows)`,
        false,
        true,
      );
    }

    if (!VpnSplit._instances[cwd]) {
      VpnSplit._instances[cwd] = new VpnSplit(
        ports,
        _.merge(defaultHosts, additionalDefaultHosts),
        cwd,
      );
    }
    return VpnSplit._instances[cwd] as VpnSplit;
  }
  //#endregion

  //#region start server
  async startServer(saveHostInUserFolder = false) {
    this.createCertificateIfNotExists();
    //#region modify /etc/host 80,443 to redirect to proper server domain/ip
    saveHosts(this.hosts, { saveHostInUserFolder });
    //#endregion
    for (let index = 0; index < this.portsToPass.length; index++) {
      const portToPassthrough = this.portsToPass[index];
      await this.serverPassthrough(portToPassthrough as any);
    }
    Helpers.info(`Activated.`);
  }
  //#endregion

  //#region apply hosts
  public applyHosts(hosts: EtcHosts) {
    // console.log(hosts);
    saveHosts(hosts);
  }
  //#endregion

  //#region start client
  public async startClient(
    vpnServerTargets: URL[] | URL,
    saveHostInUserFolder = false,
  ) {
    if (!Array.isArray(vpnServerTargets)) {
      vpnServerTargets = [vpnServerTargets];
    }
    for (const vpnServerTarget of vpnServerTargets) {
      this.preventBadTargetForClient(vpnServerTarget);
    }

    this.createCertificateIfNotExists();
    //#region modfy clien 80, 443 to local ip of server
    const hosts = [];
    for (const vpnServerTarget of vpnServerTargets) {
      const newHosts = await this.getRemoteHosts(vpnServerTarget);
      for (const host of newHosts) {
        host.originHostname = vpnServerTarget.hostname;
        // console.log('host.originHostname' + host.originHostname)
        hosts.push(host);
      }
    }
    // console.log(hosts);
    // process.exit(0)
    const originalHosts = this.hostsArr;
    const cloned = _.values(
      [
        ...originalHosts,
        ...hosts.map(h =>
          HostForServer.From(
            {
              aliases: h.alias as any,
              ipOrDomain: h.ip,
              originHostname: h.originHostname,
            },
            `external host ${h.alias} ${h.ip}`,
          ),
        ),
      ]
        .map(c => {
          let copy = c.clone();
          if (!copy.isDefault) {
            copy.ip = `127.0.0.1`;
          }
          // copy = HostForServer.From(copy);
          // console.log('cloned host.originHostname' + copy.originHostname)
          return copy;
        })
        .reduce((prev, curr) => {
          return _.merge(prev, {
            [curr.aliases.join(' ')]: curr,
          });
        }, {}),
    ) as any;

    saveHosts(cloned, { saveHostInUserFolder });
    //#endregion
    // console.log((cloned as HostForServer[]))
    // process.exit(0)
    for (const portToPassthrough of this.portsToPass) {
      await this.clientPassthrough(portToPassthrough, vpnServerTargets, cloned);
    }
    Helpers.info(`Client activated`);
  }
  //#endregion

  //#region private methods / get remote hosts
  private async getRemoteHosts(vpnServerTarget: URL) {
    try {
      const url = `http://${vpnServerTarget.hostname}${SERVERS_PATH}`;
      const response = (await axios({
        url,
        method: 'GET',
      })) as any;
      return response.data as {
        ip: string;
        alias: string;
        originHostname: string;
      }[];
    } catch (err) {
      Helpers.error(
        `Remote server: ${vpnServerTarget.hostname} maybe inactive...` +
          ` nothing to passthrought `,
        true,
        true,
      );
      return [];
    }
  }
  //#endregion

  //#region private methods / create certificate
  private createCertificateIfNotExists() {
    if (
      !Helpers.exists(this.serveKeyPath) ||
      !Helpers.exists(this.serveCertPath)
    ) {
      Helpers.info(
        `[vpn-split] Generating new certification for localhost... please follow instructions..`,
      );
      const commandGen = `openssl req -nodes -new -x509 -keyout ${this.serveKeyName} -out ${this.serveCertName}`;
      Helpers.run(commandGen, { cwd: this.cwd, output: true }).sync();

      // Helpers.run(`openssl verify -verbose -x509_strict -CAfile ${this.serveKeyName} ${this.serveCertChainName}`,
      //   { cwd: this.cwd, output: true }).sync()
    }
  }
  //#endregion

  //#region private methods / proxy passthrough

  getTarget({
    req,
    res,
    port,
    hostname,
  }: {
    req: express.Request;
    res: express.Response;
    port: number;
    hostname: string;
  }): string {
    // console.log(`protocol="${req.protocol}", hostname="${hostname}", port="${port}"`)
    return `${req.protocol}://${hostname}:${port}`;
  }

  getProxyConfig({
    req,
    res,
    port,
    hostname,
    isHttps,
  }: {
    req: express.Request;
    res: express.Response;
    port: number;
    hostname?: string;
    isHttps: boolean;
  }): httpProxy.ServerOptions {
    const serverPassthrough = !!hostname;
    const target = this.getTarget({
      req,
      res,
      port,
      hostname: serverPassthrough ? hostname : req.hostname,
    });
    // console.log(`[target] [${serverPassthrough ? 'server' : 'client'}] target="${target}", hostname="${hostname}",`
    // +` protocol="${req.protocol}", ip="${req.ip}", origin="${req.originalUrl}"`)
    return isHttps
      ? {
          target,
          ssl: {
            key: fse.readFileSync(this.serveKeyPath),
            cert: fse.readFileSync(this.serveCertPath),
          },
          agent: new https.Agent({
            // for self signed you could also add
            // rejectUnauthorized: false,
            // allow legacy server
            secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
          }),
          secure: false,
          // followRedirects: true,
          // changeOrigin: true,
        }
      : ({
          target,
        } as httpProxy.ServerOptions);
  }

  private getGetRequestInfo(
    req: express.Request,
    res: express.Response,
    port: number,
    type: 'client' | 'server',
  ): string {
    return `server passthrough type: ${type}
protocol: ${req.protocol} <br>
hostname: ${req.hostname} <br>
originalUrl: ${req.originalUrl} <br>
req.method ${req.method} <br>
port: ${port} <br>
SERVERS_PATH ${SERVERS_PATH} <br>`;
  }

  getNotFoundMsg(
    req: express.Request,
    res: express.Response,
    port: number,
    type: 'client' | 'server',
  ): string {
    return `[vpn-split] You are requesting url that is not in proxy reach ${type}
${this.getGetRequestInfo(req, res, port, type)}
    `;
  }

  getMaybeChangeOriginTrueMs(
    req: express.Request,
    res: express.Response,
    port: number,
    type: 'client' | 'server',
  ): string {
    return `[vpn-split] maybe changeOrigin: true, in your porxy config ?
${this.getGetRequestInfo(req, res, port, type)}
    `;
  }

  get headersToRemove() {
    return [
      // 'Strict-Transport-Security',
      // 'upgrade-insecure-requests',
      // 'Content-Security-Policy',
      // 'Upgrade-Insecure-Requests',
      // 'content-security-policy',
    ];
  }

  filterHeaders(
    req: http.IncomingMessage & express.Request,
    res: http.ServerResponse & express.Response,
  ): void {
    this.headersToRemove.forEach(headerName => {
      delete req.headers[headerName];
      res.setHeader(headerName, '');
    });
  }

  private isHttpsPort(port: number): boolean {
    const httpPorts = [
      443, 4443,
      // 2222,
      // 22,
    ];
    port = Number(port);
    return httpPorts.includes(port);
  }

  //#region start server passthrough
  private async serverPassthrough(portToPassthrough: number): Promise<void> {
    const isHttps = this.isHttpsPort(portToPassthrough);
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    const app = express();
    const proxy = httpProxy.createProxyServer({});
    const currentLocalIps = [
      'localhost',
      '127.0.0.1',
      // '0.0.0.0',
      ...Helpers.allLocalIpAddresses().map(a => a.hostname),
    ];

    // console.log({ currentLocalIps });

    app.use(
      (
        req: http.IncomingMessage & express.Request,
        res: http.ServerResponse & express.Response,
        next,
      ) => {
        this.filterHeaders(req, res);

        if (currentLocalIps.includes(req.hostname)) {
          if (req.method === 'GET' && req.originalUrl === SERVERS_PATH) {
            res.send(
              JSON.stringify(
                this.hostsArrWithoutDefault.map(h => {
                  return {
                    ip: h.ip,
                    alias: Helpers.arrays.from(h.aliases).join(' '),
                  };
                }),
              ),
            );
          } else {
            const msg = this.getNotFoundMsg(
              req,
              res,
              portToPassthrough,
              'server',
            );
            log.d(msg);
            res.send(msg);
          }
          next();
        } else {
          proxy.web(
            req,
            res,
            this.getProxyConfig({ req, res, port: portToPassthrough, isHttps }),
            next,
          );
        }
      },
    );

    const h = isHttps
      ? new https.Server(
          {
            key: fse.readFileSync(this.serveKeyPath),
            cert: fse.readFileSync(this.serveCertPath),
          },
          app,
        )
      : new http.Server(app);

    await Helpers.killProcessByPort(portToPassthrough, { silent: true });
    await new Promise((resolve, reject) => {
      h.listen(portToPassthrough, () => {
        console.log(
          `Passthrough ${isHttps ? 'SECURE' : 'UNSECURE'} server` +
            ` listening on port: ${portToPassthrough}
        env: ${app.settings.env}
          `,
        );
      });
      resolve(void 0);
    });
  }
  //#endregion

  //#region start client passthrough
  private resolveProperTarget(
    vpnServerTargetsObj: { [originHostname: string]: URL },
    req: http.IncomingMessage & express.Request,
    hosts: { [originHostname: string]: string },
  ): URL {
    /**
     *
     */
    const originHostname = hosts[req.hostname];
    // console.log({
    //   'req.hostname': req.hostname,
    //   'originHostname': originHostname
    // })
    return vpnServerTargetsObj[originHostname];
  }

  private async clientPassthrough(
    portToPassthrough: number,
    vpnServerTargets: URL[],
    hostsArr: HostForServer[],
  ) {
    const hosts = hostsArr.reduce((a, b) => {
      const aliasesObj = {};
      for (const aliasDomain of b.aliases) {
        aliasesObj[aliasDomain] = b.originHostname;
      }
      return _.merge(a, aliasesObj);
    }, {});

    const vpnServerTargetsObj = vpnServerTargets.reduce((a, b) => {
      return _.merge(a, {
        [b.hostname]: b,
      });
    }, {});

    delete hosts['localhost'];
    delete hosts['broadcasthost'];
    // console.log({ vpnServerTargetsObj });

    const isHttps = this.isHttpsPort(portToPassthrough);
    // if (isHttps) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    // }
    const app = express();
    const proxy = httpProxy.createProxyServer({});

    app.use(
      (
        req: http.IncomingMessage & express.Request,
        res: http.ServerResponse & express.Response,
        next,
      ) => {
        // console.log('req', req  );
        this.filterHeaders(req, res);
        const port = this.getPortFromRequest(req);

        if (req.hostname === 'localhost') {
          if (this.portsToPass.includes(port)) {
            const msg = this.getNotFoundMsg(
              req,
              res,
              portToPassthrough,
              'client',
            );
            // log.d(msg)
            res.send(msg);
          } else {
            const msg = this.getMaybeChangeOriginTrueMs(
              req,
              res,
              portToPassthrough,
              'client',
            );
            // log.d(msg)
            res.send(msg);
          }
          next();
        } else {
          proxy.web(
            req,
            res,
            this.getProxyConfig({
              req,
              res,
              port: portToPassthrough,
              isHttps,
              hostname: this.resolveProperTarget(
                vpnServerTargetsObj,
                req,
                hosts,
              ).hostname,
            }),
            next,
          );
        }
      },
    );

    const h = isHttps
      ? new https.Server(
          {
            key: fse.readFileSync(this.serveKeyPath),
            cert: fse.readFileSync(this.serveCertPath),
          },
          app,
        )
      : new http.Server(app);

    await Helpers.killProcessByPort(portToPassthrough, { silent: true });
    await new Promise((resolve, reject) => {
      h.listen(portToPassthrough, () => {
        log.i(
          `Passthrough ${isHttps ? 'SECURE' : ''} client` +
            ` listening on port: ${portToPassthrough}
        env: ${app.settings.env}
          `,
        );
      });
      resolve(void 0);
    });
  }
  //#endregion

  //#endregion

  //#region private methods / get port from request
  private getPortFromRequest(req: express.Request): number {
    const host = req.headers.host;
    const protocol = req.protocol;
    let port: number | string;
    if (host) {
      const hostParts = host.split(':');
      if (hostParts.length === 2) {
        port = hostParts[1];
      } else {
        // Default ports based on protocol
        port = protocol === 'https' ? '443' : '80';
      }
    } else {
      // Default to port 80 if no host header is present (uncommon)
      port = '80';
    }
    return Number(port);
  }

  //#endregion

  //#region private methods / prevent bad target for client
  private preventBadTargetForClient(vpnServerTarget: URL) {
    if (!vpnServerTarget) {
      const currentLocalIp = Helpers.localIpAddress();
      Helpers.error(
        `[vpn-server] Please provide (correct?) target server
      Example:
      vpn-server ${currentLocalIp} # or whatever ip of your machine with vpn

      # your local ip is: ${currentLocalIp}

      your args:
      ${process.argv.slice(2).join(', ')}
      `,
        false,
        true,
      );
    }
  }

  //#endregion
}

//#region helper / gen msg
const genMsg =
  `
################################################
## This file is generated #####################
################################################
`.trim() + EOL;
//#endregion

//#region helpers / save hosts
function saveHosts(
  hosts: EtcHosts | HostForServer[],
  options?: {
    saveHostInUserFolder: boolean;
  },
) {
  // console.log({ hosts })
  const { saveHostInUserFolder } = options || ({} as any);
  if (_.isArray(hosts)) {
    hosts = hosts.reduce((prev, curr) => {
      return _.merge(prev, {
        [curr.name]: curr,
      });
    }, {} as EtcHosts);
  }
  const toSave = parseHost(hosts, saveHostInUserFolder);
  // Object.values(hosts).forEach( c => c )
  // console.log({ toSave })
  if (saveHostInUserFolder) {
    Helpers.writeFile(HOST_FILE_PATHUSER, toSave);
  } else {
    Helpers.writeFile(HOST_FILE_PATH, toSave);
  }
}
//#endregion

//#region helpers / parse hosts
function parseHost(
  hosts: EtcHosts,
  options: {
    saveHostInUserFolder: boolean;
  },
) {
  const { saveHostInUserFolder } = options || ({} as any);
  _.keys(hosts).forEach(hostName => {
    const v = hosts[hostName] as HostForServer;
    v.name = hostName;
  });
  return (
    genMsg +
    EOL +
    _.keys(hosts)
      .map(hostName => {
        const v = hosts[hostName] as HostForServer;
        if (saveHostInUserFolder) {
          return `${v.disabled ? '#' : ''}${v.ipOrDomain} ${(v.aliases as string[]).join(' ')}`;
        }
        return (
          `${v.disabled ? '#' : ''}${v.ipOrDomain} ${(v.aliases as string[]).join(' ')}` +
          ` # ${v.name} ${GENERATED}`
        );
      })
      .join(EOL) +
    EOL +
    EOL +
    genMsg
  );
}
//#endregion
