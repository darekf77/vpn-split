//#region imports
import { execSync } from 'child_process';
import * as crypto from 'crypto';
// TODO I am using TCP ugrade not UDP!
import * as dgram from 'dgram'; // <-- For UDP sockets
import * as http from 'http';
import { URL } from 'url';

import axios from 'axios';
import * as express from 'express';
import * as httpProxy from 'http-proxy';
import { Log, Level } from 'ng2-logger/src';
import { config, Utils } from 'tnp-core/src';
import {
  _,
  path,
  fse,
  https,
  isElevated,
  crossPlatformPath,
  os,
  UtilsOs,
  UtilsNetwork,
} from 'tnp-core/src';
import { CoreModels } from 'tnp-core/src';
import { Helpers, HelpersTaon } from 'tnp-helpers/src';

import { Hostile } from './hostile.backend';
import { EtcHosts, HostForServer, OptHostForServer } from './models';

const HOST_FILE_PATH = UtilsNetwork.getEtcHostsPath();

const log = Log.create('vpn-split', Level.INFO);
//#endregion

//#region consts

const GENERATED = '#GENERATED_BY_CLI#';

const EOL = process.platform === 'win32' ? '\r\n' : '\n';

const SERVERS_PATH = '/$$$$servers$$$$';

const HOST_FILE_PATHUSER = crossPlatformPath([
  UtilsOs.getRealHomeDir(),
  'hosts-file__vpn-split',
]);

const from = HostForServer.From;
const DefaultEtcHosts = {
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
    ports = [80, 443, 4443, 22, 2222, 8180, 8080, 4407, 7999, 9443],
    additionalDefaultHosts = {},
    cwd = process.cwd(),
    allowNotSudo = false,
  }: {
    ports?: number[];
    additionalDefaultHosts?: EtcHosts;
    cwd?: string;
    allowNotSudo?: boolean;
  } = {}) {
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
        _.merge(DefaultEtcHosts, additionalDefaultHosts),
        cwd,
      );
    }
    return VpnSplit._instances[cwd] as VpnSplit;
  }
  //#endregion

  //#region start server
  async startServer(saveHostInUserFolder = false) {
    this.createCertificateIfNotExists();

    const hostsForCert = this.hosts;

    // const domainsForCert: string[] = Utils.uniqArray(
    //   Object.keys(hostsForCert).reduce((prev, curr) => {
    //     const host = hostsForCert[curr] as HostForServer;
    //     host.aliases.forEach(alias => {
    //       if (!host.isDefault) {
    //         prev.push(alias);
    //       }
    //     });
    //     return prev;
    //   }, [] as string[]),
    // );

    // this.ensureMkcertCertificate(domainsForCert);

    //#region modify /etc/host to direct traffic appropriately
    saveHosts(hostsForCert, { saveHostInUserFolder });
    //#endregion

    // Start TCP/HTTPS passthrough
    for (const portToPassthrough of this.portsToPass) {
      await this.serverPassthrough(portToPassthrough);
    }

    // Start UDP passthrough
    for (const portToPassthrough of this.portsToPass) {
      await this.serverUdpPassthrough(portToPassthrough);
    }

    Helpers.info(`Activated (server).`);
  }
  //#endregion

  //#region apply hosts
  public applyHosts(hosts: EtcHosts) {
    // console.log(hosts);
    saveHosts(hosts);
  }

  public applyHostsLocal(hosts: EtcHosts) {
    // console.log(hosts);
    saveHostsLocal(hosts);
  }
  //#endregion

  //#region start client
  public async startClient(
    vpnServerTargets: URL[] | URL,
    options: {
      saveHostInUserFolder?: boolean;
      useHost?: EtcHosts;
    },
  ) {
    options = options || {};
    const { saveHostInUserFolder } = options;
    if (!Array.isArray(vpnServerTargets)) {
      vpnServerTargets = [vpnServerTargets];
    }
    for (const vpnServerTarget of vpnServerTargets) {
      await this.preventBadTargetForClient(vpnServerTarget);
    }

    this.createCertificateIfNotExists();

    // Get remote host definitions from remote server
    const hosts: Array<{
      ip: string;
      alias: string;
      originHostname?: string;
    }> = [];

    for (const vpnServerTarget of vpnServerTargets) {
      const newHosts = await this.getRemoteHosts(vpnServerTarget);
      for (const host of newHosts) {
        // Mark the original VPN server domain
        host.originHostname = vpnServerTarget.hostname;
        hosts.push(host);
      }
    }

    // Merge with original, redirecting all non-default entries to 127.0.0.1
    const originalHosts = this.hostsArr;
    const combinedHostsObj = _.values(
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
          return copy;
        })
        .reduce((prev, curr) => {
          return _.merge(prev, {
            [curr.aliases.join(' ')]: curr,
          });
        }, {}),
    ) as HostForServer[];

    const hostsForCert = options.useHost ? options.useHost : combinedHostsObj;

    // const domainsForCert: string[] = Utils.uniqArray(
    //   Object.keys(hostsForCert).reduce((prev, curr) => {
    //     const host = hostsForCert[curr] as HostForServer;
    //     host.aliases.forEach(alias => {
    //       if (!host.isDefault) {
    //         prev.push(alias);
    //       }
    //     });
    //     return prev;
    //   }, [] as string[]),
    // );

    // this.ensureMkcertCertificate(domainsForCert);

    saveHosts(hostsForCert, {
      saveHostInUserFolder,
    });

    // Start TCP/HTTPS passthrough
    for (const portToPassthrough of this.portsToPass) {
      await this.clientPassthrough(
        portToPassthrough,
        vpnServerTargets,
        combinedHostsObj,
      );
    }

    // Start UDP passthrough
    for (const portToPassthrough of this.portsToPass) {
      await this.clientUdpPassthrough(
        portToPassthrough,
        vpnServerTargets,
        combinedHostsObj,
      );
    }

    Helpers.info(`Client activated`);
  }
  //#endregion

  //#region private methods / get remote hosts
  private async getRemoteHosts(vpnServerTarget: URL) {
    try {
      const url = `http://${vpnServerTarget.hostname}${SERVERS_PATH}`;
      const response = await axios({ url, method: 'GET' });
      return response.data as {
        ip: string;
        alias: string;
        originHostname?: string;
      }[];
    } catch (err) {
      Helpers.error(
        `Remote server: ${vpnServerTarget.hostname} may be inactive...`,
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
        `[vpn-split] Generating new self-signed certificate for localhost...`,
      );
      const commandGen = UtilsOs.isRunningInWindowsPowerShell()
        ? `powershell -Command "& 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' req -nodes -new -x509 -keyout ${this.serveKeyName} -out ${this.serveCertName}"`
        : `openssl req -nodes -new -x509 -keyout ${this.serveKeyName} -out ${this.serveCertName}`;
      Helpers.run(commandGen, { cwd: this.cwd, output: true }).sync();
    }
  }
  //#endregion

  //#region private methods / TCP & HTTPS passthrough
  private getTarget({
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
    return `${req.protocol}://${hostname}:${port}`;
  }

  private getProxyConfig({
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
    // console.log({
    //   target,
    //   port,
    //   hostname,
    //   reqHostname: req.hostname,
    //   serverPassthrough,
    // });
    return isHttps
      ? {
          target,
          ssl: {
            key: fse.readFileSync(this.serveKeyPath),
            cert: fse.readFileSync(this.serveCertPath),
          },
          // agent: new https.Agent({
          //   secureOptions: crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
          // }),
          // changeOrigin: true,
          secure: true,
        }
      : ({ target } as httpProxy.ServerOptions);
  }

  private getNotFoundMsg(
    req: express.Request,
    res: express.Response,
    port: number,
    type: 'client' | 'server',
  ): string {
    return `[vpn-split] You are requesting a URL that is not in proxy reach [${type}]
Protocol: ${req.protocol}
Hostname: ${req.hostname}
OriginalUrl: ${req.originalUrl}
Req.method: ${req.method}
Port: ${port}
SERVERS_PATH: ${SERVERS_PATH}`;
  }

  private getMaybeChangeOriginTrueMsg(
    req: express.Request,
    res: express.Response,
    port: number,
    type: 'client' | 'server',
  ): string {
    return `[vpn-split] Possibly need changeOrigin: true in your proxy config
Protocol: ${req.protocol}
Hostname: ${req.hostname}
OriginalUrl: ${req.originalUrl}
Req.method: ${req.method}
Port: ${port}`;
  }

  private filterHeaders(
    req: http.IncomingMessage & express.Request,
    res: http.ServerResponse & express.Response,
  ): void {
    // If you have any headers to remove, do it here:
    const headersToRemove = [
      // 'Strict-Transport-Security',
      // 'Content-Security-Policy',
      // ...
    ];
    headersToRemove.forEach(headerName => {
      delete req.headers[headerName];
      res.setHeader(headerName, '');
    });
  }

  private isHttpsPort(port: number): boolean {
    // Decide your logic for “is HTTPS” here
    return [443, 4443, 9443].includes(port);
  }

  //#region server passthrough (TCP/HTTPS)
  private async serverPassthrough(portToPassthrough: number): Promise<void> {
    const isHttps = this.isHttpsPort(portToPassthrough);
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    const app = express();
    const proxy = httpProxy.createProxyServer({});

    const localIp = await UtilsNetwork.getLocalIpAddresses();
    const currentLocalIps = [
      CoreModels.localhostDomain,
      CoreModels.localhostIp127,
      ...localIp.map(a => a.address),
    ];

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
                this.hostsArrWithoutDefault.map(h => ({
                  ip: h.ip,
                  alias: HelpersTaon.arrays.from(h.aliases).join(' '),
                })),
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

    const server = isHttps
      ? https.createServer(
          {
            key: fse.readFileSync(this.serveKeyPath),
            cert: fse.readFileSync(this.serveCertPath),
          },
          app,
        )
      : http.createServer(app);

    await Helpers.killProcessByPort(portToPassthrough, { silent: true });
    await new Promise<void>((resolve, reject) => {
      server.listen(portToPassthrough, () => {
        console.log(
          `TCP/HTTPS server listening on port ${portToPassthrough} (secure=${isHttps})`,
        );
        resolve();
      });
    });
  }
  //#endregion

  //#region client passthrough (TCP/HTTPS)
  private async clientPassthrough(
    portToPassthrough: number,
    vpnServerTargets: URL[],
    hostsArr: HostForServer[],
  ) {
    // Map from an alias => the “real” origin hostname (the server domain)
    const aliasToOriginHostname: { [alias: string]: string | undefined } = {};
    for (const h of hostsArr) {
      for (const alias of h.aliases) {
        aliasToOriginHostname[alias] = h.originHostname;
      }
    }
    // Remove defaults from the map so we don't cause collisions
    delete aliasToOriginHostname['localhost'];
    delete aliasToOriginHostname['broadcasthost'];

    // Build a dictionary from originHostname => URL (for quick lookup)
    const originToUrlMap: { [origin: string]: URL } = {};
    for (const url of vpnServerTargets) {
      originToUrlMap[url.hostname] = url;
    }

    const isHttps = this.isHttpsPort(portToPassthrough);
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    const app = express();
    const proxy = httpProxy.createProxyServer({});

    app.use(
      (
        req: http.IncomingMessage & express.Request,
        res: http.ServerResponse & express.Response,
        next,
      ) => {
        this.filterHeaders(req, res);

        // Identify the real origin server based on alias
        const originHostname = aliasToOriginHostname[req.hostname];
        if (!originHostname) {
          // Not one of our known aliases
          const msg = this.getMaybeChangeOriginTrueMsg(
            req,
            res,
            portToPassthrough,
            'client',
          );
          res.send(msg);
          next();
          return;
        }

        // Proxy onward to the real server domain at the same port
        const targetUrlObj = originToUrlMap[originHostname];
        if (!targetUrlObj) {
          const notFoundMsg = this.getNotFoundMsg(
            req,
            res,
            portToPassthrough,
            'client',
          );
          res.send(notFoundMsg);
          next();
          return;
        }

        // Forward
        proxy.web(
          req,
          res,
          this.getProxyConfig({
            req,
            res,
            port: portToPassthrough,
            isHttps,
            hostname: targetUrlObj.hostname,
          }),
          next,
        );
      },
    );

    const server = isHttps
      ? https.createServer(
          {
            key: fse.readFileSync(this.serveKeyPath),
            cert: fse.readFileSync(this.serveCertPath),
          },
          app,
        )
      : http.createServer(app);

    await Helpers.killProcessByPort(portToPassthrough, { silent: true });
    await new Promise<void>((resolve, reject) => {
      server.listen(portToPassthrough, () => {
        log.i(
          `TCP/HTTPS client listening on port ${portToPassthrough} (secure=${isHttps})`,
        );
        resolve();
      });
    });
  }
  //#endregion

  //#region UDP passthrough
  /**
   * Start a UDP socket for “server” mode on a given port.
   * This example forwards inbound messages right back to the sender,
   * or you can forward them to an external IP:port if desired.
   */
  private async serverUdpPassthrough(port: number): Promise<void> {
    return;
    // Example of a simple “echo-style” server or forwarder
    const socket = dgram.createSocket('udp4');

    // (Optionally) kill existing processes on that port – though for UDP
    // we might not have a direct “listener process.” Adjust as needed.
    // await Helpers.killProcessByPort(port, { silent: true }).catch(() => {});

    socket.on('message', (msg, rinfo) => {
      // rinfo contains { address, port } of the sender
      // In a typical “server” scenario, you might:
      // 1. Inspect msg
      // 2. Possibly forward to some real backend if needed
      // 3. Or just echo it back

      // For a real forward, do something like:
      // const backendHost = 'some-other-host-or-ip';
      // const backendPort = 9999;
      // socket.send(msg, 0, msg.length, backendPort, backendHost);

      // For a basic echo server:
      socket.send(msg, 0, msg.length, rinfo.port, rinfo.address, err => {
        if (err) {
          log.er(`UDP server send error: ${err}`);
        }
      });
    });

    socket.on('listening', () => {
      const address = socket.address();
      log.i(`UDP server listening at ${address.address}:${address.port}`);
    });

    socket.bind(port);
  }

  /**
   * Start a UDP socket for “client” mode on a given port.
   * This example also just does a trivial pass-through or echo,
   * but you can adapt to forward to a remote server.
   */
  private async clientUdpPassthrough(
    port: number,
    vpnServerTargets: URL[],
    hostsArr: HostForServer[],
  ): Promise<void> {
    return;
    // console.log(`Client UDP passthrough, port ${port}` );
    // In client mode, we typically intercept local UDP traffic on “port”
    // and forward it to the remote server. Then we forward the remote
    // server's response back to the local client.

    const socket = dgram.createSocket('udp4');
    // await Helpers.killProcessByPort(port, { silent: true }).catch(() => {});

    // For simplicity, pick the first server from the array
    // Or add your own logic to choose among multiple.
    const primaryTarget = vpnServerTargets[0];
    const targetHost = primaryTarget.hostname;
    // Choose the same port or a custom port
    const targetPort = port;

    // A map to remember who originally sent us a packet,
    // so we can route the response back properly.
    // Key could be “targetHost:targetPort => { address, port }”
    // or “clientAddress:clientPort” => { remoteAddress, remotePort }.
    // Adapt to your scenario.
    const clientMap = new Map<string, dgram.RemoteInfo>();

    socket.on('message', (msg, rinfo) => {
      //
      // If the message is from a local client, forward to server.
      // If the message is from the server, forward back to the correct client.
      //

      // Check if it’s from local or remote by address. This is simplistic:
      const isFromLocal = !_.includes(
        hostsArr.map(h => h.ipOrDomain),
        rinfo.address,
      );

      if (isFromLocal) {
        // Received from local => forward to “server” (the VPN server)
        // Keep track of who we got this from (the local client)
        const key = `local-${rinfo.address}:${rinfo.port}`;
        clientMap.set(key, rinfo);

        // Forward to remote
        socket.send(msg, 0, msg.length, targetPort, targetHost, err => {
          if (err) {
            log.er(`UDP client forward error: ${err}`);
          }
        });
      } else {
        // Probably from remote => forward back to whichever local client sent it
        // In a more advanced scenario, parse the payload or maintain a bigger table
        // with NAT-like sessions.
        //
        // For now, we guess it’s from the “VPN server”
        // We'll just route it back to the single local client that we stored
        // or do multiple if we had a better NAT map.

        // If you have multi-target or multi-client logic, adapt here.
        // For example, search clientMap by something in the msg or a NAT key.
        clientMap.forEach((localRinfo, key) => {
          socket.send(
            msg,
            0,
            msg.length,
            localRinfo.port,
            localRinfo.address,
            err => {
              if (err) {
                log.er(`UDP client re-send error: ${err}`);
              }
            },
          );
        });
      }
    });

    socket.on('listening', () => {
      const address = socket.address();
      log.i(
        `UDP client listening at ${address.address}:${address.port}, forwarding to ${targetHost}:${targetPort}`,
      );
    });

    socket.bind(port);
  }
  //#endregion

  //#region private methods / get port from request
  private getPortFromRequest(req: express.Request): number {
    const host = req.headers.host;
    const protocol = req.protocol;
    if (host) {
      const hostParts = host.split(':');
      if (hostParts.length === 2) {
        return Number(hostParts[1]);
      } else {
        return protocol === 'https' ? 443 : 80;
      }
    }
    return 80;
  }
  //#endregion

  // Put this method in your VpnSplit class (or outside as a static helper)
  private ensureMkcertCertificate(domains: string[]) {
    //#region @backendFunc

    // console.log('Domains for cert:', domains);
    // Helpers.error(``,false,true);

    if (!UtilsOs.commandExistsSync('mkcert')) {
      Helpers.error('[vpn-split] mkcert is not installed.', false, true);
    }

    const certPath = this.serveCertPath; // e.g. .../tmp-server_cert
    const keyPath = this.serveKeyPath; // e.g. .../tmp-server_key

    const allNames = [
      'localhost',
      '127.0.0.1',
      // '::1',
      // optional: common local networks so the cert also works for raw IP access
      // '10.0.0.0/8',
      // '172.16.0.0/12',
      // '192.168.0.0/16',
      ...domains, // <-- your 120+ domains here
    ];

    // Helper: run mkcert and capture output
    const runMkcert = (args: string) => {
      try {
        return execSync(`mkcert ${args}`, { stdio: 'pipe' }).toString().trim();
      } catch (err: any) {
        const stderr = err.stderr?.toString() || '';
        if (stderr.includes('command not found')) {
          Helpers.error(
            '[vpn-split] mkcert is not installed. Install it first: https://github.com/FiloSottile/mkcert',
            false,
            true,
          );
        }
        throw err;
      }
    };

    // 1. Check if the root CA is already installed
    let caInstalled = false;
    try {
      const output = runMkcert('-CAROOT');
      // If -CAROOT succeeds and the root files exist → CA is installed
      const rootDir = crossPlatformPath(output.trim());
      if (
        rootDir &&
        fse.pathExistsSync(crossPlatformPath([rootDir, 'rootCA.pem']))
      ) {
        Helpers.info('[vpn-split] mkcert local CA is already installed');
        caInstalled = true;
      } else {
        Helpers.info('[vpn-split] mkcert local CA is NOT installed');
      }
    } catch {
      Helpers.info('[vpn-split] mkcert error checking local CA installation');
    }

    // 2. Install the local CA if needed (requires sudo once)
    if (!caInstalled) {
      Helpers.info(
        '[vpn-split] Installing mkcert local CA (requires sudo once)...',
      );
      try {
        execSync('mkcert -install', { stdio: 'inherit' });
        Helpers.info('[vpn-split] Local CA installed and trusted system-wide');
      } catch (err) {
        Helpers.error(
          '[vpn-split] Failed to run "mkcert -install". Run it manually with sudo.',
          false,
          true,
        );
      }
    }

    const isWindows = process.platform === 'win32';

    // const maxArgLength = isWindows ? 2000 : 8000; // Conservative limits
    let tempCertFiles: string[] = [];
    let tempKeyFiles: string[] = [];

    if (allNames.length <= 20 || !isWindows) {
      // Small list or non-Windows: one shot
      const namesArg = allNames.map(d => `"${d}"`).join(' ');
      const mkcertCmd = `-key-file "${keyPath}" -cert-file "${certPath}" ${namesArg}`;
      fse.ensureDirSync(path.dirname(certPath));
      runMkcert(mkcertCmd);
    } else {
      // Big list on Windows: Batch into chunks of ~20 domains
      const chunkSize = 20;
      fse.ensureDirSync(path.dirname(certPath));

      for (let i = 0; i < allNames.length; i += chunkSize) {
        const chunk = allNames.slice(i, i + chunkSize);
        const tempCert = `${certPath}.${i}.pem`;
        const tempKey = `${keyPath}.${i}.pem`;
        const namesArg = chunk.map(d => `"${d}"`).join(' ');
        const mkcertCmd = `-key-file "${tempKey}" -cert-file "${tempCert}" ${namesArg}`;

        Helpers.info(
          `[vpn-split] Generating batch ${Math.floor(i / chunkSize) + 1}/${Math.ceil(allNames.length / chunkSize)}...`,
        );
        runMkcert(mkcertCmd);

        tempCertFiles.push(tempCert);
        tempKeyFiles.push(tempKey);
      }

      // 3. Merge all temp certs into one (cert chain + leaves) and pick first key
      Helpers.info('[vpn-split] Merging batches into final cert...');
      const firstKey = tempKeyFiles[0];
      fse.copySync(firstKey, keyPath); // Use the first key (all are identical)

      // Concat all certs (mkcert output is already PEM-formatted)
      const mergedCertContent = tempCertFiles
        .map(f => fse.readFileSync(f, 'utf8'))
        .join('\n'); // PEM certs stack nicely
      fse.writeFileSync(certPath, mergedCertContent);

      // Clean up temps
      tempCertFiles.forEach(f => fse.removeSync(f));
      tempKeyFiles.slice(1).forEach(f => fse.removeSync(f)); // Keep first key as backup if needed

      Helpers.info('[vpn-split] Merged cert ready!');
    }

    // Verify
    if (!fse.existsSync(certPath) || !fse.existsSync(keyPath)) {
      Helpers.error('[vpn-split] Files missing after generation!', false, true);
    } else {
      Helpers.info(
        `[vpn-split] Trusted cert ready: ${allNames.length} hostnames covered`,
      );
    }
    //#endregion
  }

  //#region private methods / prevent bad target for client
  private async preventBadTargetForClient(vpnServerTarget: URL) {
    if (!vpnServerTarget) {
      const currentLocalIp =
        await UtilsNetwork.getFirstIpV4LocalActiveIpAddress();
      Helpers.error(
        `[vpn-server] Please provide a correct target server.\n` +
          `Example:\n` +
          `vpn-server ${currentLocalIp}\n\n` +
          `Your local IP is: ${currentLocalIp}`,
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
    saveHostInUserFolder?: boolean;
  },
) {
  const { saveHostInUserFolder } = options || {};
  if (_.isArray(hosts)) {
    hosts = hosts.reduce((prev, curr) => {
      return _.merge(prev, {
        [curr.name]: curr,
      });
    }, {} as EtcHosts);
  }
  const toSave = parseHost(hosts, !!saveHostInUserFolder);
  if (saveHostInUserFolder) {
    Helpers.writeFile(HOST_FILE_PATHUSER, toSave);
  } else {
    Helpers.writeFile(HOST_FILE_PATH, toSave);
  }
}

function saveHostsLocal(
  hosts: EtcHosts | HostForServer[],
  options?: {
    saveHostInUserFolder?: boolean;
  },
) {
  const { saveHostInUserFolder } = options || {};
  if (_.isArray(hosts)) {
    hosts = hosts.reduce((prev, curr) => {
      return _.merge(prev, {
        [curr.name]: curr,
      });
    }, {} as EtcHosts);
  }
  const toSave = parseHost(hosts, !!saveHostInUserFolder, true);
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
  saveHostInUserFolder: boolean,
  useLocal = false,
) {
  // hosts = _.merge(hosts, DefaultEtcHosts);
  hosts = {
    ...DefaultEtcHosts,
    ...hosts,
  };
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

        if (v.skipUpdateOfServerEtcHosts) {
          console.warn(
            `[vpn-split] Skip saving host: ${v.name} (${v.ipOrDomain})`,
          );
          return `# SKIPPING HOST ${v.ipOrDomain} ${v.aliases.join(' ')} ${GENERATED}`; // Skip saving this host
        }
        const aliasesStr = (v.aliases as string[]).join(' ');
        if (saveHostInUserFolder) {
          // For a user-specific hosts file:
          return useLocal
            ? `127.0.0.1 ${aliasesStr}`
            : `${v.disabled ? '#' : ''}${v.ipOrDomain} ${aliasesStr}`;
        }
        return useLocal
          ? `127.0.0.1 ${aliasesStr}`
          : `${v.disabled ? '#' : ''}${v.ipOrDomain} ${aliasesStr} # ${v.name} ${GENERATED}`;
      })
      .join(EOL) +
    EOL +
    EOL +
    genMsg
  );
}
//#endregion
