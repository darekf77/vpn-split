//#region imports
import {
  _,
  path,
  fse,
  http, https,
} from 'tnp-core';
import * as express from 'express';
import * as httpProxy from 'http-proxy';
import { Helpers } from 'tnp-helpers';
import { config } from 'tnp-config';
import { URL } from 'url';
import { Hostile } from './hostile.backend';
import { EtcHosts, HostForServer, OptHostForServer } from './models.backend';
import axios from 'axios';
import isElevated from 'is-elevated';
//#endregion

//#region consts
const GENERATED = '#GENERATED_BY_NAVI_CLI#';

const WINDOWS = process.platform === 'win32'
const EOL = WINDOWS
  ? '\r\n'
  : '\n';

const SERVERS_PATH = '/$$$$servers$$$$';

const HOST_FILE_PATH = WINDOWS
  ? 'C:/Windows/System32/drivers/etc/hosts'
  : '/etc/hosts';

const from = HostForServer.From;
const defaultHosts = {
  'localhost alias': from({
    ipOrDomain: '127.0.0.1',
    aliases: 'localhost' as any,
    isDefault: true,
  } as OptHostForServer),
  'broadcasthost': from({
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
    })
  }
  get hostsArrWithoutDefault() {
    return this.hostsArr.filter(f => !f.isDefault);
  }

  private get serveKeyName() { return 'tmp-' + config.file.server_key; }
  private get serveKeyPath() { return path.join(this.cwd, this.serveKeyName); }
  private get serveCertName() { return 'tmp-' + config.file.server_cert; }
  private get serveCertPath() { return path.join(this.cwd, this.serveCertName); }
  private get serveCertChainName() { return 'tmp-' + config.file.server_chain_cert; }
  private get serveCertChainPath() { return path.join(this.cwd, this.serveCertChainName); }
  //#endregion

  //#region fields
  private readonly __hostile: Hostile;
  //#endregion

  //#region singleton
  private static _instances = {};
  private constructor(
    private hosts: EtcHosts,
    private cwd: string
  ) {
    this.__hostile = new Hostile();
  }
  public static async Instance({ additionalDefaultHosts, cwd = process.cwd() }
    : { additionalDefaultHosts?: EtcHosts; cwd?: string; } = {}) {

    if (!(await isElevated())) {
      Helpers.error(`[vpn-split] Please run this program as sudo (or admin on windows)`, false, true)
    }

    if (!VpnSplit._instances[cwd]) {
      VpnSplit._instances[cwd] = new VpnSplit(_.merge(defaultHosts, additionalDefaultHosts), cwd);
    }
    return VpnSplit._instances[cwd] as VpnSplit;
  }
  //#endregion

  //#region privaet methods

  //#region create certificate
  private createCertificateIfNotExists() {
    if (!Helpers.exists(this.serveKeyPath) || !Helpers.exists(this.serveCertPath)) {
      Helpers.info(`[vpn-split] Generating new certification for localhost... please follow instructions..`);
      const commandGen = `openssl req -nodes -new -x509 -keyout ${this.serveKeyName} -out ${this.serveCertName}`;
      Helpers.run(commandGen, { cwd: this.cwd, output: true }).sync()

      // Helpers.run(`openssl verify -verbose -x509_strict -CAfile ${this.serveKeyName} ${this.serveCertChainName}`,
      //   { cwd: this.cwd, output: true }).sync()
    }
  }
  //#endregion

  //#region proxy passthrough

  //#region start server passthrough
  private async serverPassthrough(port: 80 | 443 | 22) {
    const isHttps = (port === 443);
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    const app = express();
    const proxy = httpProxy.createProxyServer({});
    const currentLocalIps = [
      'localhost',
      '127.0.0.1',
      // '0.0.0.0',
      ...Helpers.allLocalIpAddresses().map(a => a.hostname)
    ];

    app.use((req, res, next) => {
      if (currentLocalIps.includes(req.hostname)) {
        if (req.method === 'GET' && req.originalUrl === SERVERS_PATH) {
          res.send(JSON.stringify(this.hostsArrWithoutDefault.map(h => {
            return { ip: h.ip, alias: Helpers.arrays.from(h.aliases).join(' ') };
          })));
        } else {
          res.send(`hello from here... server passthrough
          protocol: ${req.protocol} <br>
          hostname: ${req.hostname} <br>
          originalUrl: ${req.originalUrl} <br>
          `);
        }

        next();
      } else {
        const target = `${req.protocol}://${req.hostname}`;
        proxy.web(req, res, {
          target,
          ssl: {
            key: fse.readFileSync(this.serveKeyPath),
            cert: fse.readFileSync(this.serveCertPath)
          },
          secure: false
        }, next);
      }
    });

    const h = isHttps ? (new https.Server({
      key: fse.readFileSync(this.serveKeyPath),
      cert: fse.readFileSync(this.serveCertPath)
    }, app)) : (new http.Server(app));

    await Helpers.killProcessByPort(port)
    await (new Promise((resolve, reject) => {
      h.listen(port, () => {
        console.log(`Passthrough ${isHttps ? 'SECURE' : ''} server`
          + ` listening on por: ${port}
        env: ${app.settings.env}
          `);
      });
      resolve(void 0);
    }));
  }
  //#endregion

  //#region start client passthrough
  private async clientPassthrough(port: 80 | 443 | 22, vpnServerTarget: URL) {
    const isHttps = (port === 443);
    // if (isHttps) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    // }
    const app = express();
    const proxy = httpProxy.createProxyServer({});

    app.use((req, res, next) => {
      if (req.hostname === 'localhost') {
        res.send(`hello from here... client passthrough
      protocol: ${req.protocol} <br>
      hostname: ${req.hostname} <br>
      originalUrl: ${req.originalUrl} <br>
      `);
        next();
      } else {
        const target = `${req.protocol}://${vpnServerTarget.hostname}`;
        proxy.web(req, res, {
          target,
          ssl: {
            key: fse.readFileSync(this.serveKeyPath),
            cert: fse.readFileSync(this.serveCertPath)
          },
          secure: false
        }, next);
      }
    });

    const h = isHttps ? (new https.Server({
      key: fse.readFileSync(this.serveKeyPath),
      cert: fse.readFileSync(this.serveCertPath)
    }, app)) : (new http.Server(app));

    await Helpers.killProcessByPort(port)
    await (new Promise((resolve, reject) => {
      h.listen(port, () => {
        console.log(`Passthrough ${isHttps ? 'SECURE' : ''} client`
          + ` listening on port: ${port}
        env: ${app.settings.env}
          `);
      });
      resolve(void 0);
    }));
  }
  //#endregion

  //#endregion

  //#region prevent bad target for client
  private preventBadTargetForClient(vpnServerTarget: URL) {
    if (!vpnServerTarget) {
      const currentLocalIp = Helpers.localIpAddress();
      Helpers.error(`[vpn-server] Please provide (correct?) target server
      Example:
      vpn-server ${currentLocalIp} # or whatever ip of your machine with vpn

      # your local ip is: ${currentLocalIp}

      your args:
      ${process.argv.slice(2).join(', ')}
      `, false, true);
    }
  }
  //#endregion

  //#endregion

  //#region server
  async server() {
    this.createCertificateIfNotExists();
    //#region modify /etc/host 80,443 to redirect to proper server domain/ip
    saveHosts(this.hosts);
    //#endregion
    await this.serverPassthrough(22);
    await this.serverPassthrough(80);
    await this.serverPassthrough(443);
    Helpers.info(`Activated.`)
  }
  //#endregion

  //#region client

  private async getRemoteHosts(vpnServerTarget: URL) {
    try {
      const url = `http://${vpnServerTarget.hostname}${SERVERS_PATH}`;
      const response = await axios({
        url,
        method: 'GET',
      }) as any;
      return response.data as { ip: string; alias: string; }[];
    } catch (err) {
      Helpers.error(`Remote server: ${vpnServerTarget.hostname} maybe inactive...`
        + ` nothing to passthrought `, true, true);
      return [];
    }
  }

  public async client(vpnServerTarget: URL) {
    this.preventBadTargetForClient(vpnServerTarget);
    this.createCertificateIfNotExists();
    //#region modfy clien 80, 443 to local ip of server
    const hosts = await this.getRemoteHosts(vpnServerTarget)
    const originalHosts = this.hostsArr;
    const cloned = _.values([
      ...originalHosts,
      ...hosts.map(h => HostForServer.From({
        aliases: h.alias as any,
        ipOrDomain: h.ip
      }, `external host ${h.alias} ${h.ip}`))
    ].map(c => {
      const copy = c.clone();
      if (!copy.isDefault) {
        copy.ip = `127.0.0.1`;
      }
      return copy;
    }).reduce((prev, curr) => {

      return _.merge(prev, {
        [curr.aliases.join(' ')]: curr
      })
    }, {})) as any;

    saveHosts(cloned);
    //#endregion
    await this.clientPassthrough(22, vpnServerTarget);
    await this.clientPassthrough(80, vpnServerTarget);
    await this.clientPassthrough(443, vpnServerTarget);
  }

  //#endregion

}

//#region helpers

//#region gen msg
const genMsg = `
################################################
## This file is generated by coomand navi vpn ##
################################################
`.trim() + EOL;
//#endregion

//#region save hosts
function saveHosts(hosts: EtcHosts | HostForServer[]) {
  if (_.isArray(hosts)) {
    hosts = hosts.reduce((prev, curr) => {
      return _.merge(prev, {
        [curr.name]: curr
      })
    }, {} as EtcHosts);
  }
  const toSave = parseHost(hosts)
  // Object.values(hosts).forEach( c => c )
  // console.log(toSave)
  Helpers.writeFile(HOST_FILE_PATH, toSave);
}
//#endregion

//#region parse hosts
function parseHost(hosts: EtcHosts) {
  _.keys(hosts).forEach(hostName => {
    const v = hosts[hostName] as HostForServer;
    v.name = hostName;
  });
  return genMsg + EOL + _.keys(hosts).map(hostName => {
    const v = hosts[hostName] as HostForServer;
    return `${v.disabled ? '#' : ''}${v.ipOrDomain} ${(v.aliases as string[]).join(' ')}`
      + ` # ${v.name} ${GENERATED}`;
  }).join(EOL) + EOL + EOL + genMsg;
}
//#endregion

//#endregion
