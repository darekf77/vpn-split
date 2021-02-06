//#region imports
import * as _ from 'lodash';
import * as glob from 'glob';
import * as path from 'path';
import * as express from 'express';
import * as http from 'http';
import * as https from 'https';
import * as fse from 'fs-extra';
import * as  cors from 'cors';
import * as bodyParser from 'body-parser';
import * as cookieParser from 'cookie-parser';
import * as methodOverride from 'method-override';
import * as fileUpload from 'express-fileupload';
import { Models } from 'tnp-models';
import { Helpers } from 'tnp-helpers';
import { config } from 'tnp-config';
import { URL } from 'url';
import { CLASS } from 'typescript-class-helpers';
import { Hostile } from './hostile.backend';
import { EtcHosts, HostForServer, OptHostForServer } from './models.backend';
import axios, { AxiosResponse } from 'axios';
import { Host } from '@angular/core';
declare const global: any;
const isElevated = require('is-elevated');
//#endregion

const GENERATED = '#GENERATED_BY_NAVI_CLI#';

var WINDOWS = process.platform === 'win32'
var EOL = WINDOWS
  ? '\r\n'
  : '\n'

const HOST_FILE_PATH = WINDOWS
  ? 'C:/Windows/System32/drivers/etc/hosts'
  : '/etc/hosts';

const from = HostForServer.From;
const defaultHosts = {
  'localhost alias': from({
    ipOrDomain: '127.0.0.1',
    aliases: 'localhost',
    isDefault: true,
  } as OptHostForServer),
  'broadcasthost': from({
    ipOrDomain: '255.255.255.255',
    aliases: 'broadcasthost',
    isDefault: true,
  } as OptHostForServer),
  'localhost alias ipv6': from({
    ipOrDomain: '::1',
    aliases: 'localhost',
    isDefault: true,
  } as OptHostForServer),
} as EtcHosts;

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
  public static async Instance(additionalDefaultHosts?: EtcHosts, cwd = process.cwd()) {

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

  //#endregion

  //#region server
  async server() {
    this.createCertificateIfNotExists();
    saveHosts(this.hosts);
    this.startServer(80);
    this.startServer(433);
  }

  private startServer(port: 80 | 433) {
    const app = express();

    app.get(/^\/(.*)/, (
      req: http.IncomingMessage & express.Request,
      res: http.ServerResponse & express.Response) => {

      res.send('hello')
    });

    this.initMidleware(app);
    const h = new http.Server(app);

    h.listen(port, () => {
      console.log(`Server listening on ${Helpers.urlParse(port).origin}
      env: ${app.settings.env}
        `);
    });
  }
  //#endregion

  //#region client
  public async client(vpnServerTarget: URL) {
    if (!vpnServerTarget) {
      const currentLocalIp = Helpers.localIpAddress();
      Helpers.error(`[vpn-server] Please provide target server
      Example:
      vpn-server ${currentLocalIp} # or whatever ip of your machine with vpn

      # your local ip is: ${currentLocalIp}
      `, false, false)
    }
    this.createCertificateIfNotExists();
    vpnServerTarget = Helpers.urlParse(
      `http://${vpnServerTarget.hostname}:${config.ports.VPN_SPLIT_SERVER}`
    );
    const originalHosts = this.hostsArr;
    const cloned = originalHosts
      .map(c => {
        const copy = c.clone();
        if (!copy.isDefault) {
          copy.ip = `127.0.0.1`;
        }
        return copy;
      });
    saveHosts(cloned);
    await this.clientPassthroughServer(vpnServerTarget);
    await this.clientListenServer(80);
    await this.clientListenServer(443);
  }

  private async clientPassthroughServer(vpnServerTarget: URL, port = config.ports.VPN_SPLIT_CLIENT) {
    const app = express();
    app.get(/^\/(.*)/, (
      req: http.IncomingMessage & express.Request,
      res: http.ServerResponse & express.Response) => {

      res.send('hello')
    });

    this.initMidleware(app);
    const h = new http.Server(app);

    await (new Promise((resolve, reject) => {
      h.listen(port, () => {
        console.log(`Passthrough server listening on ${Helpers.urlParse(port).origin}
        env: ${app.settings.env}
          `);
      });
      resolve(void 0);
    }));
  }

  private get serveKeyName() { return 'tmp-' + config.file.server_key; }
  private get serveKeyPath() { return path.join(this.cwd, this.serveKeyName); }
  private get serveCertName() { return 'tmp-' + config.file.server_cert; }
  private get serveCertPath() { return path.join(this.cwd, this.serveKeyName); }

  private createCertificateIfNotExists() {
    if (!Helpers.exists(this.serveKeyPath) || !Helpers.exists(this.serveCertPath)) {
      Helpers.info(`[vpn-split] Generating new certification for localhost... please follow instructions..`);
      Helpers.run(`openssl req -nodes -new -x509 -keyout ${this.serveKeyName} -out ${this.serveCertName}`,
        { cwd: this.cwd, output: true }).sync()
    }
  }

  private async clientListenServer(port: 80 | 443) {
    const isHttps = (port === 443);
    const app = express();
    app.get(/^\/(.*)/, (
      req: http.IncomingMessage & express.Request,
      res: http.ServerResponse & express.Response) => {

      res.send(`hello 80 or 443 - protocol:${req.protocol}`)
    });

    this.initMidleware(app);
    const h = isHttps ? (new https.Server({
      key: fse.readFileSync(this.serveKeyPath),
      cert: fse.readFileSync(this.serveCertPath)
    }, app)) : (new http.Server(app));

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

  //#region middle ware
  private initMidleware(app: express.Application) {

    app.use(fileUpload())
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(bodyParser.json());
    app.use(methodOverride());
    app.use(cookieParser());
    app.use(cors());

    (() => {
      app.use((req, res, next) => {

        res.set('Access-Control-Expose-Headers',
          [
            'Content-Type',
            'Authorization',
            'X-Requested-With',
          ].join(', '))
        next();
      });
    })()
  }
  //#endregion

}



const genMsg = `
################################################
## This file is generated by coomand navi vpn ##
################################################
`.trim() + EOL;

function saveHosts(hosts: EtcHosts | HostForServer[]) {
  if (_.isArray(hosts)) {
    hosts = hosts.reduce((prev, curr) => {
      return _.merge(prev, {
        [curr.name]: curr
      })
    }, {} as EtcHosts);
  }
  Helpers.writeFile(HOST_FILE_PATH, parseHost(hosts));
}

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
