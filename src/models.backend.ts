import * as _ from 'lodash';
import chalk from 'chalk';
import { Helpers } from 'tnp-helpers';

export type EtcHosts = { [hostName in string]: HostForServer; };
export type IEtcHosts = { [hostName in string]: Pick<HostForServer, 'aliases' | 'ipOrDomain'>; };

export interface OptHostForServer {
  ip?: string;
  domain?: string;
  ipOrDomain?: string;
  aliases?: string[] | string;
  name?: string;
  /**
   * if true - ip and domain will output empty string
   */
  disabled?: boolean;
}

export class HostForServer implements OptHostForServer {
  private _data: OptHostForServer;
  static From(ipOrDomain: string | URL | Pick<OptHostForServer, 'ipOrDomain' | 'aliases'>, name = '', disabled = false): HostForServer {
    if (!ipOrDomain) {
      return void 0;
    }
    if (_.isString(ipOrDomain)) {
      const parsed = Helpers.urlParse(ipOrDomain);
      if (parsed) {
        ipOrDomain = parsed;
      }
    }

    if (_.isObject(ipOrDomain) && (ipOrDomain instanceof URL)) {
      ipOrDomain = ipOrDomain as URL;
      if (Helpers.isValidIp(ipOrDomain?.host)) {
        return new HostForServer({ ip: ipOrDomain.origin, name, disabled });
      } else {
        return new HostForServer({ domain: ipOrDomain.origin, name, disabled });
      }
    } else {
      if (_.isString(ipOrDomain)) {
        return new HostForServer({ ipOrDomain, name, disabled });
      } else {
        (ipOrDomain as OptHostForServer).name = (name && (name.trim() !== '')) ?
          name : (ipOrDomain as OptHostForServer).name;
        if (!_.isBoolean((ipOrDomain as OptHostForServer).disabled)) {
          (ipOrDomain as OptHostForServer).disabled = disabled;
        }
        return new HostForServer(ipOrDomain as any);
      }

    }
  }
  constructor(data: OptHostForServer) {
    if (data?.ipOrDomain) {
      if (Helpers.isValidIp(data.ipOrDomain)) {
        data.ip = data.ipOrDomain;
      } else {
        data.domain = data.ipOrDomain;
      }
    }
    if (data && !data.ip) {
      data.ip = '';
    }
    if (data && !data.domain) {
      data.domain = '';
    }
    if (!data) {
      data = {};
    }
    if (_.isString(data?.aliases)) {
      data.aliases = Helpers.strings.splitIfNeed(data.aliases);
    }
    this._data = data;
  }
  public get ip() {
    if (this.disabled) {
      return '';
    }
    return this._data.ip;
  }
  public get domain() {
    if (this.disabled) {
      return '';
    }
    return this._data.domain;
  }

  public get aliases(): string | string[] {
    if (this.disabled) {
      return [];
    }
    if (!_.isArray(this._data.aliases)) {
      return [];
    }
    return this._data.aliases;
  }

  public get name() {
    return this._data.name;
  }
  public set name(v) {
    this._data.name = v;
  }
  public get disabled() {
    return this._data.disabled;
  }
  public set disabled(v) {
    this._data.disabled = v;
  }
  public get ipOrDomain() {
    if (this.disabled) {
      return '';
    }
    return this.domain ? this.domain : this.ip;
  }
  public get nameWithIpOrDomain() {
    return chalk.underline(`${this.name} ${this.ipOrDomain}`);
  }
  toString = () => {
    return `[string version] ${this.nameWithIpOrDomain}`
  }
}

