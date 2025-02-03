import { _, chalk } from 'tnp-core/src';
import { Helpers } from 'tnp-helpers/src';

/***
 * @deprecated
 * use normal objects
 */
export type EtcHosts = { [hostName in string]: HostForServer };

/***
 * @deprecated
 * use normal objects
 */
export type IEtcHosts = {
  [hostName in string]: Partial<
    Pick<HostForServer, 'aliases' | 'ipOrDomain' | 'environmentName'>
  >;
};

export interface OptHostForServer {
  ip?: string;
  domain?: string;
  ipOrDomain?: string;
  environmentName?: string;
  aliases?: string[];
  isDefault?: boolean;
  /**
   * ip from command: vpn-cli 192.168.1.1 192.168.1.2
   */
  originHostname?: string;
  name?: string;
  /**
   * if true - ip and domain will output empty string
   */
  disabled?: boolean;
}

export class HostForServer implements OptHostForServer {
  private _data: OptHostForServer;

  public clone() {
    return HostForServer.From(this);
  }

  static From(
    ipOrDomain:
      | string
      | URL
      | Pick<
          OptHostForServer | HostForServer,
          'ipOrDomain' | 'aliases' | 'originHostname'
        >,
    name = '',
    disabled = false,
  ): HostForServer {
    if (!ipOrDomain) {
      return void 0;
    }
    if (_.isObject(ipOrDomain) && ipOrDomain instanceof HostForServer) {
      const dataClone = _.cloneDeep(ipOrDomain._data) as OptHostForServer;
      dataClone.name = name && name.trim() !== '' ? name : dataClone.name;
      if (!_.isBoolean(dataClone.disabled)) {
        dataClone.disabled = disabled;
      }
      return new HostForServer(dataClone);
    }
    if (_.isString(ipOrDomain)) {
      // @ts-ignore
      const parsed = Helpers.urlParse(ipOrDomain);
      if (parsed) {
        ipOrDomain = parsed as any;
      }
    }

    if (_.isObject(ipOrDomain) && ipOrDomain instanceof URL) {
      ipOrDomain = ipOrDomain as URL; // @ts-ignore
      if (Helpers.isValidIp(ipOrDomain?.host)) {
        return new HostForServer({ ip: ipOrDomain.origin, name, disabled });
      } else {
        return new HostForServer({ domain: ipOrDomain.origin, name, disabled });
      }
    } else {
      if (_.isString(ipOrDomain)) {
        return new HostForServer({ ipOrDomain, name, disabled });
      } else {
        (ipOrDomain as OptHostForServer).name =
          name && name.trim() !== ''
            ? name
            : (ipOrDomain as OptHostForServer).name;
        if (!_.isBoolean((ipOrDomain as OptHostForServer).disabled)) {
          (ipOrDomain as OptHostForServer).disabled = disabled;
        }
        return new HostForServer(ipOrDomain as any);
      }
    }
  }
  constructor(data: OptHostForServer) {
    if (data?.ipOrDomain) {
      // @ts-ignore
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
      // @ts-ignore
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
  public set ip(newIpAddress: string) {
    this._data.ip = newIpAddress;
  }
  public get domain() {
    if (this.disabled) {
      return '';
    }
    return this._data.domain;
  }

  public get aliases(): string[] {
    if (this.disabled) {
      return [];
    }
    if (_.isString(this._data.aliases)) {
      return this._data.aliases.split(' ');
    }
    if (!_.isArray(this._data.aliases)) {
      return [];
    }
    return this._data.aliases;
  }

  public get firstAlias() {
    return _.first(this.aliases);
  }

  public get name() {
    return this._data.name;
  }
  public set name(v) {
    this._data.name = v;
  }

  public get originHostname() {
    return this._data.originHostname;
  }
  public set originHostname(v) {
    this._data.originHostname = v;
  }

  public get disabled() {
    return this._data.disabled;
  }
  public get isDefault() {
    return this._data.isDefault;
  }
  public get identifier() {
    return _.kebabCase(this._data.name);
  }
  public set disabled(v) {
    this._data.disabled = v;
  }
  public get environmentName() {
    return this._data.environmentName || '';
  }
  public get ipOrDomain() {
    if (this.disabled) {
      return '';
    }
    const res = (this.domain ? this.domain : this.ip) || '';
    return res;
    // return res.startsWith('http') ? res : `http://${res}`;
  }

  public get ipOrFirstAlias() {
    if (this.disabled) {
      return '';
    }
    const res = (this.firstAlias ? this.firstAlias : this.ip) || '';
    return res;
    // return res.startsWith('http') ? res : `http://${res}`;
  }

  public get hostname() {
    // @ts-ignore
    const h = Helpers.urlParse(this.ipOrFirstAlias, true);
    return h ? h.hostname : void 0;
  }

  public get hostnameFirstAlias() {
    // @ts-ignore
    const h = Helpers.urlParse(this.firstAlias, true);
    return h ? h.hostname : void 0;
  }

  public get hostnameIp() {
    // @ts-ignore
    const h = Helpers.urlParse(this.ip);
    return h ? h.hostname : void 0;
  }

  public get nameWithIpOrDomain() {
    return chalk.underline(`${this.name} ${this.ipOrDomain}`);
  }
  toString = () => {
    return `[string version] ${this.nameWithIpOrDomain}`;
  };
}
