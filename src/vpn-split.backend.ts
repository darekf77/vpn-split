//#region imports
import * as _ from 'lodash';
import * as path from 'path';
import { Helpers, Project } from 'tnp-helpers';
import { URL } from 'url';
import { config } from 'tnp-config';
import * as moment from 'moment';
import { talkback, Options, RecordMode } from 'ng-talkback';
import * as glob from 'glob';
import chalk from 'chalk';
import * as inquirer from 'inquirer';
import { Models } from 'tnp-models';
import { Hostile } from './hostile.backend';
//#endregion


export class VpnSplit {

  readonly hostile: Hostile;

  //#region singleton
  private static _instances = {};
  private constructor() {
    this.hostile = new Hostile();
  }
  public static Instance() {
    const cwd = process.cwd()
    if (!VpnSplit._instances[cwd]) {
      VpnSplit._instances[cwd] = new VpnSplit();
    }
    return VpnSplit._instances[cwd] as VpnSplit;
  }
  //#endregion

  async server() {
    this.hostile.list();
  }

  async client() {

  }

}
