//#region @backend
import { URL } from 'url';
import { Helpers } from 'tnp-helpers';
import { VpnSplit } from './vpn-split.backend';

export async function run(args: string[]) {
  const ins = await VpnSplit.Instance();
  const command: 'server' | 'client' = args.shift() as any;
  if (command === 'server') {
    Helpers.clearConsole();
    await ins.server();
  }
  if (command === 'client') {
    await ins.client();
  }
  process.stdin.resume();
}
//#endregion
