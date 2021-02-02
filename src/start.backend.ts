//#region @backend
import { URL } from 'url';
import { Helpers } from 'tnp-helpers';
import { VpnSplit } from './vpn-split.backend';
import { EtcHosts, HostForServer } from './models.backend';


const TO_DELETE = {

} as EtcHosts;

export async function run(args: string[]) {
  Helpers.clearConsole();
  const ins = await VpnSplit.Instance(TO_DELETE);
  if (args.join().trim() === '') {
    await ins.server();
  } else {
    await ins.client(Helpers.urlParse(args.shift()));
  }
  process.stdin.resume();
}
//#endregion
