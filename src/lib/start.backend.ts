//#region @backend
import { Helpers } from 'tnp-helpers';
import { VpnSplit } from './vpn-split.backend';
import { EtcHosts, HostForServer } from './models.backend';


const TO_DELETE = {} as EtcHosts;

export async function run(args: string[]) {
  Helpers.clearConsole();
  const ins = await VpnSplit.Instance({ additionalDefaultHosts: TO_DELETE });
  type ArgType = { testModeServerClient: boolean; };
  const opt = Helpers.cliTool.argsFrom<ArgType>(args);
  args = Helpers.cliTool.cleanCommand<ArgType>(args, opt).split(' ');
  if (opt.testModeServerClient) {
    // await ins['testModeServerClient']();
  } else {
    if (args.join().trim() === '') {
      await ins.startServer();
    } else {
      await ins.startClient(Helpers.urlParse(args.shift()));
    }
  }
  process.stdin.resume();
}
//#endregion
