//#region @backend
import { URL } from 'url';
import { Helpers } from 'tnp-helpers';
import { VpnSplit } from './vpn-split.backend';
import { EtcHosts, HostForServer } from './models.backend';


const TO_DELETE = {
  'JIRA igt': HostForServer.From({
    ipOrDomain: '10.253.160.66',
    aliases: 'jira.gtech.com',
  }),
  'GITLAB igt': HostForServer.From({
    ipOrDomain: '10.253.164.121',
    aliases: 'xxgit1.gtech.com'
  }),
  'NPM server igt': HostForServer.From({
    ipOrDomain: '10.253.164.39',
    aliases: 'xxnpm'
  }),
  'product baseline server from navigator FE': HostForServer.From({
    ipOrDomain: '10.17.21.209',
    aliases: 'xxa311314'
  })
} as EtcHosts;

export async function run(args: string[]) {
  Helpers.clearConsole();
  const ins = await VpnSplit.Instance({ additionalDefaultHosts: TO_DELETE });
  type ArgType = { testModeServerClient: boolean; };
  const opt = Helpers.cliTool.argsFrom<ArgType>(args);
  args = Helpers.cliTool.cleanCommand<ArgType>(args, opt).split(' ');
  if (opt.testModeServerClient) {
    await ins['testModeServerClient']();
  } else {
    if (args.join().trim() === '') {
      await ins.server();
    } else {
      await ins.client(Helpers.urlParse(args.shift()));
    }
  }
  process.stdin.resume();
}
//#endregion
