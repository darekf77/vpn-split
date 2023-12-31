//#region @backend
// import { Helpers } from 'tnp-helpers';
// import { VpnSplit } from './vpn-split.backend';
// import { EtcHosts, HostForServer } from './models.backend';


// const TO_DELETE = {} as EtcHosts;

// export async function run(args: string[]) {
//   Helpers.clearConsole();
//   const { local }: { local: boolean } = require('minimist')(args);
//   const saveHostInUserFolder = !!local;
//   args = args.join(' ').replace('--local', '').split(' ');

//   const ins = await VpnSplit.Instance({
//     additionalDefaultHosts: TO_DELETE,
//     allowNotSudo: !!saveHostInUserFolder
//   });

//   if (args.join().trim() === '') {
//     await ins.startServer(saveHostInUserFolder);
//   } else {
//     // await ins.startClient(args.split Helpers.urlParse(args.shift()));
//     await ins.startClient(args.map(arg => Helpers.urlParse(arg)));
//   }

//   process.stdin.resume();
// }
//#endregion
