//#region @notForNpm
import { HOST_BACKEND_PORT } from './app.hosts';
//#region @browser
import { NgModule } from '@angular/core';
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-vpn-split',
  template: 'hello from vpn-split',
  styles: [
    `
      body {
        margin: 0px !important;
      }
    `,
  ],
})
export class VpnSplitComponent implements OnInit {
  constructor() {}

  ngOnInit() {}
}

@NgModule({
  imports: [],
  exports: [VpnSplitComponent],
  declarations: [VpnSplitComponent],
  providers: [],
})
export class VpnSplitModule {}
//#endregion

async function start() {
  console.log('hello world');
  console.log('Please start your server on port: ' + HOST_BACKEND_PORT);
}

export default start;

//#endregion
