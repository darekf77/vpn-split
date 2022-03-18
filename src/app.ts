//#region @notForNpm
//#region @browser
    import { NgModule } from '@angular/core';
    import { Component, OnInit } from '@angular/core';

    @Component({
      selector: 'app-vpn-split',
      template: 'hello from vpn-split'
    })
    export class $ { componentName } implements OnInit {
      constructor() { }

      ngOnInit() { }
    }

    @NgModule({
      imports: [],
      exports: [VpnSplitComponent],
      declarations: [VpnSplitComponent],
      providers: [],
    })
    export class $ { moduleName } { }
    //#endregion

    //#region @backend
    async function start(port: number) {

    }

    export default start;

//#endregion

//#endregion