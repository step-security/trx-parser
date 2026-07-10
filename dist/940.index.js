"use strict";
exports.id = 940;
exports.ids = [940];
exports.modules = {

/***/ 77940:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getMachineId = void 0;
const api_1 = __webpack_require__(63914);
async function getMachineId() {
    api_1.diag.debug('could not read machine-id: unsupported platform');
    return undefined;
}
exports.getMachineId = getMachineId;
//# sourceMappingURL=getMachineId-unsupported.js.map

/***/ })

};
;
//# sourceMappingURL=940.index.js.map