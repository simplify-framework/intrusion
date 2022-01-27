/**
 * Created by Ralph Varjabedian on 11/11/14.
 * require-hook is licensed under the [MIT]
 * do not remove this notice.
 */

console.require_hook = {};

console.require_hook.log = function() {
  console.log.apply(this, ["[require-hook]"].concat(Array.prototype.slice.call(arguments, 0)));
};

console.require_hook.warn = function() {
  console.warn.apply(this, ["[require-hook]"].concat(Array.prototype.slice.call(arguments, 0)));
};

module.exports = require("./lib/requireHook.js");