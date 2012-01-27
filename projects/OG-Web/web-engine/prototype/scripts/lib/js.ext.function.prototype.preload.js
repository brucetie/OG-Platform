/*
 * @copyright 2011 - present by OpenGamma Inc
 * @license See distribution for license
 */
Function.prototype.preload = function () {
    var method = this,
        merge = function () {
            var self = 'merge', result = {}, key, val, lcv, len = arguments.length;
            for (lcv = 0; lcv < len; lcv += 1) {
                if (typeof arguments[lcv] !== 'object')
                    throw new TypeError(self + ': ' + arguments[lcv] + ' is not an object');
                for (key in arguments[lcv]) {
                    val = arguments[lcv][key];
                    // catch falsey values (which include null, even though its type is object)
                    if (!val) {result[key] = val; continue;}
                    if (typeof val === 'object') { // catch arrays and objects
                        result[key] = val.constructor !== Array ? merge({}, val) : val.slice(); continue;
                    }
                    result[key] = val; // everything else
                }
            }
            return result;
        },
        orig = merge.apply(null, Array.prototype.slice.call(arguments)),
        new_method, key, has = 'hasOwnProperty';
    new_method = function () {
        return arguments.length ? method.call(this, merge.apply(null, Array.prototype.concat.apply([orig], arguments)))
            : method.call(this, orig);
    };
    for (key in method) if (method[has](key)) new_method[key] = method[key];
    return new_method;
};