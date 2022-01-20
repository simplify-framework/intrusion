// Copyright Joyent, Inc. and other Node contributors.
// - Extacted from https://github.com/nodejs/node/blob/v15.7.0/lib/https.js
// - Modified by DUONG Dinh Cuong for protability purpose (01/2021).
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

const {
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypeShift,
  ArrayPrototypeSplice,
  ArrayPrototypeUnshift,
  JSONStringify,
  ObjectAssign,
  ObjectSetPrototypeOf,
  ReflectConstruct,
} = {
  ArrayPrototypeIndexOf: Array.prototype.indexOf,
  ArrayPrototypePush: Array.prototype.push,
  ArrayPrototypeShift: Array.prototype.shift,
  ArrayPrototypeSplice: Array.prototype.splice,
  ArrayPrototypeUnshift: Array.prototype.unshift,
  JSONStringify: JSON.stringify,
  ObjectAssign: Object.assign,
  ObjectSetPrototypeOf: Object.setPrototypeOf,
  ReflectConstruct: Reflect.construct
}

const tls = require('tls');
const url = require('url');
const { Agent: HttpAgent } = require('_http_agent');
const {
  Server: HttpServer,
  _connectionListener,
  kServerResponse
} = require('_http_server');
const { ClientRequest } = require('_http_client');
let debug = (...args) => { /* console.log(...args) */ }
const searchParamsSymbol = Symbol('query')
const urlToHttpOptions = function (url) {
  const options = {
    protocol: url.protocol,
    hostname: typeof url.hostname === 'string' &&
      StringPrototypeStartsWith(url.hostname, '[') ?
      StringPrototypeSlice(url.hostname, 1, -1) :
      url.hostname,
    hash: url.hash,
    search: url.search,
    pathname: url.pathname,
    path: `${url.pathname || ''}${url.search || ''}`,
    href: url.href
  };
  if (url.port !== '') {
    options.port = Number(url.port);
  }
  if (url.username || url.password) {
    options.auth = `${url.username}:${url.password}`;
  }
  return options;
}
const { IncomingMessage, ServerResponse } = require('http');
const { kIncomingMessage } = require('_http_common');

function Server(opts, requestListener) {
  if (!(this instanceof Server)) return new Server(opts, requestListener);

  if (typeof opts === 'function') {
    requestListener = opts;
    opts = undefined;
  }
  opts = { ...opts };

  if (!opts.ALPNProtocols) {
    // http/1.0 is not defined as Protocol IDs in IANA
    // https://www.iana.org/assignments/tls-extensiontype-values
    //       /tls-extensiontype-values.xhtml#alpn-protocol-ids
    opts.ALPNProtocols = ['http/1.1'];
  }

  this[kIncomingMessage] = opts.IncomingMessage || IncomingMessage;
  this[kServerResponse] = opts.ServerResponse || ServerResponse;

  tls.Server.call(this, opts, _connectionListener);

  this.httpAllowHalfOpen = false;

  if (requestListener) {
    this.addListener('request', requestListener);
  }

  this.addListener('tlsClientError', function addListener(err, conn) {
    if (!this.emit('clientError', err, conn))
      conn.destroy(err);
  });

  this.timeout = 0;
  this.keepAliveTimeout = 5000;
  this.maxHeadersCount = null;
  this.headersTimeout = 60 * 1000; // 60 seconds
  this.requestTimeout = 0;
}
ObjectSetPrototypeOf(Server.prototype, tls.Server.prototype);
ObjectSetPrototypeOf(Server, tls.Server);

Server.prototype.setTimeout = HttpServer.prototype.setTimeout;

function createServer(opts, requestListener) {
  return new Server(opts, requestListener);
}


// HTTPS agents.

function createConnection(port, host, options) {
  if (port !== null && typeof port === 'object') {
    options = port;
  } else if (host !== null && typeof host === 'object') {
    options = { ...host };
  } else if (options === null || typeof options !== 'object') {
    options = {};
  } else {
    options = { ...options };
  }

  if (typeof port === 'number') {
    options.port = port;
  }

  if (typeof host === 'string') {
    options.host = host;
  }

  debug('createConnection', options);

  if (options._agentKey) {
    const session = this._getSession(options._agentKey);
    if (session) {
      debug('reuse session for %j', options._agentKey);
      options = {
        session,
        ...options
      };
    }
  }

  const socket = tls.connect(options);

  if (options._agentKey) {
    // Cache new session for reuse
    socket.on('session', (session) => {
      this._cacheSession(options._agentKey, session);
    });

    // Evict session on error
    socket.once('close', (err) => {
      if (err)
        this._evictSession(options._agentKey);
    });
  }

  return socket;
}


function Agent(options) {
  if (!(this instanceof Agent))
    return new Agent(options);

  HttpAgent.call(this, options);
  this.defaultPort = 443;
  this.protocol = 'https:';
  this.maxCachedSessions = this.options.maxCachedSessions;
  if (this.maxCachedSessions === undefined)
    this.maxCachedSessions = 100;

  this._sessionCache = {
    map: {},
    list: []
  };
}
ObjectSetPrototypeOf(Agent.prototype, HttpAgent.prototype);
ObjectSetPrototypeOf(Agent, HttpAgent);
Agent.prototype.createConnection = createConnection;

Agent.prototype.getName = function getName(options) {
  let name = HttpAgent.prototype.getName.call(this, options);

  name += ':';
  if (options.ca)
    name += options.ca;

  name += ':';
  if (options.cert)
    name += options.cert;

  name += ':';
  if (options.clientCertEngine)
    name += options.clientCertEngine;

  name += ':';
  if (options.ciphers)
    name += options.ciphers;

  name += ':';
  if (options.key)
    name += options.key;

  name += ':';
  if (options.pfx)
    name += options.pfx;

  name += ':';
  if (options.rejectUnauthorized !== undefined)
    name += options.rejectUnauthorized;

  name += ':';
  if (options.servername && options.servername !== options.host)
    name += options.servername;

  name += ':';
  if (options.minVersion)
    name += options.minVersion;

  name += ':';
  if (options.maxVersion)
    name += options.maxVersion;

  name += ':';
  if (options.secureProtocol)
    name += options.secureProtocol;

  name += ':';
  if (options.crl)
    name += options.crl;

  name += ':';
  if (options.honorCipherOrder !== undefined)
    name += options.honorCipherOrder;

  name += ':';
  if (options.ecdhCurve)
    name += options.ecdhCurve;

  name += ':';
  if (options.dhparam)
    name += options.dhparam;

  name += ':';
  if (options.secureOptions !== undefined)
    name += options.secureOptions;

  name += ':';
  if (options.sessionIdContext)
    name += options.sessionIdContext;

  name += ':';
  if (options.sigalgs)
    name += JSONStringify(options.sigalgs);

  name += ':';
  if (options.privateKeyIdentifier)
    name += options.privateKeyIdentifier;

  name += ':';
  if (options.privateKeyEngine)
    name += options.privateKeyEngine;

  return name;
};

Agent.prototype._getSession = function _getSession(key) {
  return this._sessionCache.map[key];
};

Agent.prototype._cacheSession = function _cacheSession(key, session) {
  // Cache is disabled
  if (this.maxCachedSessions === 0)
    return;

  // Fast case - update existing entry
  if (this._sessionCache.map[key]) {
    this._sessionCache.map[key] = session;
    return;
  }

  // Put new entry
  if (this._sessionCache.list.length >= this.maxCachedSessions) {
    const oldKey = ArrayPrototypeShift.call(this._sessionCache.list);
    debug('evicting %j', oldKey);
    delete this._sessionCache.map[oldKey];
  }

  ArrayPrototypePush.call(this._sessionCache.list, key);
  this._sessionCache.map[key] = session;
};

Agent.prototype._evictSession = function _evictSession(key) {
  const index = ArrayPrototypeIndexOf.call(this._sessionCache.list, key);
  if (index === -1)
    return;

  ArrayPrototypeSplice.call(this._sessionCache.list, index, 1);
  delete this._sessionCache.map[key];
};

const globalAgent = new Agent();

let urlWarningEmitted = true;
function request(...args) {
  let options = {};

  if (typeof args[0] === 'string') {
    const urlStr = ArrayPrototypeShift.call(args);
    try {
      options = urlToHttpOptions(new URL(urlStr));
    } catch (err) {
      options = url.parse(urlStr);
      if (!options.hostname) {
        throw err;
      }
      if (!urlWarningEmitted && !process.noDeprecation) {
        urlWarningEmitted = true;
        process.emitWarning(
          `The provided URL ${urlStr} is not a valid URL, and is supported ` +
          'in the https module solely for compatibility.',
          'DeprecationWarning', 'DEP0109');
      }
    }
  } else if (args[0] && args[0][searchParamsSymbol] &&
    args[0][searchParamsSymbol][searchParamsSymbol]) {
    // url.URL instance
    options = urlToHttpOptions(ArrayPrototypeShift.call(args));
  }
  if (args[0] && typeof args[0] !== 'function') {
    options = { ...options, ...ArrayPrototypeShift.call(args) };
  }
  options._defaultAgent = module.exports.globalAgent;
  ArrayPrototypeUnshift.call(args, options);
  return ReflectConstruct(ClientRequest, args);
}

function get(input, options, cb) {
  const req = request(input, options, cb);
  req.end();
  return req;
}

module.exports = {
  Agent,
  globalAgent,
  Server,
  createServer,
  get,
  request
};