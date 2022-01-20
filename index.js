"use strict";

const fp = require("fastify-plugin");

// the use of fastify-plugin is required to be able
// to export the decorators to the outer scope

async function plugin(fastify) {
  fastify.decorateRequest("auth", null);

  fastify.addHook("onRequest", async (request) => {
    const authorization = request.cookies.authorization;
    try {
      request.auth = await fastify.crypto.decrypt(authorization);
    } catch (error) {
      request.auth = null;
    }
  });

  function handle(method) {
    return function (path, options, handler) {
      if (typeof options === "function") {
        handler = options;
        options = {};
      }

      fastify[method](
        path,
        options,
        async function authHandler(request, reply) {
          if (!request.auth) {
            return fastify.httpErrors.unauthorized("please login");
          } else {
            return handler(request, reply);
          }
        }
      );
    };
  }

  fastify.decorate("auth", {
    get: handle("get", true),
    push: handle("push", true),
    post: handle("post", true),
    delete: handle("delete", true),
    patch: handle("patch", true),
  });

  fastify.decorateReply("signIn", async function signIn(data, options = {}) {
    const defaults = {
      path: "/",
      maxAge: 60 * 60 * 24, // seconds
      httpOnly: true,
      secure: true,
    };
    options = Object.assign(defaults, options);
    const encrypted = await fastify.crypto.encrypt(data);
    this.setCookie("authorization", encrypted, options);
  });

  fastify.decorateReply("signOut", function signOut() {
    this.clearCookie("authorization");
  });
}

module.exports = fp(plugin, {
  name: "fastify-auth",
  decorators: {
    fastify: ["httpErrors", "crypto"],
    request: ["cookies"],
    reply: ["setCookie", "clearCookie"],
  },
  dependencies: ["fastify-sensible", "fastify-cookie", "fastify-crypto"],
});
