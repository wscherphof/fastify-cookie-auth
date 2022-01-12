'use strict'

const fp = require('fastify-plugin')

// the use of fastify-plugin is required to be able
// to export the decorators to the outer scope

async function plugin(fastify, opts) {
  if (!fastify.httpErrors) {
    fastify.register(require('fastify-sensible'))
  }
  if (!fastify.cookies) {
    fastify.register(require('fastify-cookie'))
  }
  if (!fastify.crypto) {
    fastify.register(require('fastify-crypto'))
  }

  function auth(method, enforce) {
    return function (path, options, handler) {
      if (typeof options === 'function') {
        handler = options
        options = {}
      }
      fastify[method](path, options, async function authHandler(request, reply) {
        async function authorization() {
          const authorization = request.cookies.authorization
          try {
            return await fastify.crypto.decrypt(authorization)
          } catch (error) {
            return null
          }
        }
        if (enforce && !(await authorization())) {
          return fastify.httpErrors.unauthorized('please login')
        } else {
          return handler(request, reply, authorization)
        }
      })
    }
  }

  fastify.decorate('auth', {
    get: auth('get', true),
    push: auth('push', true),
    post: auth('post', true),
    delete: auth('delete', true),
    patch: auth('patch', true),
    optional: {
      get: auth('get'),
      push: auth('push'),
      post: auth('post'),
      delete: auth('delete'),
      patch: auth('patch')
    }
  })

  fastify.decorateReply('signIn', async function signIn(data, options = {}) {
    const defaults = {
      path: '/',
      maxAge: 60 * 60 * 24, // seconds
      httpOnly: true,
      secure: true
    }
    options = Object.assign(defaults, options)
    const encrypted = await fastify.crypto.encrypt(data)
    this.setCookie('authorization', encrypted, options)
  })

  fastify.decorateReply('signOut', function signOut() {
    this.clearCookie('authorization')
  })
}

module.exports = fp(plugin, {
  name: 'fastify-auth'
})
