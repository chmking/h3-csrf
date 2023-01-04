import { createServer } from 'http'
import { createApp, H3Event, readBody, toNodeListener, eventHandler } from 'h3'
import { csrf, Options } from './index'
import request, { Response } from 'supertest'
import 'mocha'
import { expect } from 'chai'

describe('CSRF middleware', () => {
  describe('when a matching CSRF token is sent in the body', () => {
    it('returns success', (done) => {
      const server = createTestServer()
      request(server)
        .get('/')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err)
          const token = res.text
          request(server)
            .post('/login')
            .set('Cookie', cookies(res))
            .send({ _csrf: token })
            .expect(200, done)
        })
    })
  })

  describe('when a matching CSRF token is sent as a query param', () => {
    it('returns success', (done) => {
      const server = createTestServer()
      request(server)
        .get('/')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err)
          const token = res.text
          request(server)
            .post('/login?_csrf=' + encodeURIComponent(token))
            .set('Cookie', cookies(res))
            .expect(200, done)
        })
    })
  })

  describe('when a matching CSRF token is sent in csrf-token header', () => {
    it('returns success', (done) => {
      const server = createTestServer()
      request(server)
        .get('/')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err)
          const token = res.text
          request(server)
            .post('/login')
            .set('Cookie', cookies(res))
            .set('csrf-token', token)
            .expect(200, done)
        })
    })
  })

  describe('when a matching CSRF token is sent in xsrf-token header', () => {
    it('returns success', (done) => {
      const server = createTestServer()
      request(server)
        .get('/')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err)
          const token = res.text
          request(server)
            .post('/login')
            .set('Cookie', cookies(res))
            .set('xsrf-token', token)
            .expect(200, done)
        })
    })
  })

  describe('when a matching CSRF token is sent in x-csrf-token header', () => {
    it('returns success', (done) => {
      const server = createTestServer()
      request(server)
        .get('/')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err)
          const token = res.text
          request(server)
            .post('/login')
            .set('Cookie', cookies(res))
            .set('x-csrf-token', token)
            .expect(200, done)
        })
    })
  })

  describe('when a matching CSRF token is sent in x-xsrf-token header', () => {
    it('returns success', (done) => {
      const server = createTestServer()
      request(server)
        .get('/')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err)
          const token = res.text
          request(server)
            .post('/login')
            .set('Cookie', cookies(res))
            .set('x-xsrf-token', token)
            .expect(200, done)
        })
    })
  })

  describe('when an invalid CSRF token is sent', () => {
    it('returns a 403', (done) => {
      const server = createTestServer()
      request(server)
        .get('/')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err)

          request(server)
            .post('/login')
            .set('Cookie', cookies(res))
            .send({ _csrf: '42' })
            .expect(403)
            .end((err) => {
              if (err) return done(err)
              return done()
            })
        })
    })
  })

  describe('when no CSRF token is sent', () => {
    it('returns a 403', (done) => {
      const server = createTestServer()
      request(server)
        .get('/')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err)

          request(server)
            .post('/login')
            .set('Cookie', cookies(res))
            .send({})
            .expect(403)
            .end((err) => {
              if (err) return done(err)
              return done()
            })
        })
    })
  })

  describe('when the cookie name is configured', () => {
    const server = createTestServer({ cookie: { name: 'foo' } })

    it('returns a cookie with the name', (done) => {
      request(server)
        .get('/')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err)
          const name = cookies(res).split('=')[0]
          expect(name).to.equal('foo')
          return done()
        })
    })

    describe('when a matching CSRF token is sent in the body', () => {
      it('returns success', (done) => {
        request(server)
          .get('/')
          .expect(200)
          .end((err, res) => {
            if (err) return done(err)
            const token = res.text
            request(server)
              .post('/login')
              .set('Cookie', cookies(res))
              .send({ _csrf: token })
              .expect(200, done)
          })
      })
    })

    describe('when an invalid CSRF token is sent', () => {
      it('returns a 403', (done) => {
        const server = createTestServer()
        request(server)
          .get('/')
          .expect(200)
          .end((err, res) => {
            if (err) return done(err)

            request(server)
              .post('/login')
              .set('Cookie', cookies(res))
              .send({ _csrf: '42' })
              .expect(403)
              .end((err) => {
                if (err) return done(err)
                return done()
              })
          })
      })
    })
  })

  describe('when the body is read twice', () => {
    it('does not block', (done) => {
      const app = createApp()
      app.use(eventHandler(csrf()))
      app.use(
        '/login',
        eventHandler(async (event: H3Event) => {
          await readBody(event)
        })
      )
      app.use(
        '/',
        eventHandler((event: H3Event) => {
          return event.node.req.csrfToken()
        })
      )

      const server = createServer(toNodeListener(app))

      request(server)
        .get('/')
        .expect(200)
        .end((err, res) => {
          if (err) return done(err)
          const token = res.text
          request(server)
            .post('/login')
            .set('Cookie', cookies(res))
            .send({ _csrf: token })
            .expect(200)
            .end((err) => {
              if (err) return done(err)
              return done()
            })
        })
    })
  })
})

function cookies(res: Response) {
  return res.headers['set-cookie']
    .map(function (cookies: string) {
      return cookies.split(';')[0]
    })
    .join(';')
}

function createTestServer(options: Options = {}) {
  const app = createApp()
  app.use(eventHandler(csrf(options)))

  // Return the CSRF Token for testing
  app.use(
    '/',
    eventHandler((event: H3Event) => {
      return event.node.req.csrfToken()
    })
  )

  app.use(
    '/login',
    eventHandler(() => 'Login')
  )

  return createServer(toNodeListener(app))
}
