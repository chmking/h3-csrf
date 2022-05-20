import { createServer } from "http";
import { createApp, CompatibilityEvent } from "h3";
import { csurf } from "./index";
import request, { Response } from "supertest";
import "mocha";

describe("CSRF middleware", () => {
  describe("when a matching CSRF token is sent in the body", () => {
    it("returns success", (done) => {
      const server = createTestServer();
      request(server)
        .get("/")
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          const token = res.text;
          request(server)
            .post("/login")
            .set("Cookie", cookies(res))
            .send({ _csrf: token })
            .expect(200, done);
        });
    });
  });

  describe("when a matching CSRF token is sent as a query param", () => {
    it("returns success", (done) => {
      const server = createTestServer();
      request(server)
        .get("/")
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          const token = res.text;
          request(server)
            .post("/login?_csrf=" + encodeURIComponent(token))
            .set("Cookie", cookies(res))
            .expect(200, done);
        });
    });
  });

  describe("when a matching CSRF token is sent in csrf-token header", () => {
    it("returns success", (done) => {
      const server = createTestServer();
      request(server)
        .get("/")
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          const token = res.text;
          request(server)
            .post("/login")
            .set("Cookie", cookies(res))
            .set("csrf-token", token)
            .expect(200, done);
        });
    });
  });

  describe("when a matching CSRF token is sent in xsrf-token header", () => {
    it("returns success", (done) => {
      const server = createTestServer();
      request(server)
        .get("/")
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          const token = res.text;
          request(server)
            .post("/login")
            .set("Cookie", cookies(res))
            .set("xsrf-token", token)
            .expect(200, done);
        });
    });
  });

  describe("when a matching CSRF token is sent in x-csrf-token header", () => {
    it("returns success", (done) => {
      const server = createTestServer();
      request(server)
        .get("/")
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          const token = res.text;
          request(server)
            .post("/login")
            .set("Cookie", cookies(res))
            .set("x-csrf-token", token)
            .expect(200, done);
        });
    });
  });

  describe("when a matching CSRF token is sent in x-xsrf-token header", () => {
    it("returns success", (done) => {
      const server = createTestServer();
      request(server)
        .get("/")
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          const token = res.text;
          request(server)
            .post("/login")
            .set("Cookie", cookies(res))
            .set("x-xsrf-token", token)
            .expect(200, done);
        });
    });
  });

  describe("when an invalid CSRF token is sent", () => {
    it("returns a 403", (done) => {
      const server = createTestServer();
      request(server)
        .get("/")
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);

          request(server)
            .post("/login")
            .set("Cookie", cookies(res))
            .send({ _csrf: "42" })
            .expect(403)
            .end((err) => {
              if (err) return done(err);
              return done();
            });
        });
    });
  });

  describe("when no CSRF token is sent", () => {
    it("returns a 403", (done) => {
      const server = createTestServer();
      request(server)
        .get("/")
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);

          request(server)
            .post("/login")
            .set("Cookie", cookies(res))
            .send({})
            .expect(403)
            .end((err) => {
              if (err) return done(err);
              return done();
            });
        });
    });
  });
});

function cookies(res: Response) {
  return res.headers["set-cookie"]
    .map(function (cookies: string) {
      return cookies.split(";")[0];
    })
    .join(";");
}

function createTestServer() {
  const app = createApp();
  app.use(csurf());

  // Return the CSRF Token for testing
  app.use("/", (event: CompatibilityEvent) => {
    return event.req.csrfToken();
  });

  app.use("/login", () => "Login");

  return createServer(app);
}
