# H3 CSRF

Node.js [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) protection middleware for H3.

## Installation

This is a [Node.js](https://nodejs.org/en/) module available through the
[npm registry](https://www.npmjs.com/). Installation is done using the
[`npm install` command](https://docs.npmjs.com/getting-started/installing-npm-packages-locally):

```sh
$ npm install @chmking/h3-csrf
```

## Usage

The CSRF protection middleware is added to H3 as a priority to inject `csrfToken()` in the `event`:

```js
import { createServer } from 'http'
import { createApp } from 'h3'
import { csurf } from '@chmking/h3-csrf'

const app = createApp()
app.use(csurf())

const server = createServer(app)
```

Further down the layers, the token can be retrieved from the `event`:

```js
handler(event: CompatibilityEvent) => {
    const token = event.req.csrfToken()
}
```

### csurf([options])

Creates a middleware for token creation an validation. The middleare injects `event.req.csrfToken()` function to make a token which should be added to requests which mutate the state. This token it validated against the visitor's csrf cookie.

### Options

The `csurf` function takes an optional `Options` object that may contain the following keys:

#### verifiedMehtods?: Array\<HTTPMethod\>

A list of HTTP methods that will be verified by the CSRF middleware. Only the server endpoints corresponding to these methods will be verified.

Defaults:
```js
['PATCH', 'POST', 'PUT', 'DELETE']
```

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.