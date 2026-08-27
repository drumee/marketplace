# Drumee Marketplace — Office integration

A [Drumee](https://drumee.com) server plugin that wires external document
editors into the Drumee meta filesystem, so office documents open and save in
place from a Drumee workspace.

## What it provides

| Service | ACL | Editor |
|---|---|---|
| `onlyoffice` | `acl/onlyoffice.json` | ONLYOFFICE Document Server |
| `euroffice` | `acl/euroffice.json` | EurOffice |

Each service declares its callable endpoints in `acl/` and implements them in
`service/`. Templates used when creating a new document live in
`service/templates/`.

## Running it

This is a plugin: it runs inside a Drumee server runtime rather than on its own.

```console
npm install
npm run register-plugin     # register with the local Drumee runtime
npm run dev                 # development mode
npm run deploy              # build and deploy
npm run remove-plugin       # unregister
```

To get a runtime to develop against, follow the
[getting-started guides](https://docs.drumee.com/getting-started).

## Built on

[`@drumee/server-core`](https://github.com/drumee/server-core) and
[`@drumee/server-essentials`](https://github.com/drumee/server-essentials).

## Contributing

See the org [CONTRIBUTING guide](https://github.com/drumee/.github/blob/main/CONTRIBUTING.md).
Questions: [Discussions](https://github.com/orgs/drumee/discussions).

## License

Apache-2.0 — see [LICENSE](LICENSE).
