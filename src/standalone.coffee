TenPlyServer = require "./server.coffee"


api = new TenPlyServer()
await api.register defer err
if err
  console.error err
  process.exit 1

api.listen()
