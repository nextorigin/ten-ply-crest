LetsEncrypt = require "./letsencrypt"
VaultModel  = require "./vault"


class Challenge extends VaultModel
  @logPrefix: "(Challenge)"

  @configure "Challenge",
    # "id", # domain
    "type",
    "uri",
    "token"

  @setup: (storeopts, @keypair) ->
    super

  response: -> LetsEncrypt.makeKeyAuth this, @constructor.keypair


module.exports = Challenge
