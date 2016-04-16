util        = require "util"
Vault       = require "node-vault"
Flannel     = require "flannel"
errify      = require "errify"
LetsEncrypt = require "./letsencrypt"
Challenge   = require "./challenge"
VaultModel  = require "./vault"


unique = (array) ->
  (elem for elem, i in array when (array.indexOf elem) is i)


class KeyPair
  @logPrefix: "(KeyPair)"

  @path: "secret/ten-ply/keypair"

  @setup: ({@storeopts, @Flannel}) ->
    @Flannel.shirt this
    @info "initializing"

  @load: (callback) ->
    ideally = errify callback
    vault = new Vault @storeopts
    @debug "loading"
    await vault.read @path, defer err, result

    if (keypair = result?.data) and keypair.publicKey
      keypair =
        publicKey:  new Buffer(keypair.publicKey)
        privateKey: new Buffer(keypair.privateKey)

    else
      @warn "no keypair found, creating"
      await @create ideally defer keypair
      keypairStrings =
        publicKey:  keypair.publicKey.toString()
        privateKey: keypair.privateKey.toString()

      await vault.write @path, keypairStrings, ideally defer()
      @info "new keypair stored in vault"

    callback null, keypair

  @create: (callback) ->
    keypair = LetsEncrypt.createKeypair()
    callback null, keypair


class Cert extends VaultModel
  @logPrefix: "(Cert)"

  @configure "Cert",
    # "id", # domain
    "domain", # helper fn
    "country",
    "country_short",
    "locality",
    "organization",
    "organization_short",
    "password",
    "unstructured",
    "subject_alt_names",
    "cert",
    "key",
    "ciphers",
    "lease_expires",
    # "renewing" # timestamp for when we last started renewing, false if not renewing. so we don't double up on a slow renew

    "parent_id" # if this is a san, it will have a parent cert

    # Optional
    # npn: [ ... ]
    # ticket_key: ""

  @belongsTo Cert, "parent", "parent_id"
  @hasOne Challenge, "challenge", "id"

  @setup: (storeopts, {@email, @keypair, @account_uri, @Flannel, @url}, callback) ->
    @Flannel or= Flannel.init Console: level: "debug"
    @Flannel.shirt this
    @info "initializing"

    ideally = errify callback
    unless @keypair?
      @warn "no keypair found, loading from backend"
      KeyPair.setup {storeopts, @Flannel}
      await KeyPair.load ideally defer @keypair
    @le = new LetsEncrypt {@keypair, @Flannel, @url}
    await @le.setup ideally defer()
    super
    await @setupAccount ideally defer()
    callback null, @keypair

  @setupAccount: (callback = ->) ->
    @info "setting up Let's Encrypt account for #{@email}"
    ideally = errify callback
    unless @account_url
      await @le.createAccount @email, ideally defer @account_uri
      @info "account URI for #{@email}: #{@account_uri}"
    await @le.getTosLink @account_uri, ideally defer link
    await @le.agreeToTos @account_uri, link, ideally defer()
    callback()

  @findPrimary: (id, callback) ->
    ideally = errify callback

    await @find id, ideally defer record
    await record.parent defer _, parent
    return callback null, parent if parent
    callback null, record

  constructor: (attributes) ->
    attributes = util._extend (util._extend {}, @defaults), attributes if @defaults
    super attributes

  domain: -> @id

  addSANs: (subject_alt_names) ->
    @subject_alt_names or= []
    @subject_alt_names.concat subject_alt_names
    @subject_alt_names = unique subject_alt_names.sort()

  register: (callback) ->
    @constructor.info "registering domain #{@id}"
    return callback err if err = @validate()
    ideally = errify callback

    await @constructor.le.authorize @id, ideally defer challenge, validation_location
    await @constructor.le.acceptChallenge challenge, ideally defer()
    await @challenge challenge, ideally defer()
    await @constructor.le.waitForValidation validation_location, ideally defer()

    for name in @subject_alt_names? and @subject_alt_names when name isnt @id
      await @constructor.find name, ideally defer child
      await child.register ideally defer()

    callback()

  fetchCert: (callback) ->
    @constructor.info "fetching cert for #{@id}"
    ideally = errify callback
    {csr, privateKey} = @constructor.le.signedCsr @attributes()

    await @constructor.le.requestSigning csr, @id, ideally defer poll_location
    await @constructor.le.waitForCert poll_location, ideally defer @cert

    @constructor.info "acquired cert for #{@id}"
    @key = privateKey.toString()
    callback null, @cert

  save: (callback) ->
    ideally = errify callback
    for name in @subject_alt_names? and @subject_alt_names when name isnt @id
      child = new @constructor id: name, parent_id: @id
      await child.save ideally defer()
    super

  ## https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#certificate-revocation
  ## POST to resource "revoke-cert"
  # remove: ->


module.exports = Cert
