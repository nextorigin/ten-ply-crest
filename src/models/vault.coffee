url       = require "url"
Spine     = require "spine"
Relations = require "spine-relations/async"
Vault     = require "node-vault"
errify    = require "errify"


class VaultModel extends Spine.Model
  @cacheEnabled: true

  @setup: (options) ->
    @path  = options.path
    @path += "/" unless @path[-1..] is "/"
    @vault = new Vault options

  @find: (id, callback) ->
    ideally = errify callback
    # if lease is still valid and we use cache, use cached
    if @cacheEnabled
      record = @findCached id
      if record and not record.lease_expired()
        return callback null, record

    path = url.resolve @path, id
    await @vault.read path, ideally defer result

    attrs               = result.data
    attrs.id            = id
    lease_expires       = new Date Date.now() + result.lease_duration * 1000
    attrs.lease_expires = lease_expires.toUTCString()
    [record]            = @refresh attrs
    callback null, record

  ## @findCached() is available thanks to spine-relations import
  # @findCached: -> Spine.Model.find.apply this, arguments

  # @findAll: (callback) ->
  #   be able to load all on init? or only lazy-load

  @findByAttribute: (name, value, callback) ->
    return @find value, callback if name is "id"
    return callback "not implemented"

  save: (callback) ->
    ideally = errify callback
    path    = url.resolve @constructor.path, @id
    await @constructor.vault.write path, @attributes(), ideally defer result
    super
    callback null, this

  remove: (callback) ->
    ideally = errify callback
    path    = url.resolve @constructor.path, @id
    await @constructor.vault.delete path, ideally defer result
    super
    callback null, this

  lease_expired: ->
    @lease_expires and Date.now() > (new Date @lease_expires).getTime()

  ## .diff() is available thanks to spine-relations import
  # diff: ->


module.exports = VaultModel
