express = require "express"
Consul  = require "consul"
Xanax   = require "xanax"
Errors  = require "restify-errors"
errify  = require "errify"


unique = (array) ->
  (elem for elem, i in array when (array.indexOf elem) is i)


class TenPlyCrest
  logPrefix: "(TenPlyCrest)"

  email:          null
  domains:        [""]
  consul_addr:    "127.0.0.1"
  tag:            "ssl"
  logger:         console
  healthInterval: 10
  healthTimeout:  2

  storeopts:
    path: "secret/ten-ply/cert"
    challenge_path: "secret/ten-ply/challenge"
    endpoint: "https://vault.service.consul:8200"
    token: process.env.VAULT_TOKEN

  constructor: (@options = {}) ->
    ideally     = errify (err) -> throw err if err
    @[key]      = value for key, value of @options
    @Store      or= require "./models/cert"
    @Challenge  or= require "./models/challenge"
    @[logLevel] = fn for logLevel, fn of @logger
    @_locks     = {}
    @info "initializing"
    throw new Error "administrator email required" unless @email

    @Store::defaults = @certopts
    @Store.on "error", @err or @error
    @Challenge.on "error", @err or @error
    await @register ideally defer()
    await @Store.setup @storeopts, {@email, @account_uri, @keypair, @Flannel, @url}, ideally defer @keypair
    challenge_opts = path: @storeopts.challenge_path, endpoint: @storeopts.endpoint, token: @storeopts.token
    @Challenge.setup challenge_opts, @keypair
    @_watchTimeout = @delay @healthInterval * 3 * 1000, @registerWatch if @tag

  middleware: =>
    @router = express.Router()
    @router.get  "/.well-known", ->
    @router.get  "/.well-known/health", @health
    @router.get  "/.well-known/acme-challenge/:key", @challengeresponse

    xanax = new Xanax Model: @Store
    @router.use xanax.router
    @router

  health: (req, res) -> res.status(200).send "OK"

  challengeresponse: (req, res, next) =>
    ideally = errify next
    {host}  = req.headers
    {key}   = req.params
    @info "received challenge webhook from #{host} for key: #{key}"

    await @Challenge.find host, ideally defer challenge
    unless key is challenge.token
      @err "request for host #{host}, key #{key} does not match saved token #{challenge.token}"
      return next new Errors.NotFoundError
    res.send challenge.response()
    # challenge.remove()

  register: (callback) ->
    @info "registering with Consul for domains: #{@domains}"
    consul = new Consul host: @consul_addr
    website =
      name: "ten-ply-crest"
      id: "ten-ply-crest"
      tags: ("urlprefix-#{domain}/.well-known" for domain in @domains)
      address: @address
      port: @port
      check:
        http: "http://#{@address}:#{@port}/.well-known/health"
        interval: "#{@healthInterval}s"
        timeout: "#{@healthTimeout}s"

    consul.agent.service.register website, callback

  ## has no callback, since auto-retries after errors:
  ## https://github.com/silas/node-consul/blob/42451d97d10f36c1d758af1ef1165523a033f699/lib/watch.js#L108
  registerWatch: ->
    @info "registering with Consul to watch tag: #{@tag}"
    consul = new Consul host: @consul_addr
    @watch = consul.watch method: consul.catalog.service.list
    @watch.on "change", @checkForNewDomainsInServices
    @watch.on "error", @err
    @watch.on "end", => @err "watch ended"

  checkForNewDomainsInServices: (services, res) =>
    @info "service list changed"
    domains = []
    for service, tags of services when @tag in tags
      @info "found new service #{service}"
      await @parseDomainsForService service, tags, defer err, newDomains
      return @err err if err
      domains = domains.concat newDomains if newDomains
    @makeCertFromDomain domain for domain in unique domains
    return

  parseDomainsForService: (service, tags, callback) ->
    @info "parsing domains for service #{service}"
    domains = (match[1] for tag in tags when match = /urlprefix-([^/]+\.[^/]+)/.exec tag)
    unless domains.length
      return @err "unable to parse domains from tags:", tags

    domains = unique domains
    san     = do -> return match[1] for tag in tags when match = /san-(.*)/.exec tag

    if san?
      subject_alt_names = domains.concat san
      domains = [san]

    newDomains = []
    for domain in domains
      await @Store.findPrimary domain, defer _, cert
      unless cert?.cert
        newDomains.push domain
        continue

      if subject_alt_names?.length
        cert.addSANs subject_alt_names
        if diff = cert.diff()
          @info "cert changed values:", diff
          await cert.save defer err, cert
          newDomains.push domain unless err

    @info "new service #{service} needs ssl cert for domains:", newDomains if newDomains.length
    callback err, newDomains

  makeCertFromDomain: (domain, callback) ->
    return (callback or @warn.bind this) "not creating cert, #{domain} is locked" if @locked domain
    @info "creating cert for domain #{domain}"
    ideally = errify callback or @err.bind this
    @lock domain

    await @Store.findPrimary domain, defer _, cert
    unless cert?
      cert =
        id: domain
      cert[key] = value for key in @Store.attributes when @[key]?
      cert = new @Store cert
      await cert.save ideally defer cert

    await cert.register ideally defer()
    await cert.fetchCert ideally defer()
    await cert.save ideally defer cert

    @unlock domain
    callback?()

  lock: (domain) ->
    @_locks[domain] = true
    setTimeout (=> @unlock domain), 60 * 1000

  unlock: (domain) ->
    delete @_locks[domain]

  locked: (domain) ->
    @_locks[domain]

  delay: (timeout, fn) -> setTimeout (fn.bind this), timeout

  ## Account Key Rollover
  ## https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#account-key-roll-over
  rollover: () ->

  ## https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md#deleting-an-account
  deleteAccount: () ->

  renew: () ->

  ## graceful shutdown
  end: (callback = ->) ->
    @info "deregistering from consul"
    ideally = errify callback

    clearTimeout @_watchTimeout if @_watchTimeout
    @watch?.end()
    consul = new Consul host: @consul_addr
    await consul.agent.service.deregister "ten-ply-crest", ideally defer()
    @info "deregistered"
    callback()


module.exports = TenPlyCrest
