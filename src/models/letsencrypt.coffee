Acme    = require "rawacme"
Keygen  = require "rsa-keygen"
Forge   = require "node-forge"
Flannel = require "flannel"
errify  = require "errify"


class LetsEncrypt
  logPrefix: "(LetsEncrypt)"

  @createKeypair: (bit = 2048) ->
    result = Keygen.generate bit
    keypair =
      publicKey:  result.public_key
      privateKey: result.private_key

  constructor: ({@keypair, @url, @Flannel}) ->
    @Flannel or= Flannel.init Console: level: "debug"
    @Flannel.shirt this
    @info "initializing"

    @url   = Acme.LETSENCRYPT_URL if @url is "production"
    @url or= Acme.LETSENCRYPT_STAGING_URL

  setup: (callback) ->
    @info "setting up"
    ideally = errify callback

    await Acme.createClient {@url}, ideally defer @acme
    callback()

  createAccount: (emails, callback) ->
    @info "creating account for #{emails}"
    ideally = errify callback

    emails  = [emails] unless Array.isArray emails
    mailto  = ("mailto:#{email}" for email in emails)
    await @acme.newReg {contact: mailto}, @keypair, ideally defer {headers}
    ## might return 409 for a duplicate reg, but will still send location header
    ## https://github.com/letsencrypt/boulder/issues/1135
    err = "did not receive location" unless {location} = headers
    callback err, location

  getReg: (location, body = {}, callback) ->
    ideally = errify callback
    body.resource = "reg"
    await @acme.post location, body, @keypair, ideally defer res
    callback null, res

  getAccount: (location, callback) ->
    @info "getting account for #{location}"
    ideally = errify callback

    await @getReg location, null, ideally defer {body}
    callback null, body

  getTosLink: (location, callback) ->
    @info "getting TOS link for #{location}"
    ideally = errify callback
    await @getReg location, null, ideally defer {headers}
    err = "did not receive link" unless {link} = headers

    ## comes in format:
    ## <http://...>; rel=next, <http://...>; rel=...,
    [next, tos] = link.split ","
    [str, rel]  = tos.split ";"
    url = (str.split ";")[0].trim().replace /[<>]/g, ""
    callback err, url

  agreeToTos: (location, link, callback) ->
    @info "agreeing to tos at #{link}"
    @getReg location, {Agreement: link}, callback

  authorize: (domain, callback) ->
    @info "authorizing #{domain}"
    ideally = errify callback

    await @acme.newAuthz (@makeAuthRequest domain), @keypair, ideally defer {body, headers}
    return callback "did not receive location" unless {location} = headers

    {challenges} = body
    return callback "did not receive challenges" unless challenges

    preferred    = "http-01"
    selected     = challenge for challenge in challenges when challenge.type is preferred
    unless selected? then return callback "unable to select preferred challenge: #{preferred}"
    callback null, selected, location
    # selected has both token and uri

  makeAuthRequest: (domain) ->
    identifier:
      type:  "dns"
      value: domain

  acceptChallenge: (challenge, callback) ->
    @info "accepting challenge to #{challenge.uri}"
    ideally = errify callback

    await @acme.post challenge.uri, (@makeChallengeResponse challenge), @keypair, ideally defer {body}
    callback null, body

  makeChallengeResponse: (challenge) ->
    LetsEncrypt.makeChallengeResponse challenge, @keypair

  makeKeyAuth: (challenge) ->
    LetsEncrypt.makeKeyAuth challenge, @keypair

  @makeChallengeResponse: (challenge, keypair) ->
    resource: "challenge"
    keyAuthorization: @makeKeyAuth challenge, keypair

  @makeKeyAuth: (challenge, keypair) ->
    Acme.keyAuthz challenge.token, keypair.publicKey

  waitForValidation: (location, callback) ->
    @info "waiting for validation from #{location}"
    ideally = errify callback

    getValidation = (multiplier = 1) =>
      callback "retries exceeded" if multiplier > 128
      @info "polling for validation from #{location}"
      await @acme.get location, @keypair, ideally defer {body}
      {status} = body? and body
      if status is "pending"
        return setTimeout (-> getValidation multiplier * 2), multiplier * 500
      return callback (new Error status), body unless status is "valid"
      @info "validated #{location}"
      callback null, body
    getValidation()

  signedCsr: ({bit, key, domain, country, country_short, locality, organization, organization_short, password, unstructured, subject_alt_names}) ->
    if key
      privateKey = key
    else
      bit or= 2048
      {publicKey, privateKey} = LetsEncrypt.createKeypair bit

    forge_privateKey   = Forge.pki.privateKeyFromPem privateKey
    publicKey        or= Forge.pki.publicKeyToPem Forge.pki.setRsaPublicKey forge_privateKey.n, forge_privateKey.e

    csr = @createCsr {publicKey, domain, country, country_short, locality, organization, organization_short, password, unstructured, subject_alt_names}
    csr.sign forge_privateKey
    csr.verify()
    {csr, publicKey, privateKey}

  createCsr: ({publicKey, domain, country, country_short, locality, organization, organization_short, password, unstructured, subject_alt_names}) ->
    csr = Forge.pki.createCertificationRequest()
    csr.publicKey = Forge.pki.publicKeyFromPem publicKey
    potential = [
      {name: "commonName", value: domain},
      {name: "countryName", value: country},
      {shortName: "ST", value: country_short},
      {name: "localityName", value: locality},
      {name: "organizationName", value: organization},
      {shortName: "OU", value: organization_short}
    ]
    actual = (pair for pair in potential when pair.value?)
    csr.setSubject actual

    optional = [
      {name: "challengePassword", value: password}
      {name: "unstructuredName", value: unstructured}
    ]
    attributes = (pair for pair in optional when pair.value?)
    if subject_alt_names
      extensions = [
        name: "subjectAltName"
        altNames: ({type: 2, value: alt_name} for alt_name in subject_alt_names)
      ]
      attributes.push {name: "extensionRequest", extensions}
    csr.setAttributes attributes if attributes.length

    csr

  requestSigning: (csr, domain, callback) ->
    @info "requesting signing for #{domain}"
    ideally = errify callback

    await @acme.newCert (@makeCertRequest csr, 90), @keypair, ideally defer {headers}
    err = "did not receive location" unless {location} = headers
    callback err, location

  makeCertRequest: (csr, days = 90) ->
    now   = new Date
    later = new Date
    later.setDate now.getDate() + days

    csr:       Acme.base64.encode Acme.toDer Forge.pki.certificationRequestToPem csr
    notBefore: now.toISOString()
    notAfter:  later.toISOString()

  waitForCert: (location, callback) ->
    @info "waiting for cert from #{location}"
    ideally = errify callback

    getCert = (multiplier = 1) =>
      callback "retries exceeded" if multiplier > 128
      @info "polling for cert from #{location}"
      await @acme.get location, @keypair, ideally defer {body}
      unless body?
        return setTimeout (-> getCert multiplier * 2), multiplier * 500
      cert = Acme.fromDer "CERTIFICATE", body
      @info "retrieved cert from #{location}"
      callback null, cert
    getCert()


module.exports = LetsEncrypt
