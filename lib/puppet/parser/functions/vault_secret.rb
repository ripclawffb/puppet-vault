# encoding: utf-8
require 'rest-client'
require 'json'

module Puppet::Parser::Functions
  newfunction(:vault_secret, :type => :rvalue, :doc =><<-ENDHEREDOC
  Requirements:

    This function requires that the rest-client and json ruby gems are installed
    on the puppetserver. Since puppet is only compatible with MRI Ruby 1.9.3,
    you will need to use rest-client v1.8.0.

  Documentation:

    This function reads secrets from Hashicorp's Vault.

    When reading a secret, the following arguments must be provided:

    url: the url or the vault server
         valid options: string, default: undefined

    auth: a hash that includes type of authentication and corresponding
          parameters that has access to read/delete secrets in vault
          (see authentication section below)
          valid options: hash, default: undefined

    secret_fqdn: fully qualified secret name which includes mount point
                 valid options: string, default: undefined

  Authentication:

    This function currently supports two types of authentication:

    Token:

      To authenticate via token, just pass in a hash with the type of 'token'
      and the actual token.

      { 'type' => 'token',
        'token => 'c38e2dca-9a61-6ea1-0d2d-397a5d2e2c63' }

    Approle:

      To authenticate via approle, you will need to enable the approle backend
      by running 'vault auth-enable approle'. Once enabled, you can pass in a
      hash with the type of 'approle', role id and secret id.

      { 'type'      => 'approle',
        'role_id'   => '2fab2f1c-afc2-2138-81de-asf11d9f3af0',
        'secret_id' => '2df95cb9-d22c-3816-74db-e6458604384a' }

  Usage:

    To use the function, call it with the parameters listed below:

      vault_secret(url, auth, secret_fqdn)

  Examples:

    To read a secret with the name 'foo' under the mount point secret/ in vault,
    call the function like this (the lines are wrapped for readability):

      vault_secret('read', 'https://vault.example.local:8200', \
                   '{ 'type' => 'token', \
                      'token => 'c38e2dca-9a61-6ea1-0d2d-397a5d2e2c63' }', \
                   'secret/foo')

    ENDHEREDOC
             ) do |args|
    if args.length != 3
      raise(Puppet::ParseError, 'vault_secret(): requires three args: \
        a vault url, vault token, secret fqdn')
    end

    # assign variables
    # url of vault
    vault_addr = args[0].to_s
    # token with access to vault
    vault_auth = args[1]
    # secret fully qualified name
    secret_fqdn = args[2].to_s
    # path of secret
    secret_path = secret_fqdn.split('/', 2).first
    # name of secret
    secret_name = secret_fqdn.split('/', 2).last

    # check to see if vault is sealed
    get_seal_status = RestClient.get(vault_addr + '/v1/sys/seal-status')
    # parse json
    seal_result = JSON.parse(get_seal_status.body)
    # get vault seal status
    seal_status = seal_result['sealed']

    # raise an error if the vault is sealed
    raise(Puppet::ParseError, 'Vault is currently sealed!') if seal_status

    # determine authentication type
    raise(Puppet::ParseError, 'Auth parameter passed is not a hash!') \
      unless vault_auth.instance_of?(Hash)

    # get token based on authentication type specified
    if vault_auth['type'] == 'token'
      # get token from hash
      vault_token = vault_auth['token']
    elsif vault_auth['type'] == 'approle'
      # get role id and secret id from hash
      vault_role_id = vault_auth['role_id']
      vault_secret_id = vault_auth['secret_id']

      # authenticate to vault to get client token
      get_token = RestClient.post(vault_addr + '/v1/auth/approle/login', \
                                  { 'role_id' => vault_role_id, \
                                    'secret_id' => vault_secret_id }.to_json, \
                                  headers={ 'X-Vault-Token' => vault_token, \
                                            'Content-Type' => 'application/json' })

      # parse resulting json
      result = JSON.parse(get_token.body)
      # get token from result
      vault_token = result['auth']['client_token']

    else
      raise(Puppet::ParseError, 'Auth type passed is not supported by this function!')
    end

    # get current secrets
    begin
      list_secrets = RestClient.get(vault_addr + '/v1/' + secret_path + '/?list=true', \
                                    headers={ 'X-Vault-Token' => vault_token })
      list_result = JSON.parse(list_secrets.body)
    rescue RestClient::ResourceNotFound
      check_secret = false
    end

    # check to see if secret already exists
    unless list_result.nil?
      if list_result['data']['keys'].include? secret_name
        check_secret = true
      else
        check_secret = false
      end
    end

    # if secret exists, then go ahead and read the value
    if check_secret
      # get secret
      get_secret = RestClient.get(vault_addr + '/v1/' + secret_path + '/' + secret_name, \
                                  headers={ 'X-Vault-Token' => vault_token })
      secret_result = JSON.parse(get_secret.body)
      secret = secret_result['data']
    else
      # if secret doesn't exist, raise an error
      raise(Puppet::ParseError, "Secret #{secret_path}/#{secret_name} does not exist")
    end

    return secret
  end
end
