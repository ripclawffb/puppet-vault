require 'rest-client'
require 'json'

Puppet::Type.type(:vault_secret).provide(:rest) do
  def exists?
    # split the namevar into secret mount and secret name
    secret_path = resource[:secret_fqdn].split('/', 2).first
    secret_name = resource[:secret_fqdn].split('/', 2).last

    # check to see if vault is sealed
    get_seal_status = RestClient.get(resource[:url] + '/v1/sys/seal-status')
    # parse json
    seal_result = JSON.parse(get_seal_status.body)
    # get vault seal status
    seal_status = seal_result['sealed']

    raise Puppet::Error, 'Vault is currently sealed!' if seal_status

    # get vault authentication token
    vault_token = auth(resource[:auth])

    # get current secrets
    list_secrets = RestClient.get(resource[:url] + '/v1/' + secret_path + '/?list=true', \
                                  headers={ 'X-Vault-Token' => vault_token })
    list_result = JSON.parse(list_secrets.body)

    # check to see if secret already exists
    if list_result['data']['keys'].include? secret_name
      true
    else
      false
    end
  rescue RestClient::ResourceNotFound, NoMethodError => e
    false
  end


  def create
    # get vault authentication token
    vault_token = auth(resource[:auth])

    raise Puppet::Error, 'Secret hash is required!' if resource[:secret].nil?

    RestClient.post(resource[:url] + '/v1/' + resource[:secret_fqdn], \
                    resource[:secret].to_json, \
                    headers={ 'X-Vault-Token' => vault_token, \
                              'Content-Type' => 'application/json' })
  end

  def destroy
    # get vault authentication token
    vault_token = auth(resource[:auth])

    # delete secret
    RestClient.delete(resource[:url] + '/v1/' + resource[:secret_fqdn], \
                      headers={ 'X-Vault-Token' => vault_token })
  end

  def secret
    # get vault authentication token
    vault_token = auth(resource[:auth])

    # get secret
    get_secret = RestClient.get(resource[:url] + '/v1/' + resource[:secret_fqdn], \
                                headers={ 'X-Vault-Token' => vault_token })
    secret_result = JSON.parse(get_secret.body)

    # if update is set to false, return value passed in to ensure value isn't
    # updated
    if resource[:update]
      secret_result['data']
    else
      resource[:secret]
    end
  end

  def secret=(value)
    # get vault authentication token
    vault_token = auth(resource[:auth])

    RestClient.post(resource[:url] + '/v1/' + resource[:secret_fqdn], \
                    resource[:secret].to_json, \
                    headers={ 'X-Vault-Token' => vault_token, \
                              'Content-Type' => 'application/json' })
  end

  def auth(vault_auth)
    # get token based on authentication type specified
    if vault_auth['type'] == 'token'
      # get token from hash
      vault_auth['token']
    elsif vault_auth['type'] == 'approle'
      # get role id and secret id from hash
      vault_role_id = vault_auth['role_id']
      vault_secret_id = vault_auth['secret_id']

      # authenticate to vault to get client token
      get_token = RestClient.post(resource[:url] + '/v1/auth/approle/login', \
                                  { 'role_id' => vault_role_id, \
                                    'secret_id' => vault_secret_id }.to_json, \
                                  headers={ 'X-Vault-Token' => vault_token, \
                                            'Content-Type' => 'application/json' })

      # parse resulting json
      result = JSON.parse(get_token.body)
      # get token from result
      result['auth']['client_token']
    else
      raise Puppet::Error, 'Auth type passed is not supported by this provider!'
    end
  end
end
