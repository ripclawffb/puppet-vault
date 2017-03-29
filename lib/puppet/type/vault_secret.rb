# lib/puppet/type/vault_secret.rb
require 'uri'

Puppet::Type.newtype(:vault_secret) do
  desc <<-EOT
    Requirements:

      This type/provider requires that the rest-client and json ruby gems
      are installed on the puppetserver. Since puppet is only compatible with
      MRI Ruby 1.9.3, you will need to use rest-client v1.8.0.

    Documentation:

      This puppet type creates, updates or deletes secrets from Hashicorp Vault
      server.

      When using this type, the following parameters are available:

      title: fully qualified secret name which includes mount point
             valid options: string

      ensure: ensures whether the secret is present.
              valid options: 'present', 'absent', default: 'present'

      url: the url or the vault server
           valid options: string, default: undefined

      auth: a hash that includes type of authentication and corresponding
            parameters that has access to read/delete secrets in vault
            (see authentication section below)
            valid options: hash, default: undefined

      secret: a hash that includes the key value pair that you want to
              insert into vault. you can include multiple key value pairs.
              valid options: hash, default: undefined

      update: determines if secret in vault is updated if passed doesn't match
              what is in vault.
              valid options: true, false, default: true

    Authentication:

      This function currently supports two types of authentication:

      Token:

        To authenticate via token, just pass in a hash with the type of 'token'
        and the actual token.

        { 'type' => 'token',
          'token => 'c38e2dca-9a61-6ea1-0d2d-397a5d2e2c63' }

      Approle:

        To authenticate via approle, you will need to enable the approle backend
        by running 'vault auth-enable approle'. Once enabled, create an approle
        with a role_id and secret_id. Ensure the approle has correct permissions
        in the policy applied to the secret mount point you want to create or
        delete secrets from. You can pass in a hash with the type of 'approle',
        role id and secret id.

        { 'type'      => 'approle',
          'role_id'   => '2fab2f1c-afc2-2138-81de-asf11d9f3af0',
          'secret_id' => '2df95cb9-d22c-3816-74db-e6458604384a' }

    Example 1:

    vault_secret { 'secret/foo':
      ensure => present,
      url    => 'http://127.0.0.1:8200',
      auth   => {
        type  => 'token',
        token => 'c38e2dca-9a61-6ea1-0d2d-397a5d2e2c63'
      },
      secret => {
        value1 => 'bar1',
        value2 => 'bar2'
      },
    }

    In this example, a secret called foo will be created under the mount point
    secret/ with two values using the token authentication method.

    Example 2:

    vault_secret { 'secret/foo':
      ensure => present,
      url    => 'http://127.0.0.1:8200',
      auth   => {
        type      => 'approle',
        role_id   => '2fab2f1c-afc2-2138-81de-asf11d9f3af0',
        secret_id => '2df95cb9-d22c-3816-74db-e6458604384a'
      },
      secret => {
        value => fqdn_rand_string(10),
      },
      update => false,
    }

    In this example, a secret called foo with a randomly generated value will be
    created under the mount point secret/ using the approle authentication
    method. Note, the update parameter is set to false, so if the value ever
    changes, it will not update the value in vault. This is added as a
    protection mechanism to ensure secrets are not accidently overwritten.

    Example 3:

    vault_secret { 'secret/foo':
      ensure => absent,
      url    => 'http://127.0.0.1:8200',
      auth   => {
        type      => 'approle',
        role_id   => '2fab2f1c-afc2-2138-81de-asf11d9f3af0',
        secret_id => '2df95cb9-d22c-3816-74db-e6458604384a'
      },
    }

    In this example, the secret foo is deleted from the mount point secret/.

  EOT
  ensurable do
    defaultvalues
    defaultto :present
  end

  newparam(:secret_fqdn, namevar: true) do
    desc 'The fully qualified secret which includes mount point and name.'
  end

  newparam(:update, boolean: true, parent: Puppet::Parameter::Boolean) do
    desc 'Update secret if value passed is different from value in vault.'
    defaultto :true
  end

  newparam(:url) do
    desc 'The url of the secret server.'
    validate do |value|
      unless URI.parse(value).is_a?(URI::HTTP)
        raise ArgumentError, \
              'Invalid url parameter passed, check url format.' \
      end
    end
  end

  newparam(:auth) do
    desc 'The type of authentication and credentials to use.'
    validate do |value|
      unless value.instance_of?(Hash)
        raise ArgumentError, \
              'Invalid authentication parameter passed, requires a hash.' \
      end
    end
  end

  newproperty(:secret) do
    desc 'The value to set or update for the secret'
    validate do |value|
      unless value.instance_of?(Hash)
        raise ArgumentError, \
              'Invalid secret parameter passed, requires a hash.' \
      end
    end
  end
end
