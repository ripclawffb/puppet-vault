# an example of using the vault_secret type to create a secret in vault
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

# an example of using the vault_secret function to read a secret from vault
$vault_auth = {
  type  => 'token',
  token => 'c38e2dca-9a61-6ea1-0d2d-397a5d2e2c63'
}

$vault_read = vault_secret('http://127.0.0.1:8200', $vault_auth, 'secret/foo')

notify{'read_secret_foo':
  message => $vault_read,
}
