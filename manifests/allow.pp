define ufw::allow($proto='tcp', $port='all', $ip='', $from='any', $ensure = 'present') {

  $ipadr      = $ip ? {
    ''      => $::ipaddress_eth0 ? {
      undef   => 'any',
      default => $::ipaddress_eth0,
    },
    default => $ip,
  }

  $from_match = $from ? {
    'any'   => 'Anywhere',
    default => "$from",
  }

  case $ensure {
    'present' : {
      exec { "add-ufw-allow-${proto}-from-${from}-to-${ipadr}-port-${port}":
        command => $port ? {
          'all'   => "ufw allow proto $proto from $from to $ipadr",
          default => "ufw allow proto $proto from $from to $ipadr port $port",
        },
        unless  => "$ipadr:$port" ? {
          'any:all'    => "ufw status | grep -E \" +ALLOW +$from_match\"",
          /[0-9]:all$/ => "ufw status | grep -E \"$ipadr/$proto +ALLOW +$from_match\"",
          /^any:[0-9]/ => "ufw status | grep -E \"$port/$proto +ALLOW +$from_match\"",
          default      => "ufw status | grep -E \"$ipadr $port/$proto +ALLOW +$from_match\"",
        },
        require => Exec['ufw-default-deny'],
        before  => Exec['ufw-enable'],
      }
    }
    'absent'  : {
      exec { "delete-ufw-allow-${proto}-from-${from}-to-${ipadr}-port-${port}":
        command => $port ? {
          'all'   => "ufw delete allow proto $proto from $from to $ipadr",
          default => "ufw delete allow proto $proto from $from to $ipadr port $port",
        },
        onlyif  => "$ipadr:$port" ? {
          'any:all'    => "ufw status | grep -E \" +ALLOW +$from_match\"",
          /[0-9]:all$/ => "ufw status | grep -E \"$ipadr/$proto +ALLOW +$from_match\"",
          /^any:[0-9]/ => "ufw status | grep -E \"$port/$proto +ALLOW +$from_match\"",
          default      => "ufw status | grep -E \"$ipadr $port/$proto +ALLOW +$from_match\"",
        },
        require => Exec['ufw-default-deny'],
        before  => Exec['ufw-enable'],
      }
    }
    default   : {
      fail("Unrecognized ensure parameter. Must be 'present' or 'absent'.")
    }
  }

}
