// Curated snapshot of well-known typosquats and confused-package names.
// Source: snyk advisories, npm/pypi removed-package lists, security blogs.
// Map of suspected → canonical so the finding can suggest the fix.
export const TYPOSQUATS: ReadonlyMap<string, string> = new Map([
  // npm
  ['lodass', 'lodash'],
  ['lodassh', 'lodash'],
  ['lodashs', 'lodash'],
  ['expresss', 'express'],
  ['cross-env-shell', 'cross-env'],
  ['discord.dll', 'discord.js'],
  ['noblox.js-proxy', 'noblox.js'],
  ['mongoose-mock', 'mongoose'],
  ['axios-proxy', 'axios'],
  ['react-native-google-pay', 'react-native-google-pay'],
  ['electron-native-notify', 'node-notifier'],
  ['twilio-npm', 'twilio'],
  ['rgb-css-color', 'color'],
  // pypi
  ['djanga', 'django'],
  ['urllib', 'urllib3'],
  ['python-sqlite', 'sqlite3'],
  ['python-mysql', 'mysql-connector-python'],
  ['crypt', 'cryptography'],
  ['python3-dateutil', 'python-dateutil'],
  ['jeIlyfish', 'jellyfish'], // capital I instead of l
  ['colourama', 'colorama'],
  ['python-openssl', 'pyopenssl'],
  // ruby
  ['atlas_client', 'atlas-client'],
  ['rest-clients', 'rest-client'],
]);
