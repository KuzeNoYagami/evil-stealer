const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const jsObfuscator = require('javascript-obfuscator')

if (fs.existsSync(path.join(__dirname, '\\build'))) {
  fs.rmSync(path.join(__dirname, '\\build'), {
    recursive: true,
    force: true
  });
}

const start = Date.now();

const jsObfuscatorOptions = {
  compact: true,
  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 1,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 1,
  // debugProtection: true,
  // debugProtectionInterval: 4000,
  // disableConsoleOutput: true,
  identifierNamesGenerator: 'hexadecimal',
  log: false,
  numbersToExpressions: true,
  renameGlobals: false,
  selfDefending: true,
  simplify: true,
  splitStrings: true,
  splitStringsChunkLength: 5,
  stringArray: true,
  stringArrayCallsTransform: true,
  stringArrayEncoding: ['rc4'],
  stringArrayIndexShift: true,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 5,
  stringArrayWrappersChainedCalls: true,    
  stringArrayWrappersParametersMaxCount: 5,
  stringArrayWrappersType: 'function',
  stringArrayThreshold: 1,
  target: 'node',
  transformObjectKeys: true,
  unicodeEscapeSequence: false
}

let coreCode = fs.readFileSync(path.join(__dirname, 'core.js'), 'utf8')
let configCode = fs.readFileSync(path.join(__dirname, 'config.js'), 'utf8')

runnerCode = jsObfuscator.obfuscate(configCode, jsObfuscatorOptions).getObfuscatedCode()

function encrypt(text, masterkey) {
  const iv = crypto.randomBytes(16)
  const salt = crypto.randomBytes(64)
  const key = crypto.pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512')
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([salt, iv, tag, encrypted]).toString('base64')
}

function decrypt(encdata, masterkey) {
  const bData = Buffer.from(encdata, 'base64')
  const salt = bData.slice(0, 64)
  const iv = bData.slice(64, 80)
  const tag = bData.slice(80, 96)
  const text = bData.slice(96)
  const key = crypto.pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512')
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  const decrypted = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8')
  return decrypted
}

// Get a random encryption secret key
const secret = [...Array(50)].map(() => Math.random().toString(36)[2]).join('')
const key = crypto.createHash('sha256').update(String(secret)).digest('base64').substr(0, 32)

runnerCode = `${coreCode}\n${runnerCode}`

const encrypted = encrypt(runnerCode, key)

runnerCode = `const crypto = require('crypto')
${decrypt.toString()}
const decrypted = decrypt(\`${encrypted}\`, '${key}')
new Function('require', decrypted)(require)`

fs.writeFileSync(path.join(__dirname, 'coreAES.js'), runnerCode, 'utf8')

console.log(`Obfuscated and encrypted with AES-256: (${Date.now() - start} milliseconds)`)