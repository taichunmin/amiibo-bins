import _ from 'lodash'
import { cp, mkdir, readFile, writeFile } from 'node:fs/promises'
import axios from 'axios'
import CryptoJS from 'crypto-js'
import fg from 'fast-glob'
import jsyaml from 'js-yaml'
import Packet from 'pn532.js/Packet.js'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const basedir = new URL('./', import.meta.url)
const distDir = new URL('./dist/', import.meta.url)
const srcDir = new URL('./amiibos/', import.meta.url)
const baseurl = _.trimEnd(getenv('BASEURL', 'https://taichunmin.idv.tw/amiibo-bins/'), '/') + '/'
let db = null

const AMIIBOID_BLACKLIST = [
  '0000000000000000', // blank
]

async function build () {
  db = await fetchDb()
  await mkdir(distDir, { recursive: true })
  const dbTmp = _.mapValues(db, (v, k) => _.fromPairs([...v.entries()]))
  await writeFile(new URL('./db.json', distDir), JSON.stringify(dbTmp, null, 2))
  await writeFile(new URL('./db.yml', distDir), jsyaml.dump(dbTmp, { lineWidth: -1, noRefs: true }))

  console.log(`basedir = ${basedir}`)
  const files = await fg('amiibos/**/*.bin', { cwd: fileURLToPath(basedir) })
  const amiiboBins = []
  const unknownBins = []

  const binNameUniq = new Map()
  const binUniq = new Set()
  for (const file of files) {
    const filepath = new URL(file, basedir)
    let relative = path.relative(srcDir.href, filepath.href)
    try {
      let bin = Packet.fromView(await readFile(filepath))
      if (bin.length > 572) throw _.set(new Error('invalid NTAG215 bin'), 'dist', `unknown/${relative}`)
      bin = bin.subarray(0, 540)

      // bin unique
      if (binUniq.has(bin.base64url)) continue
      binUniq.add(bin.base64url)

      const tag = AmiiboNtag215.fromNtag215OrAmiitool(bin)
      const amiiboId = tag.amiiboId
      if (_.includes(AMIIBOID_BLACKLIST, amiiboId)) throw new Error(`blacklist, amiiboId = ${amiiboId}`)

      if (!tag.isValid()) console.log(`warning: failed to validate signature, ${relative}`)
      tag.fixTag()

      const binNamePrefix = `${amiiboId}_${tag.uid.hex}`
      binNameUniq.set(binNamePrefix, (binNameUniq.get(binNamePrefix) ?? 0) + 1)
      relative = `${binNamePrefix}_${binNameUniq.get(binNamePrefix)}.bin`

      amiiboBins.push({
        amiiboId,
        ntag215Url: new URL(`./ntag215/${relative}`, baseurl).href,
        amiitoolUrl: new URL(`./amiitool/${relative}`, baseurl).href,
      })

      await Promise.all([
        copyOrWriteBinToDist(tag.pack, `./ntag215/${relative}`), // ntag215 files
        copyOrWriteBinToDist(tag.toAmiitool(), `./amiitool/${relative}`), // amiitool files
      ])
    } catch (err) {
      const dist = `unknown/${relative}`
      await copyOrWriteBinToDist(filepath, dist)
      unknownBins.push(new URL(dist, baseurl).href)
      console.error(jsyaml.dump([errToJson(_.set(err, 'data.relative', relative))], { lineWidth: -1, noRefs: true }))
    }
    // if (amiiboBins.length + unknownBins.length >= 10) break
  }
  console.log(`amiiboBins.length = ${amiiboBins.length}`)

  const tmpAid = new Packet(8)
  const amiibos = _.mapValues(_.groupBy(_.orderBy(amiiboBins, 'amiiboId'), 'amiiboId'), (bins, amiiboId) => {
    tmpAid.setBigUint64(0, BigInt(`0x${amiiboId}`), false)
    return {
      // amiibo name
      ..._.omit(db.amiibos.get(amiiboId) ?? {}, ['games3DS', 'gamesSwitch', 'gamesWiiU', 'id']),

      // ID of the series
      amiiboSeries: db.amiiboSeries.get(tmpAid[6]),

      // the first element is the collection ID, the second the character in this collection, the third the variant
      character: db.characters.get(tmpAid.getUint16(0, false)),
      gameSeries: db.gameSeries.get(tmpAid.getUint16(0, false) >>> 4),
      modelId: tmpAid.getUint16(4, false),

      // Type of amiibo 0 = figure, 1 = card, 2 = plush
      type: db.amiiboTypes.get(tmpAid[3]),
      unknownId: tmpAid[7],

      // ID shared by all exact same amiibo. Some amiibo are only distinguished by this one like regular SMB Series Mario and the gold one
      variantId: tmpAid.getUint24(0, false),

      amiiboId,
      ntag215Urls: _.map(bins, 'ntag215Url'),
      amiitoolUrls: _.map(bins, 'amiitoolUrl'),
    }
  })
  await writeFile(new URL('./amiiboBins.json', distDir), JSON.stringify({ amiibos, unknownBins }, null, 2))
  await writeFile(new URL('./amiiboBins.yml', distDir), jsyaml.dump({ amiibos, unknownBins }, { lineWidth: -1, noRefs: true }))
}

async function copyOrWriteBinToDist (srcDataOrPath, relative) {
  const dist = new URL(relative, distDir)
  await mkdir(path.dirname(fileURLToPath(dist)), { recursive: true })
  if (Packet.isLen(srcDataOrPath)) await writeFile(dist, srcDataOrPath)
  if (srcDataOrPath instanceof URL) await cp(srcDataOrPath, dist)
}

;(() => { // extend Packet
  Packet.fromWordArray = wordArray => {
    const { words, sigBytes } = wordArray
    const pack = new Packet(sigBytes)
    for (let i = 0; i < sigBytes; i++) pack[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF
    return pack
  }
  Packet.prototype.toWordArray = function () {
    const { lib: { WordArray } } = CryptoJS
    return new WordArray.init(this) // eslint-disable-line new-cap
  }
})()

async function fetchDb () {
  const [jsonAmiibos1, jsonAmiibos2, jsonGames] = _.map(await Promise.all([
    axios.get('https://raw.githubusercontent.com/N3evin/AmiiboAPI/master/database/amiibo.json'),
    axios.get('https://raw.githubusercontent.com/hax0kartik/wumiibo/master/jsons/amiibos.json'),
    axios.get('https://raw.githubusercontent.com/N3evin/AmiiboAPI/master/database/games_info.json'),
  ]), 'data')
  // console.log({ jsonAmiibos1, jsonAmiibos2, jsonGames })

  // parse jsonAmiibos1
  const amiiboSeries = new Map(_.map(jsonAmiibos1.amiibo_series, (v, k) => [_.parseInt(k.slice(2), 16), v]))
  const characters = new Map(_.map(jsonAmiibos1.characters, (v, k) => [_.parseInt(k.slice(2), 16), v]))
  const gameSeries = new Map(_.map(jsonAmiibos1.game_series, (v, k) => [_.parseInt(k.slice(2), 16), v]))
  const amiiboTypes = new Map(_.flatMap(jsonAmiibos1.types, (v, k) => [
    [_.parseInt(k.slice(2), 16), v],
    [v, _.parseInt(k.slice(2), 16)],
  ]))
  const amiibos = new Map(_.map(jsonAmiibos1.amiibos, (v, k) => [_.toUpper(k.slice(2)), {
    id: _.toUpper(k.slice(2)),
    name: v.name,
    image: `https://raw.githubusercontent.com/N3evin/AmiiboAPI/master/images/icon_${k.slice(2, 10)}-${k.slice(10, 18)}.png`,
    release: v.release,
  }]))

  // parse and merge jsonAmiibos2
  for (const [, v1] of _.toPairs(jsonAmiibos2)) {
    for (const v2 of v1) {
      const amiiboId = _.toUpper(v2[1].slice(2))
      const amiibo = amiibos.get(amiiboId) ?? { id: amiiboId, name: v2[0] }
      if (amiibo.name !== v2[0]) amiibo.name2 = v2[0]
      amiibos.set(amiiboId, amiibo)
    }
  }

  // parse games
  const games = new Map()
  for (const [k1, v1] of _.toPairs(jsonGames.amiibos)) {
    const amiibo = amiibos.get(_.toUpper(k1.slice(2)))
    for (const tmpType of ['games3DS', 'gamesSwitch', 'gamesWiiU']) {
      for (const tmpGame of v1[tmpType]) {
        const gameUniq = `${tmpType.slice(5)}-${tmpGame.gameName}`
        const game = games.get(gameUniq) ?? { name: tmpGame.gameName, platform: tmpType.slice(5) }
        // merge games data
        game.amiiboUsage = _.uniqBy([...(game.amiiboUsage ?? []), ...tmpGame.amiiboUsage], usage => `${usage.Usage}${+usage.write}`)
        game.gameIds = _.uniq([...(game.gameIds ?? []), ...tmpGame.gameID])
        games.set(gameUniq, game)
        for (const gid of game.gameIds) games.set(gid, game)
        if (amiibo) game.amiiboIds = _.uniq([...(game.amiiboIds ?? []), amiibo.id])
      }
    }
  }

  return { amiibos, amiiboSeries, amiiboTypes, characters, gameSeries, games }
}

function getenv (key, defaultval) {
  return _.get(process, ['env', key], defaultval)
}

const ERROR_KEYS = [
  'name',
  'message',
  'stack',
  'address',
  'args',
  'code',
  'data',
  'dest',
  'errno',
  'extensions',
  'info',
  'locations',
  'path',
  'port',
  'positions',
  'reason',
  'response.data',
  'response.headers',
  'response.status',
  'source',
  'status',
  'statusCode',
  'statusMessage',
  'syscall',
]

function errToJson (err) {
  const tmp = {
    ..._.pick(err, ERROR_KEYS),
    ...(_.isNil(err.originalError) ? {} : { originalError: errToJson(err.originalError) }),
    stack: err?.stack?.replaceAll?.(basedir, './'),
  }
  return tmp
}

const RETAIL_KEY = Packet.fromBase64('HRZLN1typVcouR1ktqPCBXVuZml4ZWQgaW5mb3MAAA7bS54_RSePOX7_m0-5kwAABEkX3Ha0lkDW-Dk5lg-u1O85L6qyFCiqIftU5UUFR2Z_dS0oc6IAF_74XAV1kEttbG9ja2VkIHNlY3JldAAAEP3IoHaUuJ5MR9N96M5cdMEESRfcdrSWQNb4OTmWD67U7zkvqrIUKKoh-1TlRQVHZg') // UNFIXED_INFOS: 80 bytes + LOCKED_SECRET: 80 bytes
class AmiiboNtag215 {
  constructor () {
    this.pack = new Packet(540) // encrypted
    this.decrypted = null
    this.keys = null
  }

  static fromNtag215 (input) {
    if (!Packet.isLen(input, 540)) throw new TypeError(`invalid NTAG215 dump: ${input?.length} bytes`)
    const tag = new AmiiboNtag215()
    tag.pack.set(input) // clone
    tag.fixPwd() // because pwd can not be read from NTAG215, so we need to regenerate
    tag.encryptIfSign2Invalid()
    return tag
  }

  static concatFromByteMaps (src, byteMaps = []) {
    return Packet.merge(..._.map(byteMaps, ([offset, len]) => src.subarray(offset, offset + len)))
  }

  static fromAmiitool (amiitool) {
    if (!Packet.isLen(amiitool)) throw new TypeError('amiitool should be instance of Packet')
    if (!_.includes([520, 540], amiitool.length)) throw new TypeError(`invalid amiitool.length = ${amiitool?.length}`)
    const { concatFromByteMaps, fromNtag215 } = AmiiboNtag215
    // https://github.com/socram8888/amiitool/blob/master/amiibo.c#L63
    const pack = concatFromByteMaps(amiitool, [ // Don't change the order
      [0x1D4, 0x008], // NTAG215 UID
      [0x000, 0x008], // Lock/CC
      [0x028, 0x024], // 0x28: Counter, 0x2A: Init Date, 0x2C: Modified Date, 0x2E: Hash?, 0x34: Console #, 0x38: Nickname
      [0x1B4, 0x020], // LOCKED_SECRET HS256
      [0x1DC, 0x02C], // 0x1DC: Char. ID (AmiiboId), 0x1E4: Crypto Seed
      [0x008, 0x020], // UNFIXED_INFOS HS256
      [0x04C, 0x168], // 0x04C: Mii, 0x0B4: Write Counter, 0x0B6: App ID, 0x0BC: Hash, 0x0DC: App Data
      [0x208, 0x014], // Dynamic Lock Bytes, MIRROR, ACCESS, PWD, PACK
    ])
    return fromNtag215(pack)
  }

  static fromNtag215OrAmiitool (input) {
    const { fromNtag215, fromAmiitool } = AmiiboNtag215
    const isNtag215 = (input.subarray(0, 3).xor ^ 0x88) === input[3] && input.subarray(4, 8).xor === input[8]
    return isNtag215 ? fromNtag215(input) : fromAmiitool(input)
  }

  static hs256 (pack, secret) {
    return Packet.fromWordArray(CryptoJS.HmacSHA256(pack.toWordArray(), secret.toWordArray()))
  }

  static aes128Ctr (pack, key, iv) {
    const encrypted = CryptoJS.AES.encrypt(pack.toWordArray(), key.toWordArray(), {
      iv: iv.toWordArray(),
      mode: CryptoJS.mode.CTR,
      padding: CryptoJS.pad.NoPadding,
    })
    return Packet.fromWordArray(encrypted.ciphertext)
  }

  static generateKeyBySeedAndRetailKey (baseSeed, retail) {
    const { hs256 } = AmiiboNtag215
    const seed = new Packet(baseSeed)
    seed.set(retail.subarray(16, 30), 2) // key type: LOCKED_SECRET or UNFIXED_INFOS
    if (retail[31] === 16) seed.set(retail.subarray(32, 48), 16) // 16 magic bytes
    else seed.set(retail.subarray(32, 46), 18) // 14 magic bytes
    for (let i = 0; i < 32; i++) seed[48 + i] ^= retail[48 + i] // xorPad
    // - console.log(`retail = ${retail.base64url}`)
    // - console.log(`seed = ${seed.base64url}`)
    const res = {}
    if (retail[31] === 14) [res.aesKey, res.aesIv] = hs256(seed, retail.subarray(0, 16)).chunk(16)
    seed[1] = 1
    res.secret = hs256(seed, retail.subarray(0, 16)).subarray(0, 16)
    return res
  }

  static parseDate (raw) { return `${(raw >>> 9) + 2000}-${(raw >>> 5) & 0x0F}-${(raw >>> 0) & 0x1F}` }

  static calcSign1 (input, { secret1 }) {
    const { hs256, concatFromByteMaps } = AmiiboNtag215
    return hs256(concatFromByteMaps(input, [
      [0x000, 0x008], // uid + bcc0
      [0x054, 0x00c], // model
      [0x060, 0x020], // salt
    ]), secret1)
  }

  static calcSign2 (input, { secret2 }) {
    const { hs256, concatFromByteMaps } = AmiiboNtag215
    return hs256(concatFromByteMaps(input, [
      [0x011, 0x023], // setting.slice(1)
      [0x0A0, 0x168], // appData
      [0x034, 0x020], // sign1
      [0x000, 0x008], // uid + bcc0
      [0x054, 0x00c], // model
      [0x060, 0x020], // salt
    ]), secret2)
  }

  static calcPwd (uid) {
    const pwd = Packet.fromHex('AA55AA55')
    for (let i = 0; i < 4; i++) pwd[i] ^= uid[i + 1] ^ uid[i + 3]
    return pwd
  }

  get uid () { return AmiiboNtag215.concatFromByteMaps(this.pack, [[0, 3], [4, 4]]) }
  get setting () { return this.pack.subarray(0x10, 0x34) } // Tag setting
  get sign1 () { return this.pack.subarray(0x34, 0x54) } // Tag HS256
  get amiiboId () { return this.pack.subarray(0x54, 0x5C).hex }
  get salt () { return this.pack.subarray(0x60, 0x80) } // Keygen Salt
  get sign2 () { return this.pack.subarray(0x80, 0xA0) } // appData HS256
  get pwd () { return this.pack.subarray(0x214, 0x218) } // read pwd

  // https://github.com/hax0kartik/wumiibo/blob/master/source/AmiiboFile.cpp
  get flag () { return this.pack[0x2C] }
  get hasUserData () { return (this.flag >>> 4) & 1 }
  get hasAppData () { return (this.flag >>> 5) & 1 }
  get countryCode () { return this.pack[0x2D] }
  get initDate () { return AmiiboNtag215.parseDate(this.pack.getUint16(0x30, false)) }
  get modifiedDate () { return AmiiboNtag215.parseDate(this.pack.getUint16(0x32, false)) }
  get nickname () { return new TextDecoder('utf-16be').decode(this.pack.subarray(0x38, 0x4c)) }

  get parsedUserData () { // https://github.com/hax0kartik/wumiibo/blob/master/source/amiibo_structs.h
    if (!this.hasUserData) return undefined
    return {
      countryCodeId: this.pack[45], // Country Code ID, from the system which setup this amiibo.
      flag: this.flag & 0x0F, // See also the Amiibo_amiiboFlag enums.
      mii: this.pack.subarray(76, 172), // [0x4C, 0x4C + 0x60], Owner Mii.
      nickname: this.pack.subarray(56, 76), // [0x38, 0x38 + 0x14], UTF-16BE Amiibo nickname.
      lastWriteDate: AmiiboNtag215.parseDate(this.pack.getUint16(50, false)),
      setupDate: AmiiboNtag215.parseDate(this.pack.getUint16(48, false)),
    }
  }

  get parsedAppDataConfig () {
    if (!this.hasAppData) return undefined
    if (!this.decrypted) this.generateDecrypted()
    return {
      appId: this.decrypted.getUint32(182, false),
      counter: this.decrypted.getUint16(180, false),
      // Amiibo module writes hard-coded uint8_t value 0xD8 here. This is the size of the Amiibo AppData, apps can use this with the AppData R/W commands. ...
      data: this.decrypted.subarray(220, 436), // [0xDC, 0xDC + 0xD8]
      titleId: this.decrypted.subarray(172, 180), // BigUint64
      unk: this.flag >>> 4,
    }
  }

  toAmiitool () {
    const { concatFromByteMaps } = AmiiboNtag215
    if (!this.decrypted) this.generateDecrypted()
    // https://github.com/socram8888/amiitool/blob/master/amiibo.c#L53
    return concatFromByteMaps(this.decrypted, [ // Don't change the order
      [0x008, 0x008], // Lock/CC
      [0x080, 0x020], // UNFIXED_INFOS HS256
      [0x010, 0x024], // 0x10: Counter, 0x12: Init Date, 0x14: Modified Date, 0x16: Hash?, 0x1C: Console #, 0x20: Nickname
      [0x0A0, 0x168], // 0x0A0: Mii, 0x0108: Write Counter, 0x10A: App ID, 0x110: Hash, 0x130: App Data
      [0x034, 0x020], // LOCKED_SECRET HS256
      [0x000, 0x008], // NTAG215 UID
      [0x054, 0x02C], // 0x54: Char. ID (AmiiboId), 0x5C: Crypto Seed
      [0x208, 0x014], // Dynamic Lock Bytes, MIRROR, ACCESS, PWD, PACK
    ])
  }

  generateKeys () {
    const LOCKED_SECRET = RETAIL_KEY.subarray(80) // for sign1
    const UNFIXED_INFOS = RETAIL_KEY.subarray(0, 80) // for sign2
    const { generateKeyBySeedAndRetailKey } = AmiiboNtag215
    const keys = {}
    const baseSeed = Packet.merge(
      new Packet(16),
      this.setting.subarray(1, 3), // 2 bytes: [17, 19]
      new Packet(14),
      this.pack.subarray(0, 8), // uid + bcc0
      this.pack.subarray(0, 8), // uid + bcc0
      this.salt,
    )
    // - console.log(`baseSeed = ${baseSeed.base64url}`)

    const key1 = generateKeyBySeedAndRetailKey(baseSeed, LOCKED_SECRET)
    keys.secret1 = key1.secret

    const key2 = generateKeyBySeedAndRetailKey(baseSeed, UNFIXED_INFOS)
    keys.secret2 = key2.secret
    keys.aesKey = key2.aesKey
    keys.aesIv = key2.aesIv

    this.keys = keys
  }

  encryptOrDecrypt (input) {
    const { aes128Ctr, concatFromByteMaps } = AmiiboNtag215
    if (!this.keys) this.generateKeys()
    const { aesKey, aesIv } = this.keys
    const encryptByteMaps = [
      [0x014, 0x020], // setting.slice(4)
      [0x0A0, 0x168], // appData
    ]
    const payload = concatFromByteMaps(input, encryptByteMaps)
    const encrypted = aes128Ctr(payload, aesKey, aesIv)
    const output = new Packet(input)
    let offset1 = 0
    for (const [offset2, len] of encryptByteMaps) {
      output.set(encrypted.subarray(offset1, offset1 + len), offset2)
      offset1 += len
    }
    return output
  }

  generateDecrypted () {
    this.decrypted = this.encryptOrDecrypt(this.pack)
  }

  isValidSign1 () {
    const { calcSign1 } = AmiiboNtag215
    if (!this.keys) this.generateKeys()
    const sign1 = calcSign1(this.pack, this.keys)
    return sign1.isEqual(this.sign1)
  }

  isValidSign2 (packToValidate = this.decrypted) {
    const { calcSign2 } = AmiiboNtag215
    if (!this.keys) this.generateKeys()
    const sign2 = calcSign2(packToValidate, this.keys)
    return sign2.isEqual(this.sign2)
  }

  isValidPwd () {
    const { calcPwd } = AmiiboNtag215
    const pwd = calcPwd(this.uid)
    return pwd.isEqual(this.pwd)
  }

  isValid () {
    if (!this.decrypted) this.generateDecrypted()
    // console.log(`isValid = ${JSON.stringify([this.isValidPwd(), this.isValidSign1(), this.isValidSign2()])}`)
    return this.isValidPwd() && this.isValidSign1() && this.isValidSign2()
  }

  encryptIfSign2Invalid () {
    if (!this.decrypted) this.generateDecrypted()
    if (this.isValidSign2()) return true // no need to encrypt
    if (!this.isValidSign2(this.pack)) return false // both sign2 invalid
    ;[this.pack, this.decrypted] = [this.decrypted, this.pack] // swap
    return true
  }

  fixPwd () {
    const { calcPwd } = AmiiboNtag215
    this.pwd.set(calcPwd(this.uid))
    this.pack.setUint16(0x218, 0x8080, false) // password ack
  }

  fixSignature () {
    const { calcSign1, calcSign2 } = AmiiboNtag215
    if (!this.decrypted) this.generateDecrypted(true) // no validate sign2
    this.sign1.set(calcSign1(this.decrypted, this.keys))
    this.sign2.set(calcSign2(this.decrypted, this.keys))
  }

  fixUid () {
    this.pack[3] = this.pack.subarray(0, 3).xor ^ 0x88 // bcc0 = CT (0x88) ^ uid0 ^ uid1 ^ uid2
    this.pack[8] = this.pack.subarray(4, 8).xor // bcc1 = uid3 ^ uid4 ^ uid5 ^ uid6
  }

  fixData () {
    // Set blank tag?
    // https://github.com/HiddenRamblings/TagMo/blob/master/app/src/main/java/com/hiddenramblings/tagmo/nfctech/TagReader.kt#L17
    this.pack.set(Packet.fromHex('0FE0'), 0x00A)
    // Set 0xA5, Write Counter, and Unknown
    this.pack.set(Packet.fromHex('A5000000'), 0x010)
    // Set Dynamic Lock, and RFUI, CFG0, CFG1
    // https://github.com/HiddenRamblings/TagMo/blob/master/app/src/main/java/com/hiddenramblings/tagmo/nfctech/Foomiibo.kt#L43
    this.pack.set(Packet.fromHex('01000FBD000000045F000000'), 0x208)
  }

  fixTag () {
    this.fixUid() // fix uid bcc0, bcc1
    this.fixData() // fix static data
    this.fixPwd() // re-generate pwd
    this.generateKeys() // re-generate keys
    this.generateDecrypted() // re-generate decrypted
    this.fixSignature() // fix sign1, sign2
  }

  setUid (uid7b) {
    if (!Packet.isLen(uid7b, 7)) throw new TypeError('invalid uid7b')
    if (uid7b[0] !== 0x04) throw new TypeError('uid7b[0] should be NXP (0x04)')

    if (!this.decrypted) this.generateDecrypted() // decrypt

    this.uid.set(uid7b.subarray(0, 3), 0)
    this.uid.set(uid7b.subarray(3, 7), 4)
    this.fixTag()
  }

  randomUid () {
    const uid7b = Packet.fromWordArray(CryptoJS.lib.WordArray.random(7))
    uid7b[0] = 0x04
    this.setUid(uid7b)
  }
}

build().catch(err => {
  console.error(err)
  process.exit(1)
})
