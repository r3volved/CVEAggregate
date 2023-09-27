/**
 * Convert ESM files from /src into CommonJS files to /lib
 * Simple stream-pipe, by-line
 * - Changes /src references to /lib
 * - Changes .js references to .cjs
 * - Changes import to require
 * - Changes export to module.exports 
 */

import { createReadStream, createWriteStream, readdirSync, existsSync, mkdirSync } from 'fs'
import { fileURLToPath } from 'url'
import { join, dirname } from 'path'
import readline from 'node:readline'
import events from 'node:events'

const libraryFolder = 'lib'
const sourceFolder = 'src'

const __dirname = dirname(fileURLToPath(import.meta.url))
const src = join(__dirname, sourceFolder)
const files = readdirSync(src)

const lib = join(__dirname, libraryFolder)
if( !existsSync(lib) ) mkdirSync(lib)

for(const file of files) {
    if( !file.match(/[\.js|\.md]$/) ) continue
    const type = file.slice(-2)
    try {
        const srcpath = join(src, file)
        const rl = readline.createInterface({ input: createReadStream(srcpath), crlfDelay: Infinity })

        const outfile = type === 'js' ? file.replace(/(\.js)$/, '.cjs') : file
        const libpath = join(lib, outfile)
        const wl = createWriteStream(libpath)

        const exports = []
        rl.on('line', (line) => {
            if( line.startsWith('const __dirname') ) {
                return //ignore this line
            } 
            
            line = line.replace('await import','require')
            line = line.replace(/(\.js)\b/,'.cjs')
            line = line.replace('/src/','/lib/')
            
            if( line.startsWith('export') ) {
                line = line.slice(7)
                exports.push(line.match(/\w+\s{1,}([\w|\d]*)/)?.[1])
            } else if( line.startsWith('import') ) {
                line = line.replace('import', 'const')
                line = line.replace('from', '=')
                line = line.replace(/\'/g,'"')
                const eqInx = line.lastIndexOf('=')
                const path = JSON.parse(line.slice(eqInx+1).trim())
                line = line.slice(0, eqInx+2) + `require('${path}')`
            }

            wl.write(`${line}\n`)
        })

        rl.on('close', () => {
            if( type === 'js' ) {
                wl.write(`module.exports = {\n\t${exports.join(',\n\t')}\n}\n\n`)
            }
            wl.end()
        })

        await events.once(rl, 'close')
    } catch(e) {
        console.error(e)
    }
}

