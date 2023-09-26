import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const fileJson = process.argv[2]
if( !fileJson?.length ) {
    console.error('Error: No export file specified\n')
    console.log(`Build a full CVE aggregate with:\n$ node ${join(__dirname, 'build.js')} /path/to/cves.json`)
    process.exit(-1)
}

const cveLibPath = join(__dirname, 'src', 'index.js')
const { CVEAggregate } = await import(cveLibPath)
const aggregate = new CVEAggregate(fileJson, true)

await aggregate.build(true)
await aggregate.logger.log("-".repeat(30))
await aggregate.report()
