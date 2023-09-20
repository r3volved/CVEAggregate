const path = require('path')

if( !process.argv[2]?.length ) {
    console.error('Error: No export file specified\n')
    console.log(`Build a full CVE aggregate with:\n$ node ${path.join(__dirname, 'build.js')} /path/to/cves.json`)
    process.exit(-1)
}

const modulepath = path.join(__dirname, 'index.js')
const CVEAggregate = require(modulepath)

const filepath = process.argv[2]
const aggregate = new CVEAggregate(filepath, true)

aggregate.build()
    .then(() => aggregate.logger.log("-".repeat(30)))
    .then(() => aggregate.report())
