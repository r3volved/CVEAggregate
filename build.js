if( !process.argv[2]?.length ) {
    console.log(`Build a full cve aggregate with: $ node build /path/to/cves.json`)
    process.exit(-1)
}
const path = require('path')
const CVEAggregate = require(path.join(__dirname, 'index.js'))

new CVEAggregate(process.argv[2], true).build()
