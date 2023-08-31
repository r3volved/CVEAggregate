if( !process.argv[2]?.length ) {
    console.log(`Build a full cve aggregate with: $ node build /path/to/cves.json`)
    process.exit(-1)
}
const CVEAggregate = require('.')
new CVEAggregate(process.argv[2], true).build()
