(async () => {
    const CVEAggregate = require('.')
    const cves = new CVEAggregate(process.argv[2], true)
    
    // console.log('-'.repeat(30))
    // await cves.build()

    console.log('-'.repeat(30))
    await cves.update()        

    console.log('-'.repeat(30))
    cves.report()

    const cveList = ['CVE-2023-35390','CVE-2023-35391','CVE-2023-38180']

    console.log('-'.repeat(30))
    // console.log('CVEs', 'queued', cveList)
    // console.log('CISA', 'in-KEV', cves.getCISA(...cveList)) //Is at least one of these CVEs in the KEV?
    // console.log('EPSS', 'scaled', cves.getEPSS(...cveList)) //Scaled product of all EPSS
    console.log('CVSS', 'scored', cves.getCVSS(...cveList)) //Maximum score of all CVSS

    console.log('-'.repeat(30))
    // console.log('CISA', cves.mapCISA(...cveList))
    // console.log('EPSS', cves.mapEPSS(...cveList))
    console.log('CVSS', cves.mapCVSS(...cveList))

    console.log('-'.repeat(30))
    console.log(cves.calculateCVSSVector("AV:N/AC:L/Au:N/C:C/I:C/A:C"))
    
    console.log('-'.repeat(30))
    console.log(cves.calculateCVSSVector("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"))



})()