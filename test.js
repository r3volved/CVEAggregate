(async () => {
    const CVES = require('.')
    const cves = new CVES(process.argv[2], true)
    
    await cves.build()
    console.log('-'.repeat(30))

    // await cves.update()        
    // console.log('-'.repeat(30))

    cves.report()
    console.log('-'.repeat(30))

    const cveList = [
        'CVE-2023-28251',
        'CVE-2023-28283',
        'CVE-2023-24939',
        'CVE-2023-24900',
        'CVE-2023-24940',
        'CVE-2023-24901',
        'CVE-2023-24941',
        'CVE-2023-24942',
        'CVE-2023-24943',
        'CVE-2023-24944',
        'CVE-2023-24945',
        'CVE-2023-24946',
        'CVE-2023-24948',
        'CVE-2023-29324',
        'CVE-2023-29325',
        'CVE-2023-24903',
        'CVE-2023-24947',
        'CVE-2023-24949',
    ]

    console.log('CVEs', 'queued', cveList)
    console.log('CISA', 'in-KEV', cves.getCISA(...cveList)) //Is at least one of these CVEs in the KEV?
    console.log('EPSS', 'scaled', cves.getEPSS(...cveList)) //Scaled product of all EPSS
    console.log('CVSS', 'scored', cves.getCVSS(...cveList)) //Maximum score of all CVSS

    // console.groupCollapsed('Mappings')
    // console.log('CISA', cves.mapCISA(...cveList))
    // console.log('EPSS', cves.mapEPSS(...cveList))
    // console.log('CVSS', cves.mapCVSS(...cveList))
    // console.groupEnd()
})()