export class Logger {
    constructor() {
        this.logging = false
    }

    /**
     * Log to console
     * @param {Error}   lines an error object to throw in console
     */
    error(err) {
        this.logging = false
        console.error(err)
    }

    /**
     * Log multiple lines console
     * @param {array}   lines a list of strings to replace the last n-lines in console if the last log was array
     */
    multi(lines) {
        if( this.logging ) {
            process.stdout.moveCursor(0, -1*(lines.length))
            process.stdout.clearLine(0)
            process.stdout.cursorTo(0)
        }
        process.stdout.write(lines.join('\n')+'\n')
        this.logging = true
    }

    /**
     * Log to console
     * @param {array}   lines a list of strings to replace the last n-lines in console if the last log was array
     * @param {Error}   lines an error object to throw in console
     * @param {any}     lines any other value/type to log in console
     */
    log(lines, ...other) {
        if( lines === undefined ) return
        if( lines instanceof Error ) return this.error(lines)
        if( Array.isArray(lines) ) return this.multi(lines)

        this.logging = false
        console.log(lines, ...other)
    }    
}
