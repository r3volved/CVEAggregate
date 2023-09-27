/**
 * Get the difference between two dates (in days)
 * @param  {Date}   date1    
 * @param  {Date}   date2   Optional second date to use instead of current date
 * @return {number} Difference in days (floating point)
 */
const diffInDays = (date1, date2 = Date.now()) => {
    const last = new Date(date1)
    const now  = new Date(date2)
    const Difference_In_Time = now.getTime() - last.getTime()
    const Difference_In_Days = Difference_In_Time / (1000 * 3600 * 24)
    return Difference_In_Days
}

/**
 * Compare a value against a condition (optional format func)
 * @param  {*}      val     The value from the aggregate
 * @param  {object} option  The condition to compare with
 * @param  {func}   format  Optional formatting function for normalizing both sides of the condition
 * @return {bool}   Whether the value matches the condition
 */
const compare = (val, option, format) => {
    const key = Object.keys(option||{})[0]
    return !key ? false : typeof format === 'function'
        ? compareFunc[key]( val === null ? val : format(val), format(option[key]) )
        : compareFunc[key]( val, option[key] )
}

/** 
 * Comparison functions mapped by key (gt,gte,lt,lte,eq,ne,neq)
 */
const compareFunc = {
    gt: (v1, v2) => v1 > v2,    //Greater than
    gte:(v1, v2) => v1 >= v2,   //Greater than, or equal
    lt: (v1, v2) => v1 < v2,    //Less than
    lte:(v1, v2) => v1 <= v2,   //Less than, or equal
    eq: (v1, v2) => v1 === v2,  //Is equal
    ne: (v1, v2) => v1 !== v2,  //Not equal
    neq:(v1, v2) => v1 !== v2,  //Same as ne
}

module.exports = {
	diffInDays,
	compare,
	compareFunc
}

