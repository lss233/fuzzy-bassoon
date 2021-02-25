const net = require('net')
function query(text, options) {
    return new Promise((resolve, reject) => {
        let client  = new net.Socket();
        client.connect({
            host: 'whois.dn42',
            port: 43
        });
        client.on('connect', function () {
            client.write(text + '\r\n');
        })
        let ans = ''
        client.on('data', function(data) {
            ans += data.toString()
        })
        client.on('close', function() {
            if(options && options.raw) {
                resolve(ans);                    
            } else {
                let result = {};
                let currentKey = text;
                for(let i of ans.split('\n')) {
                    if(i.startsWith('%')) {
                        if(i.startsWith('% Information related to')) {
                            currentKey = i.substring(26, i.length - 2)
                            result[currentKey] = {}
                        }
                    } else if(i.includes(':')) {
                        let a = i.split(':', 2)
                        result[currentKey][a[0]] = result[currentKey][a[0]] || [];
                        result[currentKey][a[0]].push(a[1].trim())
                    }
                }
                if(options && options.last) {
                    resolve(result[currentKey])
                } else {
                    resolve(result)
                }
            }
        })
    })
}
module.exports = {
    query: query,
    queryRaw: (text) => query(text, {raw: true}),
    queryLast: (text) => query(text, {last: true})
}