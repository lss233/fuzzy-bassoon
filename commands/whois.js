const whois = require('../whois');

module.exports = async function (session, object) {
    session.sendMessage(await whois.queryRaw(object))
}