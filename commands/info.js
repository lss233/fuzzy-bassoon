const chalk = require('chalk');

module.exports = async function (session) {
    session.sendMessage('')
    session.sendMessage(chalk.bgGray.black('    Node                       ') + '  ' + session.node.name)
    session.sendMessage(chalk.bgGray.black('    AS Number                  ') + '  ' + session.node.asn)
    session.sendMessage(chalk.bgGray.black('    Wireguard Endpoint         ') + '  ' + session.node.wireguard.endpoint)
    session.sendMessage(chalk.bgGray.black('    Wireguarrd Publickey       ') + '  ' + session.node.wireguard.publickey)
    session.sendMessage(chalk.bgGray.black('    DN42 IPv4                  ') + '  ' + session.node.wireguard.ipv4)
    session.sendMessage(chalk.bgGray.black('    DN42 IPv6                  ') + '  ' + session.node.wireguard.ipv6)
    session.sendMessage(chalk.bgGray.black('    Link-Local                 ') + '  ' + session.node.wireguard.linkLocal)
    session.sendMessage(chalk.bgGray.black('    Multiprotocol BGP Support  ') + '  ' + session.node.mpbgp)
    session.sendMessage('')
    session.sendMessage('')
}