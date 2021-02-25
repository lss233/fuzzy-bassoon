const chalk = require('chalk');

module.exports = async function (session) {
    session.sendMessage('')
    session.sendMessage(chalk.bgGray.black('    help            ') + '  Show this help menu           ')
    session.sendMessage(chalk.bgGray.black('    show            ') + '  Show current peerrings status ')
    session.sendMessage(chalk.bgGray.black('    new             ') + '  Establish new peering         ')
    session.sendMessage(chalk.bgGray.black('    delete ID       ') + '  Show this help menu           ')
    session.sendMessage(chalk.bgGray.black('    whois OBJECT    ') + '  Whois directory service       ')
    session.sendMessage(chalk.bgGray.black('    exit            ') + '  Leave this place              ')
    session.sendMessage('')
    session.sendMessage('')
}