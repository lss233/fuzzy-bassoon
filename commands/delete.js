const fs = require('fs')
const promisify = require('util').promisify
const exec = promisify(require('child_process').exec);

module.exports = async function deletePeer(session, id) {
    let info = session.db.get('peers').find({id: id, mntner: session.user}).value();
    if(info === undefined) {
        session.sendMessage('Invalid ID.')
        return;
    }
    exec(`wg-quick down "${__dirname}/data/wireguards/${info.interface}.conf"`)
    exec('birdc')
    session.db.get('peers').remove({id: id, mntner: session.user}).write()
    fs.unlinkSync(`${__dirname}/../data/wireguards/${info.interface}.conf`)
    fs.unlinkSync(__dirname + `/../data/bird/dn42_${session.user}_${asn.substring(info.asn.length - 4, asn.length)}AP.conf`)
    session.sendMessage('Peer has been deleted.')
}