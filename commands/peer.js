const fs = require('fs')
const net = require('net')
const chalk = require('chalk')
const whois = require('../whois');
const promisify = require('util').promisify
const exec = promisify(require('child_process').exec);
const hostnameValidator = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))|(^\s*((?=.{1,255}$)(?=.*[A-Za-z].*)[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?)*)\s*$)/;
function isValidHostname(text) {
    return hostnameValidator.test(text)
}
module.exports = async function newPeering(session) {
    let node = session.node
    let question = text => new Promise((resolve, reject) => {
        try {
            session.rl.question(text, resolve)
        } catch(e) {
            reject(e)
        }
    })
    let questionYesOrNo = async text => {
        let qA;
        while (qA = await question(text + ' [y/N] ')) {
            console.log(qA)
            if (qA == '' || qA == ' ' || qA == 'y' || qA == 'yes' || qA == 'Y') {
                return true;
            } else if (qA == 'n' || qA == 'N' || qA == 'no' || qA == 'NO') {
                return false;
            } else {
                session.sendMessage('Please type `yes` or `no`.')
            }
        }
    }
    let questionValidate = async (text, validator, failText) => {
        while(true) {
            let answer = await question(text)
            try{
                if(answer && 
                    ((answer = answer.replace(/\n/g, '').trim()),
                    await validator(answer))
                ) {
                    return answer;
                } else {
                    session.sendMessage(failText)
                }
            } catch(e) {
                console.error('Error when validating ', answer, e)
            }
        }
    }
    let validateOwnership = (block) => block && block['mnt-by'] && block['mnt-by'][0] == session.user

    let asn = await questionValidate(
        'Your AS Number: ',
        async asn => !isNaN(asn) && validateOwnership(await whois.queryLast(`aut-num/AS${asn}`)),
        `Invalid AS Number. Please input a valid AS Number which ${chalk.bgYellow.blue('mnt-by')} is ${chalk.yellow(session.user)}`
    )
    let hostname = await questionValidate(
        'Your Clearnet Hostname: ', 
        async hostname => isValidHostname(hostname),
        'Invalid Hostname. Please retry. If you don\'t have one, just write something looks right.')

    let wgPort = await questionValidate(
        'Your WireGuard Port: ', 
        async port => (e => Number.isSafeInteger(e) && e > 0 && e < 65535)(Number.parseInt(port, 10)),
        'Invalid Port. Please provide a valid port number within range (0, 65535).')

    let wgPublickey = await questionValidate(
        'Your WireGuard PublicKey: ',
        async key => key.length == 44,
        'Invalid publickey provided. Please retry.')
    let interfaceName = `dn42_${asn.substring(asn.length - 4, asn.length)}_AP`

    let wgPostUp = ''

    if (await questionYesOrNo('Do you have DN42 IPv4?')) {
        var ipv4 = await questionValidate(
            'Your DN42 IPv4 Address: ', 
            async ipv4 => net.isIPv4(ipv4) &&validateOwnership(await whois.queryLast(ipv4)),
            `Invalid DN42 IP. Please input a valid IP which ${chalk.bgYellow.blue('mnt-by')} is ${chalk.yellow(session.user)}`
        )
        wgPostUp += `PostUp = ip addr del ${node.wireguard.ipv4}/32 dev ${interfaceName} && ip addr add ${node.wireguard.ipv4}/32 peer ${ipv4 ? ipv4 : '172.18.1.22'}/32 dev ${interfaceName}\n`
    }

    if (await questionYesOrNo('Do you have DN42 IPv6?')) {
        var ipv6 = await questionValidate(
            'Your DN42 IPv6 Address: ', 
            async ipv6 => net.isIPv6(ipv6) && validateOwnership(await whois.queryLast(ipv6)),
            `Invalid DN42 IP. Please input a valid IP which ${chalk.bgYellow.blue('mnt-by')} is ${chalk.yellow(session.user)}`
        )
    }

    let linkLocal = await questionValidate(
        'Your IPv6 Link-local Address: ', 
        async ipv6 => net.isIPv6(ipv6),
        `Invalid IPv6 Link-local`
    )
    console.log(wgPostUp)
    let wgConf = `# Generated by Automatic Peer System on ${Date()}
[Interface]
# ${session.user} v4:${ipv4} v6:${ipv6}
ListenPort = 5${asn.substring(asn.length - 4, asn.length)}
PrivateKey = ${node.wireguard.privatekey}
Address = ${node.wireguard.ipv4}/32, ${node.wireguard.ipv6}/128, ${node.wireguard.linkLocal}
${wgPostUp}
Table = off
[Peer]
PublicKey = ${wgPublickey}
Endpoint = ${hostname}:${wgPort}
AllowedIPs = 172.20.0.0/14, 10.0.0.0/8, fd00::/8, fe80::/10
PersistentKeepalive = 30`

    if (await questionYesOrNo('Do you support Multiprotocol BGP?')) {

        var birdCfg = `# Generated by Automatic Peer System on ${Date()}
protocol bgp dn42_${asn.substring(asn.length - 4, asn.length)}AP_v6 from dnpeers {
    neighbor ${linkLocal ? linkLocal : ipv6 ? ipv6 : ipv4} % '${interfaceName}' as ${asn};
}`
    } else {
        var birdCfg = `# Generated by Automatic Peer System on ${Date()}
protocol bgp dn42_${session.user}_${asn.substring(asn.length - 4, asn.length)}AP_v6 from dnpeers {
    neighbor ${linkLocal ? linkLocal : ipv6 ? ipv6 : ipv4} % '${interfaceName}' as ${asn};
    ipv4 {
        import none;
        export none;
    };
}`
        if(ipv4) {
            birdCfg += `
protocol bgp dn42_${session.user}_${asn.substring(asn.length - 4, asn.length)}AP_v4 from dnpeers {
    neighbor ${ipv4} as ${asn};
    ipv6 {
        import none;
        export none;
    };
}`
        }
    }
    if(!await questionYesOrNo('Is this right?')) {
        session.sendMessage(chalk.red('Abort peering.'))
        return;
    }
    session.sendMessage(chalk.red('Processing.'))
    
    fs.writeFileSync(__dirname + `/../data/wireguards/${interfaceName}.conf`, wgConf)
    fs.writeFileSync(__dirname + `/../data/bird/dn42_${session.user}_${asn.substring(asn.length - 4, asn.length)}AP.conf`, birdCfg)
    try {
        await exec(`wg-quick up "${__dirname}/../data/wireguards/${interfaceName}.conf"`)
        await exec('birdc c')
    } catch(e) {
        console.log('>> ' + __dirname + `/../data/wireguards/${interfaceName}.conf`)
        console.log(wgConf)
        console.log('>> ' + __dirname + `/../data/bird/dn42_${session.user}_${asn.substring(asn.length - 4, asn.length)}AP.conf`)
        console.log(birdCfg)
        console.error(e)
        session.sendMessage('OOps! Something seems wrong in your input.')
        session.sendMessage('Unable to establish a peer connection.')
        exec(`wg-quick down "${__dirname}/../data/wireguards/${interfaceName}.conf"`).catch(() => {})
        exec('birdc c').catch(() => {})
        fs.unlinkSync(__dirname + `/../data/wireguards/${interfaceName}.conf`, wgConf)
        fs.unlinkSync(__dirname + `/../data/bird/dn42_${session.user}_${asn.substring(asn.length - 4, asn.length)}AP.conf`, birdCfg)
        return;
    }   
    session.sendMessage('')
    session.sendMessage('Congratulation! The peer process over my side has')
    session.sendMessage('been completed. Once you have set up, you can check')
    session.sendMessage('our connection status on my Looking Glass:')
    session.sendMessage(chalk.bgGrey('  https://lg.lss233.com  '))

    session.db.get('peers').push({
        mntner: session.user,
        endpoint: hostname + ':' + wgPort,
        publicKey: wgPublickey,
        address: [ipv4, ipv6, linkLocal].filter(i => i).join('/'),
        asn: asn,
        interface: interfaceName,
        bird: `dn42_${session.user}_${asn.substring(asn.length - 4, asn.length)}AP`
    }).write()
}