const fs = require('fs'),
    crypto = require('crypto'),
    ssh2 = require('ssh2'),
    chalk = require('chalk'),
    readline = require('readline'),
    node = require('./node'),
    whois = require('./whois'),
    openpgp = require('openpgp');
openpgp.config.showComment = false
openpgp.config.showVersion = false
openpgp.config.versionString = 'FuzzyBasson v1.0.0'
openpgp.config.commentString = 'i@lss233.com'

const commands = require('./commands')

const low = require('lowdb')
const FileSync = require('lowdb/adapters/FileSync')

const adapter = new FileSync('./data/db.json')
const db = low(adapter)
db.defaults({ peers: [] }).write()
db._.mixin(require('lodash-id'))

const hkp = new openpgp.HKP('http://keys.gnupg.net');

var utils = ssh2.utils;

function checkValue(input, allowed) {
    const autoReject = (input.length !== allowed.length);
    if (autoReject) {
        allowed = input;
    }
    const isMatch = crypto.timingSafeEqual(input, allowed);
    return (!autoReject && isMatch);
}

new ssh2.Server({
    ident: 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2',
    greeting: 'Welcome to Lss233\'s Automatic Peering System',
    banner: '',
    hostKeys: [fs.readFileSync('.ssh/privkey')]
}, function (client) {
    let user;
    let isPGPAuth = true;
    let handler;
    let mntnerInfo;
    console.log('Client connected!');

    client.on('authentication', async function (ctx) {
        if(handler) {
            handler(ctx)
            handler = undefined
            return;
        }
        let rejectWithMessage = (msg) => {
            if (ctx.method === 'keyboard-interactive') {
                console.log(`Reject ${ctx.username} due to: ${msg}`)
                ctx.prompt(chalk.bgRed.white('Error: ') + chalk.red(msg) + '\r\n Press Ctrl + C to continue.\r\n', () => {
                    ctx.reject(['none'])
                })
                ctx.reject(['none'])
            } else {
                handler = (ctx) => {
                    console.log(`Reject ${ctx.username} due to: ${msg}`)
                    ctx.prompt(chalk.bgRed.white('Error: ') + chalk.red(msg) + '\r\n Press ' + chalk.bgWhite.black('Enter') + ' to continue.\r\n', () => {
                        ctx.reject(['keyboard-interactive'])
                    })
                }
                return ctx.reject(['keyboard-interactive'])
            }
        }

        user = Buffer.from(ctx.username).toString();

        console.log(user, ctx.method)
        try {
            mntnerInfo = await whois.queryLast('mntner/' + user);
            if (mntnerInfo === undefined ||
                ((user = mntnerInfo['mntner'][0]),
                    !/^[a-zA-Z0-9-]+$/.test(user) && user.toLowerCase().endsWith('-mnt'))
            ) {
                return rejectWithMessage('Please login as mntner.')
            }
        } catch(e) {
            console.error(e)
            ctx.reject();
        }
        

        switch (ctx.method) {
            case 'password':
                return ctx.reject(['publickey', 'keyboard-interactive']);
            case 'publickey':
                try {
                    for (let auth of mntnerInfo.auth) {
                        if (auth.startsWith('ssh-')) {
                            let allowedPubKey = utils.parseKey(auth)
                            if (ctx.key.algo !== allowedPubKey.type
                                || !checkValue(ctx.key.data, allowedPubKey.getPublicSSH())
                                || (ctx.signature && allowedPubKey.verify(ctx.blob, ctx.signature) !== true)) {
                                continue;
                            }
                            user = mntnerInfo['mntner'][0]
                            isPGPAuth = false;
                            return ctx.accept();
                        }
                    }
                    return rejectWithMessage('Could not authenticate with your publickey. Please use your mntner publickey to login.')
                } catch (e) {
                    console.log(e)
                }
                break;
            case 'keyboard-interactive':
                return ctx.accept();
            default:
                return ctx.reject();
        }
    }).on('ready', function () {
        console.log('Client authenticated!');
        client.on('session', function (accept, reject) {
            let stdin, stdout;
            var session = accept();
            session
                .on('pty', (accept, reject, info) => {
                    session.pty = info
                })
                .on('shell', async function (accept, reject) {
                    let shell = accept();

                    stdin = shell.stdin, stdout = shell.stdout;
                    let stderr = shell.stderr;

                    session.db = db;
                    session.user = user
                    session.sendMessage = (text) => {
                        for (let i of text.split('\n')) {
                            stdout.write(i + '\r\n')
                        }
                    }
                    session.clearScreen = () => {
                        if(session.pty && session.pty.rows && session.pty.cols){
                            shell.stdout.write('\033[0;0H');
                            shell.stdout.write(' '.repeat(session.pty.rows * session.pty.cols));
                            shell.stdout.write('\033[0;0H');
                        }
                    }
                    session.sendErrMessage = (text) => {
                        for (let i of text.split('\n')) {
                            stderr.write(i + '\r\n')
                        }
                    }

                    if(isPGPAuth) {
                        try {
                            const password = 'Lss233PeerValidation@' + crypto.randomBytes(32).toString('base64')
                            for (let auth of mntnerInfo.auth) {
                                if (auth.startsWith('pgp-fingerprint')) {
                                    let publicKeyArmored = await hkp.lookup({ query: '0x' + auth.substr(16) });
                                    let publicKey = await openpgp.key.readArmored(publicKeyArmored);
                                    session.sendMessage('Entering PGP publickey authentication mode.')
                                    session.sendMessage('Please sign following text using ')
                                    session.sendMessage(`${chalk.bgWhite.black(auth)}`)
                                    session.sendMessage('Text:')
                                    session.sendMessage(`${chalk.bgGray(password)}`)
                                    session.sendMessage(`Please provide the PGP signed text:`)
                                    let armoredText = ''
                                    let isDetachedSignature = true;
                                    let rl = readline.createInterface({
                                        input: shell.stdin,
                                        output: shell.stdout,
                                        terminal: true
                                    });
                                    await new Promise((resolve, reject) => {
                                        rl.on('line', async text => {
                                            text = text.trim();
                                            armoredText += text + '\r\n';
                                            if(text.includes('-----BEGIN PGP SIGNED MESSAGE-----')){
                                                isDetachedSignature = false;
                                            } else if(text == '-----END PGP SIGNATURE-----') {
                                                rl.close();
                                                try {
                                                    let isVerified = false;
                                                    if(isDetachedSignature) {
                                                        const clearText = await openpgp.cleartext.fromText(password)
                                                        const signature = await openpgp.signature.readArmored(armoredText);
                                                        const verified = await openpgp.verify({
                                                            message: clearText,
                                                            signature: signature,
                                                            publicKeys: publicKey.keys
                                                        })
                                                        isVerified = await verified.signatures[0].verified
                                                    } else {
                                                        const signedMessage = await openpgp.cleartext.readArmored(armoredText);
                                                        if(signedMessage.getText() != password) {
                                                            isVerified = false;
                                                        } else {
                                                            const verified = await signedMessage.verify(publicKey.keys)
                                                            isVerified = await verified[0].verified
                                                        }
                                                    }
                                                    
                                                    if (isVerified) {
                                                        isPGPAuth = false;
                                                        return resolve();
                                                    } else {
                                                        return reject('signature could not be verified')
                                                    }
                                                } catch(e) {
                                                    console.error(e)
                                                    reject('Invalid authentication.')
                                                }
                                                
                                            }
                                        })
                                    })
                                }
                            }
                            if(isPGPAuth){
                                session.sendErrMessage(`
Authentication failed.
We support pgp-fingerprint and ssh-publickey only,
But nether of these could verify your identity.
If you are new to DN42, it may take an hour to update
the database after the pull request is merged.
You may want to try it again, sorry for the inconvenience.
                                    `)
                                return shell.end();
                            }
                        } catch (e) {
                            session.sendErrMessage('PGP signature could not be verified.')
                            shell.end()
                            console.log(e)
                            return;
                        }
                    }
                    if(isPGPAuth) {
                        return shell.end();
                    }
                    session.clearScreen();

                    session.sendMessage(fs.readFileSync(__dirname + '/banner.txt').toString())
                    session.node = node

                    // session.sendMessage('Welcome to Lss233\'s automatic peering system.\r\n')
                    session.sendMessage('If you encounter any issues, contact me at i@lss233.com')
                    session.sendMessage('or find lss233 on #dn42.\r\n')
                    session.sendMessage('This ssh session is for peering management only,')
                    session.sendMessage('DO NOT break anything please.\r\n')
                    session.sendMessage(`You have been verified as ${chalk.yellow(user)}.\r\n`)
                    session.sendMessage('Type `help` for help and start peering.\r\n')
                    session.sendMessage(`Last login: ${Date().substr(0, 24)} from 162.14.3.11\r\n`)
                    session.rl = readline.createInterface({
                        input: stdin,
                        output: stdout,
                        terminal: true
                    });
                    let prompt = async () => {
                        session.rl.question(chalk.yellow(user) + chalk.green('~$ '), async command => {
                            try {
                                command = command.split(' ');
                                switch (command[0]) {
                                    case 'help':
                                        await commands.help(session);
                                        break;
                                    case 'info':
                                        await commands.info(session);
                                        break;
                                    case 'show':
                                        await commands.show(session);
                                        break;
                                    case 'new':
                                        await commands.peer(session);
                                        break;
                                    case 'whois':
                                        if (command.length == 1) {
                                            session.sendMessage('Usage: whois OBJECT')
                                            session.sendMessage('Example: whois lss233-mnt')
                                            session.sendMessage('         whois 172.23.143.48')
                                        } else {
                                            await commands.whois(session, command[1])
                                        }
                                        break;
                                    case 'delete':
                                        if (command.length == 1) {
                                            session.sendMessage('Usage: delete ID')
                                            session.sendMessage('Example: delete 02b12880-726d-44bf-9632-f1803181ca07')
                                        } else {
                                            await commands.delete(session, command[1])
                                        }
                                        break;
                                    case 'exit':
                                        session.rl.close();
                                        session.rl = undefined;
                                        shell.end();
                                        break;
                                    default:
                                        session.sendErrMessage('\r\n' + chalk.red('bash: ') + command[0] + ': command not found')
                                        break;
                                }
                            } catch (e) {
                                console.log(e)
                            }
                            if (session.rl) {
                                prompt();
                            }
                        })
                        session.rl.on('SIGINT', () => {
                            session.rl.prompt()
                        })
                        .on('SIGTSTP', () => {
                            shell.end();
                        })
                    }
                    await prompt();
                })
                .on('end', function () {
                    console.log('SIGNAL received')
                    session.rl.close()
                    session.rl = readline.createInterface({
                        input: stdin,
                        output: stdout,
                        terminal: true
                    });
                });
        })
    }).on('error', function (err) {
        console.error(user, err)
    }).on('end', function () {
        console.log('Client disconnected');
    });
}).on('error', function (err) {
    console.error(err)
}).listen(39745, '0.0.0.0', function () {
    console.log('Listening on port ' + this.address().port);
});