const fs = require('fs'),
    crypto = require('crypto'),
    ssh2 = require('ssh2'),
    chalk = require('chalk'),
    readline = require('readline'),
    node = require('./node'),
    whois = require('./whois'),
    openpgp = require('openpgp');

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
    console.log('Client connected!');

    client.on('authentication', async function (ctx) {
        let rejectWithMessage = (msg) => {
            if (ctx.method === 'keyboard-interactive') {
                console.log(`Reject ${ctx.username} due to: ${msg}`)
                ctx.prompt(chalk.bgRed.white('Error: ') + chalk.red(msg) + '\r\n Press Ctrl + C to continue.\r\n', () => {
                    ctx.reject([])
                })
                ctx.reject([])
            } else {
                ctx.reject(['keyboard-interactive'])
            }
        }

        user = Buffer.from(ctx.username).toString();

        console.log(user, ctx.method)

        let mntnerInfo = await whois.queryLast('mntner/' + user);
        if (mntnerInfo === undefined ||
            ((user = mntnerInfo['mntner'][0]),
                !/^[a-zA-Z0-9-]+$/.test(user) && user.toLowerCase().endsWith('-mnt'))
        ) {
            return rejectWithMessage('Please login as mntner.')
        }

        switch (ctx.method) {
            case 'password':
                return ctx.reject(['publickey', 'keyboard-interactive']);
                break;
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
                            return ctx.accept();
                        }
                    }
                    return rejectWithMessage('Could not authenticate with your publickey. Please use your mntner publickey to login.')
                } catch (e) {
                    console.log(e)
                }
                break;
            case 'keyboard-interactive':
                try {
                    const password = crypto.randomBytes(16).toString('base64')
                    console.log(password)
                    for (let auth of mntnerInfo.auth) {
                        if (auth.startsWith('pgp-fingerprint')) {
                            let publicKeyArmored = await hkp.lookup({ query: '0x' + auth.substr(16) });
                            console.log(publicKeyArmored)
                            let publicKey = await openpgp.key.readArmored(publicKeyArmored);

                            let encrypted = await openpgp.encrypt({
                                message: openpgp.message.fromText(password),
                                publicKeys: publicKey.keys,
                            });
                            let promptText = `
Entering PGP publickey authentication mode.
Please decrypt following text using 
${chalk.bgWhite.black(auth)}
Encrypted data:
`
                                for(let i of encrypted.data) {
                                    promptText += chalk.green(i)
                                }
                                promptText += 'Please input the answer: '
                                let retry = 0;
                                let result = await new Promise((resolve, reject) => {
                                ctx.prompt(promptText,
                                    (answer) => {
                                        if(retry++ >= 2) {
                                            resolve(false);
                                        }
                                        if (answer.length === 0) {
                                            return ctx.reject(['keyboard-interactive']);
                                        }
                                        if (password == answer[0]) {
                                            return ctx.accept(), resolve(true);
                                        }
                                        return ctx.reject(['keyboard-interactive']);
                                    })
                                });
                                if(result) {
                                    return;
                                }
                        }
                    }
                    return rejectWithMessage(`
Authentication failed.
We support pgp-fingerprint and ssh-publickey only,
But nether of these could verify your identity.
If you are new to DN42, it may take a hour to update
the database after the pull request is merged.
You may want to try it again, sorry for the inconvenience.
                        `)
                } catch (e) {
                    console.log(e)
                }
                break;
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
                    session.sendErrMessage = (text) => {
                        for (let i of text.split('\n')) {
                            stderr.write(i + '\r\n')
                        }
                    }


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
                                        shell.close();
                                        break;
                                    default:
                                        session.sendErrMessage(chalk.red('bash: ') + command[0] + ': command not found')
                                        break;
                                }
                            } catch (e) {
                                console.log(e)
                            }
                            if (session.rl) {
                                prompt();
                            }
                        })
                        session.rl.on('close', () => {
                            session.rl = readline.createInterface({
                                input: stdin,
                                output: stdout,
                                terminal: true
                            });
                            prompt();
                        })
                    }
                    await prompt();
                })
                .on('signal', function () {
                    console.log('SIGNAL received')
                    session.rl.close()
                    session.rl = readline.createInterface({
                        input: stdin,
                        output: stdout,
                        terminal: true
                    });
                });
        })
    }).on('end', function () {
        console.log('Client disconnected');
    });
}).listen(39745, '0.0.0.0', function () {
    console.log('Listening on port ' + this.address().port);
});