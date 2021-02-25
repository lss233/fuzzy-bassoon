const fs = require('fs'),
    crypto = require('crypto'),
    ssh2 = require('ssh2'),
    chalk = require('chalk'),
    readline = require('readline'),
    node = require('./node'),
    whois = require('./whois');

const commands = require('./commands')

const low = require('lowdb')
const FileSync = require('lowdb/adapters/FileSync')

const adapter = new FileSync('./data/db.json')
const db = low(adapter)
db.defaults({peers: []}).write()
db._.mixin(require('lodash-id'))


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

    client.on('authentication', function (ctx) {
        user = Buffer.from(ctx.username).toString();
        console.log(user, ctx.method)
        switch (ctx.method) {
            case 'password':
                /*
                var password = Buffer.from(ctx.password);
                if (password.length !== allowedPassword.length
                    || !crypto.timingSafeEqual(password, allowedPassword)) {
                    return ctx.reject();
                }
                */

                break;
            case 'publickey':
                if (user.includes('-')) {
                    whois.query('mntner/' + user).then(resp => {
                        try {
                            resp = resp[Object.keys(resp).filter(i => i.toUpperCase() == 'MNTNER/' + user.toUpperCase())[0]];

                            for (let auth of resp.auth) {
                                if (auth.startsWith('ssh-')) {
                                    let allowedPubKey = utils.parseKey(auth)
                                    if (ctx.key.algo !== allowedPubKey.type
                                        || !checkValue(ctx.key.data, allowedPubKey.getPublicSSH())
                                        || (ctx.signature && allowedPubKey.verify(ctx.blob, ctx.signature) !== true)) {
                                        continue;
                                    }
                                    user = resp['mntner'][0]
                                    return ctx.accept();
                                }
                            }
                            ctx.reject('Invalid publickey received. Cannot verify your identity.');
                        } catch (e) {
                            console.log(e)
                            ctx.reject(e);
                        }

                    })
                } else {
                    ctx.reject('Please login by using your mntner as username.')
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
                            } catch(e) {
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