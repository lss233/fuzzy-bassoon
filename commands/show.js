'use strict';

const   art = require('ascii-art'),
        _   = require('lodash')


const tableColumns = [
    {
        value: '#',
    }, {
        value: 'Maintainer'
    }, {
        value: 'WireGuard Endpoint'
    }, {
        value: 'WierGuard Publickey'
    }, {
        value: 'DN42 Info'
    }
];

module.exports = async function (session) {
    let data = session
        .db
        .get('peers')
        .filter({mntner: session.user})
        .map(obj => 
            _(obj)
                .pick(['id', 'mntner', 'endpoint', 'publicKey', 'address'])
                .toArray()
                .value()
        ).value()
    if(data.length == 0) {
        session.sendMessage('We have no peer yet.')
    } else {
        session.sendMessage(await art.table({
            data: data,
            columns: tableColumns
        }))
    }
}