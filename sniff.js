const c = require('chalk');

const { Cap, decoders } = require('cap');
const PROTOCOL = decoders.PROTOCOL;

const capture = new Cap();

const ipv4 = '192.168.0.1'; // set to your ipv4. (same method as card-revealer)
const device = Cap.findDevice(ipv4);
const buffer = Buffer.alloc(65535);

const linkType = capture.open(device, 'tcp', 10485760, buffer);
capture.setMinBytes(0);

capture.on('packet', async () => {

    let srcIP;
    let dstIP;

    if (linkType === 'ETHERNET') {
        let ret = decoders.Ethernet(buffer);

        if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
            ret = decoders.IPV4(buffer, ret.offset);

            srcIP = ret.info.srcaddr;
            dstIP = ret.info.dstaddr;

            if (ret.info.protocol === PROTOCOL.IP.TCP) {
                let data = ret.info.totallen - ret.hdrlen;

                ret = decoders.TCP(buffer, ret.offset);
                data -= ret.hdrlen;

                let packet = buffer.toString('binary', ret.offset, ret.offset + data);
                if (!packet.startsWith('%xt')) return;

                if (srcIP == ipv4) return console.log(c.magentaBright(`Sent: ${packet} to ${dstIP}:${ret.info.dstport}`));
                return console.log(c.blueBright(`Received: ${packet} on ${srcIP}:${ret.info.srcport}`));

            }  else console.log('Unsupported IPv4 protocol: ' + PROTOCOL.IP[ret.info.protocol]);
        } else console.log('Unsupported ether type: ' + PROTOCOL.ETHERNET[ret.info.type]);
    }

});
