use rustmap_types::Protocol;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Port-to-service name mapping based on nmap-services.
pub struct PortServiceMap;

static TCP_SERVICES: LazyLock<HashMap<u16, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    // Well-known services (ports 1-1023)
    m.insert(1, "tcpmux");
    m.insert(5, "rje");
    m.insert(7, "echo");
    m.insert(9, "discard");
    m.insert(11, "systat");
    m.insert(13, "daytime");
    m.insert(15, "netstat");
    m.insert(17, "qotd");
    m.insert(19, "chargen");
    m.insert(20, "ftp-data");
    m.insert(21, "ftp");
    m.insert(22, "ssh");
    m.insert(23, "telnet");
    m.insert(25, "smtp");
    m.insert(37, "time");
    m.insert(42, "nameserver");
    m.insert(43, "whois");
    m.insert(49, "tacacs");
    m.insert(53, "domain");
    m.insert(67, "dhcps");
    m.insert(68, "dhcpc");
    m.insert(69, "tftp");
    m.insert(70, "gopher");
    m.insert(79, "finger");
    m.insert(80, "http");
    m.insert(88, "kerberos-sec");
    m.insert(102, "iso-tsap");
    m.insert(104, "acr-nema");
    m.insert(110, "pop3");
    m.insert(111, "rpcbind");
    m.insert(113, "ident");
    m.insert(119, "nntp");
    m.insert(123, "ntp");
    m.insert(135, "msrpc");
    m.insert(137, "netbios-ns");
    m.insert(138, "netbios-dgm");
    m.insert(139, "netbios-ssn");
    m.insert(143, "imap");
    m.insert(161, "snmp");
    m.insert(162, "snmptrap");
    m.insert(163, "cmip-man");
    m.insert(164, "cmip-agent");
    m.insert(179, "bgp");
    m.insert(194, "irc");
    m.insert(199, "smux");
    m.insert(389, "ldap");
    m.insert(443, "https");
    m.insert(445, "microsoft-ds");
    m.insert(464, "kpasswd5");
    m.insert(465, "smtps");
    m.insert(500, "isakmp");
    m.insert(512, "exec");
    m.insert(513, "login");
    m.insert(514, "shell");
    m.insert(515, "printer");
    m.insert(520, "efs");
    m.insert(530, "courier");
    m.insert(531, "chat");
    m.insert(532, "netnews");
    m.insert(540, "uucp");
    m.insert(543, "klogin");
    m.insert(544, "kshell");
    m.insert(548, "afp");
    m.insert(554, "rtsp");
    m.insert(556, "remotefs");
    m.insert(563, "nntps");
    m.insert(587, "submission");
    m.insert(591, "http-alt");
    m.insert(593, "http-rpc-epmap");
    m.insert(636, "ldapssl");
    m.insert(666, "doom");
    m.insert(691, "resvc");
    m.insert(749, "kerberos-adm");
    m.insert(873, "rsync");
    m.insert(902, "iss-realsecure");
    m.insert(993, "imaps");
    m.insert(995, "pop3s");

    // Registered ports (1024-49151)
    m.insert(1025, "NFS-or-IIS");
    m.insert(1080, "socks");
    m.insert(1099, "rmiregistry");
    m.insert(1194, "openvpn");
    m.insert(1433, "ms-sql-s");
    m.insert(1434, "ms-sql-m");
    m.insert(1521, "oracle");
    m.insert(1723, "pptp");
    m.insert(1883, "mqtt");
    m.insert(2049, "nfs");
    m.insert(2082, "infowave");
    m.insert(2083, "radsec");
    m.insert(2086, "gnunet");
    m.insert(2087, "eli");
    m.insert(2096, "nbx-dir");
    m.insert(2181, "eforward");
    m.insert(2222, "EtherNetIP-1");
    m.insert(2375, "docker");
    m.insert(2376, "docker-s");
    m.insert(2483, "ttc-ssl");
    m.insert(2484, "ttc");
    m.insert(3000, "ppp");
    m.insert(3128, "squid-http");
    m.insert(3268, "globalcatLDAP");
    m.insert(3269, "globalcatLDAPssl");
    m.insert(3306, "mysql");
    m.insert(3389, "ms-wbt-server");
    m.insert(3690, "svn");
    m.insert(4000, "remoteanything");
    m.insert(4443, "pharos");
    m.insert(4444, "krb524");
    m.insert(4567, "tram");
    m.insert(4711, "trinity-dist");
    m.insert(4848, "appserv-http");
    m.insert(5000, "upnp");
    m.insert(5001, "commplex-link");
    m.insert(5060, "sip");
    m.insert(5061, "sip-tls");
    m.insert(5222, "xmpp-client");
    m.insert(5269, "xmpp-server");
    m.insert(5432, "postgresql");
    m.insert(5555, "freeciv");
    m.insert(5601, "esmagent");
    m.insert(5672, "amqp");
    m.insert(5900, "vnc");
    m.insert(5984, "couchdb");
    m.insert(5985, "wsman");
    m.insert(5986, "wsmans");
    m.insert(6000, "X11");
    m.insert(6379, "redis");
    m.insert(6443, "sun-sr-https");
    m.insert(6667, "irc");
    m.insert(7001, "afs3-callback");
    m.insert(7002, "afs3-prserver");
    m.insert(7474, "neo4j");
    m.insert(8000, "http-alt");
    m.insert(8008, "http");
    m.insert(8009, "ajp13");
    m.insert(8080, "http-proxy");
    m.insert(8081, "blackice-icecap");
    m.insert(8443, "https-alt");
    m.insert(8444, "pcsync-https");
    m.insert(8888, "sun-answerbook");
    m.insert(9000, "cslistener");
    m.insert(9042, "cassandra");
    m.insert(9090, "zeus-admin");
    m.insert(9091, "xmltec-xmlmail");
    m.insert(9200, "wap-wsp");
    m.insert(9300, "vrace");
    m.insert(9418, "git");
    m.insert(9999, "abyss");
    m.insert(10000, "snet-sensor-mgmt");
    m.insert(11211, "memcache");
    m.insert(15672, "unknown");
    m.insert(27017, "mongod");
    m.insert(27018, "mongod");
    m.insert(27019, "mongod");
    m.insert(28017, "mongod");
    m.insert(50000, "ibm-db2");
    m
});

static UDP_SERVICES: LazyLock<HashMap<u16, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(7, "echo");
    m.insert(9, "discard");
    m.insert(13, "daytime");
    m.insert(17, "qotd");
    m.insert(19, "chargen");
    m.insert(37, "time");
    m.insert(42, "nameserver");
    m.insert(49, "tacacs");
    m.insert(53, "domain");
    m.insert(67, "dhcps");
    m.insert(68, "dhcpc");
    m.insert(69, "tftp");
    m.insert(111, "rpcbind");
    m.insert(123, "ntp");
    m.insert(135, "msrpc");
    m.insert(137, "netbios-ns");
    m.insert(138, "netbios-dgm");
    m.insert(161, "snmp");
    m.insert(162, "snmptrap");
    m.insert(177, "xdmcp");
    m.insert(443, "https");
    m.insert(500, "isakmp");
    m.insert(514, "syslog");
    m.insert(520, "route");
    m.insert(623, "asf-rmcp");
    m.insert(626, "serialnumberd");
    m.insert(1194, "openvpn");
    m.insert(1434, "ms-sql-m");
    m.insert(1604, "citrix-ica");
    m.insert(1900, "upnp");
    m.insert(4500, "nat-t-ike");
    m.insert(5353, "mdns");
    m.insert(5355, "llmnr");
    m.insert(40125, "unknown");
    m
});

impl PortServiceMap {
    /// Look up the service name for a port/protocol combination.
    pub fn lookup(port: u16, protocol: Protocol) -> Option<&'static str> {
        match protocol {
            Protocol::Tcp => TCP_SERVICES.get(&port).copied(),
            Protocol::Udp => UDP_SERVICES.get(&port).copied(),
            Protocol::Sctp => TCP_SERVICES.get(&port).copied(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_common_tcp_ports() {
        assert_eq!(PortServiceMap::lookup(80, Protocol::Tcp), Some("http"));
        assert_eq!(PortServiceMap::lookup(443, Protocol::Tcp), Some("https"));
        assert_eq!(PortServiceMap::lookup(22, Protocol::Tcp), Some("ssh"));
        assert_eq!(PortServiceMap::lookup(21, Protocol::Tcp), Some("ftp"));
        assert_eq!(PortServiceMap::lookup(25, Protocol::Tcp), Some("smtp"));
        assert_eq!(PortServiceMap::lookup(3306, Protocol::Tcp), Some("mysql"));
        assert_eq!(
            PortServiceMap::lookup(3389, Protocol::Tcp),
            Some("ms-wbt-server")
        );
        assert_eq!(
            PortServiceMap::lookup(5432, Protocol::Tcp),
            Some("postgresql")
        );
        assert_eq!(PortServiceMap::lookup(6379, Protocol::Tcp), Some("redis"));
        assert_eq!(
            PortServiceMap::lookup(8080, Protocol::Tcp),
            Some("http-proxy")
        );
    }

    #[test]
    fn lookup_unknown_port() {
        assert_eq!(PortServiceMap::lookup(65534, Protocol::Tcp), None);
        assert_eq!(PortServiceMap::lookup(65534, Protocol::Udp), None);
    }

    #[test]
    fn lookup_common_udp_ports() {
        assert_eq!(PortServiceMap::lookup(53, Protocol::Udp), Some("domain"));
        assert_eq!(PortServiceMap::lookup(123, Protocol::Udp), Some("ntp"));
        assert_eq!(PortServiceMap::lookup(161, Protocol::Udp), Some("snmp"));
        assert_eq!(PortServiceMap::lookup(1900, Protocol::Udp), Some("upnp"));
    }
}
