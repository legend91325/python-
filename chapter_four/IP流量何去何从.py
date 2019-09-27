import pygeoip
import dpkt
import socket
import optparse

gi = pygeoip.GeoIP(".\GeoLiteCity.dat")
def retGeoStr(tgt):
    try:
        rec = gi.record_by_name(tgt)
        city = rec['city']
        country = rec['country_code3']
        if city != '':
            geoLoc = city + ", "+country
        else:
            geoLoc = country
        country_name = rec['country_name']
        long = rec['longitude']
        lat = rec['latitude']
        return geoLoc
    except Exception as e:
        # 查不到的 默认值
        return 'Unregistered'

def printPcap(pcap):
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            # IP 转字符串
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            print("Src: "+src +" --> Dst: "+dst)
            print("Src: "+retGeoStr(src)+" --> Dst: "+retGeoStr(dst))
        except:
            # 抓不到IP层的直接忽略
            pass

def main():
    parser = optparse.OptionParser("usage: %prog -p <pcap file>")
    parser.add_option("-p", dest="pcapFile", type="string", help="specify pcap filename")
    (options,args) = parser.parse_args()
    if options.pcapFile == None:
        print(parser.usage)
        exit(0)
    pcapFile = options.pcapFile
    f = open(pcapFile, 'rb')
    pcap = dpkt.pcap.Reader(f)
    printPcap(pcap)

if __name__ == '__main__':
    main()