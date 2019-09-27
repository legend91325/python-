from winreg import *


def printNets():
    net = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\\NetworkList\Signatures\\Unmanaged"
    key = OpenKey(HKEY_LOCAL_MACHINE,net)
    print("\n Networks You have Joined")
    for i in range(100):
        try:
            # 每个网络 ProfileGuid  Description Source DnsSuffix FirstNetwork Default-GatewayMac
            # FirstNetwork 网络名  Default-GatewayMac 默认网关
            guid = EnumKey(key ,i)
            netKey = OpenKey(key,str(guid))
            (n,addr,t) = EnumValue(netKey,5)
            (n, name, t) = EnumValue(netKey, 4)
            if (name==None) | (addr == None):
                continue
            macAddr = val2addr(addr)
            netName = str(name)
            print("网络名："+netName+" MAC地址："+macAddr)
            CloseKey(netKey)
        except:
            break

# REG_BINARY值转换成实际MAC地址
def val2addr(val):
    addr = ""
    if val == None:
        return addr

    try:
        for ch in val:
            addr += ("%02x " % (ch))
        addr = addr.strip(" ").replace(" ", ":")[0:17]
    except Exception as e:
        print(str(e))

    return addr

def main():
    printNets()

if __name__ == "__main__":
    main()