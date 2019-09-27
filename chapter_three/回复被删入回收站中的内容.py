import os
import optparse
from winreg import *

# sid 与用户名 关联起来
def sid2user(sid):
    try:
        key = OpenKey(HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\\"+sid);
        (value,type) = QueryValueEx(key,"ProfileImagePath")
        user = value.split("\\")[-1]
        return user
    except Exception as e:
        print(str(e))
        return sid

def returnDir():
    dirs = ["C:\\RECYCLER\\","C:\\Recycler\\","C:\\Recycled\\","C:\\$Recycle.Bin\\"]
    for recycleDir in dirs:
        if os.path.isdir(recycleDir):
            return recycleDir
    return None

def findRecycled(recycleDir):
    dirList = os.listdir(recycleDir)
    for sid in dirList:
        files = os.listdir(recycleDir+sid)
        user = sid2user(sid)
        print("Listing Files for user："+str(user))
        for file in files:
            print("Found File:"+str(file))

def main():
    recycledDir = returnDir()
    if recycledDir == None:
        print("can`t find recycledDir ~~~")
        exit(0)
    findRecycled(recycledDir)

if __name__ == '__main__':
    main()