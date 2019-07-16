from evasions import evasions
from snort import snort


def main():
    str = input("1. Evasion log for evasions \n2. Snort logs for errors")
    if str is '1':
        evasion = evasions("/home/jazz/Desktop")
        evasion.readfolder("/home/jazz/Desktop/Data for thesis/windows/")
    elif str is '2':
        snortt = snort()
        snortt.readfolder("/home/jazz/Desktop/Data for thesis/windows/")


if __name__ == '__main__':
    main()