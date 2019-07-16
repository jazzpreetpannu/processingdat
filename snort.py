import os

class snort:
    def __init__(self):
        self.set = self.extract_set("xpsucessfiltered" )

    def readfolder(self, link):
        for entity in os.listdir(link):
            name = link + entity
            #set =
            # print("checking" + name)
            if os.path.isdir(name):
                # print("folder" + name)
                self.readfolder(name + '/')
            elif os.path.isfile(name) and "snort.log" not in name:
                # print(self.check(name, 2))
                if "alert" in name:
                    print("working on " + entity)
                    self.getting_set_filter(link + entity, "2snort_xp_success", self.set)

    def getting_set_filter(self, infile, outfile, sett):
        snortset = list()
        with open(outfile, 'a') as snort_outfile:
            with open(infile) as file:
                for line in file:
                    if "[**] [" in line[:6] and "[**]" in line:
                        if len(snortset) > 1:
                            ip = snortset[2].split(":")[2][10:]
                            if str(ip.split("->")[0]).strip() in sett:
                                # print(str(ip.split("->")[0]).strip())
                                snortset.pop()
                                snortset.reverse()
                                snortset.append(str(ip.split("->")[0]).strip())
                                stri = ''
                                while len(snortset) > 0:
                                    stri = stri + snortset.pop() + '$'
                                # print(stri)
                                snort_outfile.write(stri[:-2] + "\n")
                        snortset.clear()
                    snortset.append(line.replace("\n", ""))

    def extract_set(self, infile):
        file = open(infile, "r")
        # result = open("/home/jazz/Desktop/resultwholeevasionlinuxwith.txt", "a")
        data = file.readlines()
        sett = set()
        # print("here")
        for line in data:
            #    print(line)
            if "--src_mask=8 --dst_ip=" in line:
                splited = line.split(" --")
                sett.add(splited[2][7:])
                # result.write(line)
        print(len(sett))
        return sett