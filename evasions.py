import os


class evasions:

    def __init__(self, link):
        super()
        self.link = link

    # read folder and check file or folders
    def readfolder(self, link):

        for entity in os.listdir(link):
            name = link + entity
            # print("checking" + name)
            if os.path.isdir(name):
                # print("folder" + name)
                self.readfolder(name+'/')
            elif os.path.isfile(name) and "snort.log" not in name:
                # print(self.check(name, 2))
                if "./evader --if=enp0s8 --src_ip=" in self.check(name):
                    print("working on "+ entity )

                    self.readevasions(link, entity)

    # Check the file
    def check(self, file):
        with open(file) as infile:
            #print(infile.readlines(intt))
            return infile.readline()

    def readevasions(self, link, entity):
        print(link)
        file = open(link + entity)
        outfile = link + "/newfiltered.txt"
        file2 = open(outfile, "w")
        data = file.readlines()
        for line in data:
            #    print(line)
            if "./evader --if=enp0s8 --src_ip=" in line:
                file2.write("\n")
                file2.write(line[:-36].replace("\n", ""))
            if "0: Success." in line or "2: Likely suc" in line \
                    or "200: C" in line or "300: T" in line:
                file2.write("--")
                file2.write(line.replace("\n", ""))
        file2.close()
        self.divideevasions(link, outfile)

    def divideevasions1(self, link, infile):
        outfile1 = open("xpsucessfiltered","a")
        outfile2 = open("xpunsucessfiltered", "a")
        with open(infile) as opened:
            for line in opened:
                if "200: C" in line or "300: T" in line:
                    continue
                    print("badone ")
                elif "0: Success." in line or "2: Likely suc" in line:
                    outfile1.write(line)
                else:
                    outfile2.write(line)


    def divideevasions(self, link, infile):
        outfile1 = open("xp_sucessfiltered","a")
        outfile2 = open("xp_unsucessfiltered", "a")
        outfile3 = open("ob_xp_sucessfiltered", "a")
        outfile4 = open("ob_xp_unsucessfiltered", "a")
        with open(infile) as opened:
            for line in opened:
                if "200: C" in line or "300: T" in line:
                    continue
                    print("badone ")
                elif "0: Success." in line or "2: Likely suc" in line:
                    if "--obfuscate" in line:
                        outfile3.write(line)
                    else:
                        outfile1.write(line)
                else:
                    if "--obfuscate" in line:
                        outfile4.write(line)
                    else:
                        outfile2.write(line)