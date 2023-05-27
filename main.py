import re
import datetime
import numpy as np, matplotlib.pyplot as plt, pandas as pd
from collections import defaultdict

MAX_REQUESTS_PER_MINUTE = 5
MAX_SECONDS_TO_CHANGE_USER_AGENT = 10
MAX_RESPONSE_SIZE = 30000
MAX_ERROR_COUNT = 8


# class describing the Log line
class LogLine:
    def __int__(self, ip, date, method, path, protocol, response, size, userAgent):
        self.ip = ip
        self.date = date
        self.method = method
        self.path = path
        self.protocol = protocol
        self.response = response
        self.size = size
        self.userAgent = userAgent


# function of analyzing the line and adding to dictionary
def readLog(logStr, logList):
    ip = re.search('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', logStr).group(0)
    date = re.search('\[[0-9]{2}\/[a-zA-Z]{3}\/[0-9]{4}\:[0-9]{2}\:[0-9]{2}\:[0-9]{2} (\+|\-)?[0-9]{4}\]',
                     logStr).group(0)[1:-1]
    method = re.search('\"[A-Z]{3,4}', logStr).group(0)[1:]
    path = re.search('\"[A-Z]{3,4} \/?[-._&?:/a-zA-Z0-9]*\/?', logStr).group(0)[5:]
    protocol = re.search('[A-Z]{4,5}\/[0-9]\.[0-9]\" [0-9]{3}', logStr).group(0)[:-5]
    response = int(re.search('\" [0-9]{3}', logStr).group(0)[2:])
    size = re.search('[0-9]{3} ([0-9]{1,10} \")|(\- \")', logStr).group(0)[4:-2]
    userAgent = re.search('\" \"([-+@~()._,;:/ a-zA-Z0-9]|\[|\])*\"(\n|( \"\-\"\n))', logStr).group(0)[3:-6]

    date = datetime.datetime.strptime(date, '%d/%b/%Y:%H:%M:%S %z')

    log = LogLine()
    log.ip = ip
    log.date = date
    log.method = method
    log.path = path
    log.protocol = protocol
    log.response = response
    log.size = size
    log.userAgent = userAgent

    logList['Ip'].append(log.ip)
    logList['Date'].append(log.date)
    logList['Method'].append(log.method)
    logList['Path'].append(log.path)
    logList['Protocol'].append(log.protocol)
    logList['Response'].append(log.response)
    logList['Size'].append(log.size)
    logList['User agent'].append(log.userAgent)


# function of reading the line
def readFile(filename):
    logList = defaultdict(list)
    with open(filename) as file:
        for line in file:
            readLog(line, logList)
    analyzeData(logList)


# function of analyzing the data in dataframe and adding to blacklist
def analyzeData(logList):
    df = pd.DataFrame(logList).reset_index()

    # print(df.columns)
    # print(df.describe(include=np.number))
    df.to_csv("data.csv")

    ips = df['Ip'].unique()
    blackListByRPT = []
    blackListByUA = []
    blackListByPOST = []
    blackListByErrors = []

    for ip in ips:
        count = 0
        error = 0
        indexes = df.index[df['Ip'] == ip].tolist()

        # check for responses per moment
        if len(indexes) >= MAX_REQUESTS_PER_MINUTE:
            for i in range(len(indexes) - 1):
                if abs((df["Date"].loc[df.index[indexes[i + 1]]] - df["Date"].
                        loc[df.index[indexes[i]]]).total_seconds()) < MAX_SECONDS_TO_CHANGE_USER_AGENT:
                    count += 1
                if abs((df["Date"].loc[df.index[indexes[i + 1]]] - df["Date"].
                        loc[df.index[indexes[i]]]).total_seconds()) > 1000:
                    count = 0
        if count > MAX_REQUESTS_PER_MINUTE:
            blackListByRPT.append(ip)

        # check for user agent changes
        flag = False
        for i in range(len(indexes) - 1):
            if df["User agent"].loc[df.index[indexes[i + 1]]] != df["User agent"].loc[df.index[indexes[i]]] and \
                    abs((df["Date"].loc[df.index[indexes[i + 1]]] - df["Date"].loc[
                        df.index[indexes[i]]]).total_seconds()) < MAX_SECONDS_TO_CHANGE_USER_AGENT:
                flag = True
        if flag:
            blackListByUA.append(ip)

        # check POST response size
        for i in range(len(indexes)):
            if df["Method"].loc[df.index[indexes[i]]] == 'POST' and \
                    int(df["Size"].loc[df.index[indexes[i]]]) > MAX_RESPONSE_SIZE:
                blackListByPOST.append(ip)
                break

        # check for 4** errors
        if len(indexes) >= 8:
            for i in range(len(indexes)):
                if df["Response"].loc[df.index[indexes[i]]] >= 400:
                    error += 1
        if error > MAX_ERROR_COUNT:
            blackListByErrors.append(ip)

    # df['age' > 50].plot.hist(column='age', bins=10)
    # plt.show()
    # print(df['Ip'].value_counts())

    print(len(ips))
    print(len(blackListByRPT))
    print(len(blackListByUA))
    print(len(blackListByPOST))
    print(len(blackListByErrors))

    # print(blackListByRPT)
    # print(blackListByUA)
    # print(blackListByPOST)
    # print(blackListByErrors)


if __name__ == '__main__':
    readFile("access.log")
