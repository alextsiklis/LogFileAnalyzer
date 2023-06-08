import re
import datetime
import time
import matplotlib
import numpy as np, matplotlib.pyplot as plt, pandas as pd
from collections import defaultdict

from matplotlib.ticker import MultipleLocator

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
    lines = 0
    logList = defaultdict(list)
    with open(filename) as file:
        for line in file:
            readLog(line, logList)
            lines += 1
            # print(lines)
    print(lines)
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

    # fig, ax = plt.subplots(figsize=(5, 2.7), layout='constrained')
    # ax.plot(df.Date, df.Size)
    # ax.set_xlabel('Время', fontsize=8)
    # ax.set_ylabel('Размер', fontsize=8)
    # ax.set_title("Размер полезной нагрузки")
    # plt.gcf().autofmt_xdate()
    # y_major_locator = MultipleLocator(1000)
    # ax = plt.gca()
    # ax.yaxis.set_major_locator(y_major_locator)
    # # plt.yticks([30000, 500000, 1000000, 1500000])
    # plt.show()

    # print(len(ips))
    # print(len(blackListByRPT))
    # print(len(blackListByUA))
    # print(len(blackListByPOST))
    # print(len(blackListByErrors))

    # print(blackListByRPT)
    # print(blackListByUA)
    # print(blackListByPOST)
    # print(blackListByErrors)


if __name__ == '__main__':
    start_time = time.time()
    readFile("access.log")
    print("--- %s seconds ---" % (time.time() - start_time))

    # start_time = time.time()
    # readFile("log1.log")
    # print("--- %s seconds ---" % (time.time() - start_time))
    # y1 = time.time() - start_time
    # 
    # start_time = time.time()
    # readFile("log2.log")
    # print("--- %s seconds ---" % (time.time() - start_time))
    # y2 = time.time() - start_time
    # 
    # start_time = time.time()
    # readFile("log3.log")
    # print("--- %s seconds ---" % (time.time() - start_time))
    # y3 = time.time() - start_time
    # 
    # start_time = time.time()
    # readFile("log4.log")
    # print("--- %s seconds ---" % (time.time() - start_time))
    # y4 = time.time() - start_time
    # 
    # start_time = time.time()
    # readFile("access.log")
    # print("--- %s seconds ---" % (time.time() - start_time))
    # y5 = time.time() - start_time
    # 
    # start_time = time.time()
    # readFile("log5.log")
    # print("--- %s seconds ---" % (time.time() - start_time))
    # y6 = time.time() - start_time
    # 
    # start_time = time.time()
    # readFile("log6.log")
    # print("--- %s seconds ---" % (time.time() - start_time))
    # y7 = time.time() - start_time
    # 
    # x = [1000, 12000, 28000, 50000, 78000, 100000, 300000]
    # y = [y1, y2, y3, y4, y5, y6, y7]
    # fig, ax = plt.subplots(figsize=(5, 2.7), layout='constrained')
    # ax.plot(x, y)  # Plot some data on the axes.
    # ax.set_xlabel('Количество строк в журнале', fontsize=8)  # Add an x-label to the axes.
    # ax.set_ylabel('Время', fontsize=8)  # Add a y-label to the axes.
    # ax.set_title("Время анализа")  # Add a title to the axes.
    # ax = plt.gca()
    # plt.show()
    
    x = ['1', '2', '3', '4', '5']
    y1 = [1739, 168, 70, 5, 68]
    y2 = [1739, 168, 76, 4, 65]
    colors = ['#E69F00', '#56B4E9']
    names = ['United Air Lines Inc.', 'JetBlue Airways']
    plt.hist([y1,y2], x, label=['y1', 'y2'])
    # Plot formatting
    plt.legend()
    plt.xlabel('Delay (min)')
    plt.ylabel('Normalized Flights')
    plt.title('Side-by-Side Histogram with Multiple Airlines')
    plt.show()
